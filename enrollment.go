package burrow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// enrollCodeEnv is the variable Open enrolls from when this host holds no identity.
const enrollCodeEnv = "BURROW_ENROLL_CODE"

const invalidCode = "that enrollment code is not valid; copy it again from the Burrow's Machine tokens page"

// expiredReason is the Burrow's reason for a machine past its lifetime.
const expiredReason = "Machine has expired"

// enrollmentCode is a machine token's enrollment code, as the Burrow's Machine tokens page shows it: base64url JSON
// carrying the Burrow's URL, the token, how to trust the Burrow, and its key pin. The ratel CLI reads the same format.
type enrollmentCode struct {
	url   string
	token string
	// mode is "encrypted", "system" or "pinned".
	mode string
	pin  string
}

func decodeEnrollmentCode(raw string) (enrollmentCode, error) {
	s := strings.TrimRight(strings.TrimSpace(raw), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return enrollmentCode{}, &IdentityError{Reason: invalidCode}
	}
	var o map[string]any
	if json.Unmarshal(data, &o) != nil {
		return enrollmentCode{}, &IdentityError{Reason: invalidCode}
	}
	str := func(key string) string {
		v, _ := o[key].(string)
		return v
	}
	code := enrollmentCode{url: strings.TrimRight(str("u"), "/"), token: str("t"), mode: str("m"), pin: str("p")}
	if code.url == "" || code.token == "" {
		return enrollmentCode{}, &IdentityError{Reason: invalidCode}
	}
	// An older code has no mode: pinned when it carries a pin, system trust otherwise.
	if code.mode == "" {
		code.mode = "system"
		if code.pin != "" {
			code.mode = "pinned"
		}
	}
	return code, nil
}

// enrollmentTLS is how to trust the Burrow, from the code. A pinned code is checked against its pin from the very
// first request.
func enrollmentTLS(code enrollmentCode) TLSMode {
	switch code.mode {
	case "encrypted":
		return TLSInsecure()
	case "system":
		return TLSSystemTrust()
	}
	if code.pin != "" {
		return TLSPinnedTo(code.pin)
	}
	return TLSPinned()
}

// enrolledMachine is one enrolled machine: its id, its key held in memory, and when the Burrow ends it (zero: never).
type enrolledMachine struct {
	id        string
	key       ed25519.PrivateKey
	expiresAt time.Time
	// renewAt is when to enroll a fresh machine, ahead of expiresAt.
	renewAt time.Time
}

// enrollment is one registration in flight, which every caller that needs a machine meanwhile waits for.
type enrollment struct {
	done    chan struct{}
	machine *enrolledMachine
	err     error
}

// enrolledAuthorizer signs as a machine enrolled through a machine token and held only in memory. It enrolls on first
// use, enrolls a fresh machine with the same code shortly before the current one expires (or when the Burrow says it
// has), and ends the one it replaced. Concurrent requests share one enrollment.
type enrolledAuthorizer struct {
	code      enrollmentCode
	transport *transport
	clientTag string
	now       func() time.Time

	mu      sync.Mutex
	current *enrolledMachine
	pending *enrollment
	closed  bool
}

func newEnrolledAuthorizer(code enrollmentCode, t *transport, clientTag string) *enrolledAuthorizer {
	return &enrolledAuthorizer{code: code, transport: t, clientTag: clientTag, now: time.Now}
}

func (a *enrolledAuthorizer) machineID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == nil {
		return ""
	}
	return a.current.id
}

func (a *enrolledAuthorizer) authorize(ctx context.Context, action string, resource []string) (map[string]string, error) {
	m, err := a.machine(ctx)
	if err != nil {
		return nil, err
	}
	return signRequest(m.id, m.key, action, resource, a.clientTag, a.now())
}

// recover reports, after a refused request, whether it's worth sending again: a machine that expired under it is
// replaced, and a request signed by a machine already replaced is simply signed again.
func (a *enrolledAuthorizer) recover(ctx context.Context, err error, headers map[string]string) (bool, error) {
	var refused *AuthError
	a.mu.Lock()
	closed, current := a.closed, a.current
	a.mu.Unlock()
	if closed || !errors.As(err, &refused) || refused.Reason != expiredReason {
		return false, nil
	}
	if current != nil && current.id != headers["Ratel-Machine"] {
		return true, nil
	}
	if _, err := a.renew(ctx, current); err != nil {
		return false, err
	}
	return true, nil
}

// close ends the current machine now. Later requests are refused; a closed client can't be opened again. A machine
// the Burrow reports as expired, or a 404 for the call that ends it, counts as ended.
func (a *enrolledAuthorizer) close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	pending := a.pending
	a.mu.Unlock()
	if pending != nil {
		<-pending.done
	}
	a.mu.Lock()
	current := a.current
	a.current = nil
	a.mu.Unlock()
	if current == nil {
		return nil
	}
	err := a.expire(current)
	var refused *AuthError
	var notFound *NotFoundError
	if err == nil || (errors.As(err, &refused) && refused.Reason == expiredReason) || errors.As(err, &notFound) {
		return nil
	}
	return err
}

// machine is the machine to sign as: the current one until its renewal point, then a fresh one.
func (a *enrolledAuthorizer) machine(ctx context.Context) (*enrolledMachine, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, errClientClosed()
	}
	current := a.current
	a.mu.Unlock()
	if current != nil && (current.renewAt.IsZero() || a.now().Before(current.renewAt)) {
		return current, nil
	}
	return a.renew(ctx, current)
}

// renew enrolls a fresh machine in place of stale, then ends stale in the background, ignoring failures. Callers
// during an enrollment share it; ctx bounds only the caller's wait, so one caller giving up doesn't fail the others.
func (a *enrolledAuthorizer) renew(ctx context.Context, stale *enrolledMachine) (*enrolledMachine, error) {
	a.mu.Lock()
	p := a.pending
	if p == nil {
		p = &enrollment{done: make(chan struct{})}
		a.pending = p
		go a.enroll(p, stale)
	}
	a.mu.Unlock()
	select {
	case <-p.done:
		return p.machine, p.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (a *enrolledAuthorizer) enroll(p *enrollment, stale *enrolledMachine) {
	fresh, err := a.register()
	a.mu.Lock()
	if err == nil {
		a.current = fresh
	}
	a.pending = nil
	a.mu.Unlock()
	p.machine, p.err = fresh, err
	close(p.done)
	if err == nil && stale != nil && !stale.expiresAt.IsZero() {
		go func() { _ = a.expire(stale) }()
	}
}

func (a *enrolledAuthorizer) register() (*enrolledMachine, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, &TransportError{Reason: "making a key: " + err.Error(), Err: err}
	}
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		name = "machine"
	}
	payload, _ := json.Marshal(map[string]any{
		"token":     a.code.token,
		"publicKey": base64.StdEncoding.EncodeToString(pub),
		"name":      name,
		"inMemory":  true,
	})
	enrolledAt := a.now()
	body, err := a.transport.post(context.Background(), "/v1/machines/bootstrap/register", map[string]string{"Ratel-Client": a.clientTag}, payload)
	if err != nil {
		return nil, err
	}
	var dto struct {
		MachineID string `json:"machineId"`
		ExpiresAt *int64 `json:"expiresAt"`
	}
	if err := json.Unmarshal(body, &dto); err != nil || dto.MachineID == "" {
		return nil, &TransportError{Reason: "the Burrow's enrollment response was not understood", Err: err}
	}
	m := &enrolledMachine{id: dto.MachineID, key: key}
	if dto.ExpiresAt != nil {
		m.expiresAt = time.UnixMilli(*dto.ExpiresAt)
		m.renewAt = renewAt(enrolledAt, m.expiresAt)
	}
	return m, nil
}

// expire ends m on the Burrow. A machine with no expiry, or one already past it, needs no call.
func (a *enrolledAuthorizer) expire(m *enrolledMachine) error {
	if m.expiresAt.IsZero() || !a.now().Before(m.expiresAt) {
		return nil
	}
	headers, err := signRequest(m.id, m.key, "machine.expire", []string{m.id}, a.clientTag, a.now())
	if err != nil {
		return err
	}
	_, err = a.transport.post(context.Background(), "/v1/machine/expire", headers, nil)
	return err
}

// renewAt is when to replace a machine: a fifth of its lifetime before it ends, between ten seconds and five minutes.
// A one-minute token renews at 48 seconds; an hour-long one at 55 minutes.
func renewAt(enrolledAt, expiresAt time.Time) time.Time {
	lead := expiresAt.Sub(enrolledAt) / 5
	lead = min(5*time.Minute, max(10*time.Second, lead))
	return expiresAt.Add(-lead)
}
