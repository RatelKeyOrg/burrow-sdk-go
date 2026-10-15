package burrow

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// LiveStatus is where a live handle stands.
type LiveStatus string

const (
	// StatusLive is connected, with the Burrow's current value.
	StatusLive LiveStatus = "live"
	// StatusReconnecting is a dropped connection. The value is the last one read and may be out of date.
	StatusReconnecting LiveStatus = "reconnecting"
	// StatusRevoked is a machine that may no longer read it. The value is the last one read, and is final.
	StatusRevoked LiveStatus = "revoked"
	// StatusRemoved is a secret or environment that no longer exists on the Burrow. The value is the last one read, and
	// is final.
	StatusRemoved LiveStatus = "removed"
	// StatusClosed is a handle the app closed.
	StatusClosed LiveStatus = "closed"
)

func (s LiveStatus) final() bool {
	return s == StatusRevoked || s == StatusRemoved || s == StatusClosed
}

const (
	// liveRetryDelay is how long a handle waits to read again after a read failed.
	liveRetryDelay = 5 * time.Second
	// silenceTimeout is how long the stream may stay quiet, pings included, before it's treated as dropped.
	silenceTimeout = 45 * time.Second
)

var (
	reconnectBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	// certificateRetry is how long a live certificate waits after each failed renewal in a row.
	certificateRetry = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}
)

// EnvironmentChange is one secret of a LiveEnvironment that changed. Prev is nil for a secret that was added, and Next
// for one that was removed.
type EnvironmentChange struct {
	Name string
	Prev *Secret
	Next *Secret
}

// liveHandle is what every live handle shares: its status, its listeners, and a refresh that runs one read at a time
// and runs once more when asked again while a read is in flight. The watcher drives it.
type liveHandle struct {
	// envKey is project/env, lowercase.
	envKey string
	// secKey is the secret as the stream names it; empty for a whole environment.
	secKey  string
	watcher *watcher
	load    func(ctx context.Context) error
	// delay is how long to wait before reading again after a read failed. It's called with mu held.
	delay func() time.Duration
	// ended runs once the handle reaches a final status.
	ended func()
	// loading holds a token while a load runs, so loads never overlap.
	loading chan struct{}
	events  dispatcher

	mu         sync.Mutex
	status     LiveStatus
	syncedAt   time.Time
	loaded     bool
	pending    bool
	refreshing bool
	again      bool
	retry      *time.Timer
	retryGen   int
	onStatus   listenerList[func(LiveStatus)]
	onError    listenerList[func(error)]
}

func (h *liveHandle) init(envKey, secKey string, w *watcher, load func(context.Context) error) {
	h.envKey = envKey
	h.secKey = secKey
	h.watcher = w
	h.load = load
	h.delay = func() time.Duration { return liveRetryDelay }
	h.loading = make(chan struct{}, 1)
	h.status = StatusReconnecting
}

// Status is where the handle stands.
func (h *liveHandle) Status() LiveStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

// SyncedAt is when the value was last confirmed current; zero before the first read.
func (h *liveHandle) SyncedAt() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.syncedAt
}

// OnStatus calls fn with each new status. Listeners run one at a time, in the order things happened, on a goroutine
// of the handle's own. It returns a function that removes fn.
func (h *liveHandle) OnStatus(fn func(status LiveStatus)) (remove func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.onStatus.add(fn)
	return func() { h.mu.Lock(); h.onStatus.remove(id); h.mu.Unlock() }
}

// OnError calls fn with each error the handle meets while it follows the Burrow: a read that failed and will be tried
// again, or a listener that panicked. It returns a function that removes fn.
func (h *liveHandle) OnError(fn func(err error)) (remove func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.onError.add(fn)
	return func() { h.mu.Lock(); h.onError.remove(id); h.mu.Unlock() }
}

// Close stops following the Burrow. The value stays as last read.
func (h *liveHandle) Close() {
	if h.Status().final() {
		return
	}
	h.setStatus(StatusClosed)
	h.watcher.remove(h)
}

// notify tells the handle its value may have changed on the Burrow.
func (h *liveHandle) notify() {
	h.mu.Lock()
	if h.status.final() {
		h.mu.Unlock()
		return
	}
	if !h.loaded {
		h.pending = true
		h.mu.Unlock()
		return
	}
	h.mu.Unlock()
	h.refresh()
}

// confirm tells the handle it's connected and nothing moved since its last read.
func (h *liveHandle) confirm() {
	h.mu.Lock()
	if h.status.final() || !h.loaded || h.refreshing {
		h.mu.Unlock()
		return
	}
	h.syncedAt = time.Now()
	h.mu.Unlock()
	h.setStatus(StatusLive)
}

func (h *liveHandle) setStatus(status LiveStatus) {
	h.mu.Lock()
	if h.status == status || h.status.final() {
		h.mu.Unlock()
		return
	}
	h.status = status
	final := status.final()
	if final && h.retry != nil {
		h.retry.Stop()
		h.retry = nil
		h.retryGen++
	}
	emit(h, h.onStatus.snapshot(), func(fn func(LiveStatus)) { fn(status) })
	h.mu.Unlock()
	if final && h.ended != nil {
		h.ended()
	}
}

// initialize is the first read, before the handle is returned. It returns what the read returned.
func (h *liveHandle) initialize(ctx context.Context) error {
	if err := h.runLoad(ctx); err != nil {
		return err
	}
	connected := h.watcher.isConnected()
	h.mu.Lock()
	h.loaded = true
	h.syncedAt = time.Now()
	if !h.status.final() {
		h.status = StatusReconnecting
		if connected {
			h.status = StatusLive
		}
	}
	pending := h.pending
	h.pending = false
	h.mu.Unlock()
	if pending {
		h.refresh()
	}
	return nil
}

// runLoad runs the handle's load, one at a time.
func (h *liveHandle) runLoad(ctx context.Context) error {
	select {
	case h.loading <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-h.loading }()
	return h.load(ctx)
}

func (h *liveHandle) refresh() {
	h.mu.Lock()
	if h.refreshing {
		h.again = true
		h.mu.Unlock()
		return
	}
	h.refreshing = true
	h.mu.Unlock()
	go h.refreshLoop()
}

func (h *liveHandle) refreshLoop() {
	for {
		h.mu.Lock()
		h.again = false
		h.mu.Unlock()
		if err := h.runLoad(context.Background()); err != nil {
			h.mu.Lock()
			h.refreshing = false
			h.mu.Unlock()
			h.fail(err)
			return
		}
		connected := h.watcher.isConnected()
		h.mu.Lock()
		h.syncedAt = time.Now()
		h.mu.Unlock()
		if connected {
			h.setStatus(StatusLive)
		}
		h.mu.Lock()
		if !h.again || h.status.final() {
			h.refreshing = false
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()
	}
}

// fail settles a failed read: a secret that's gone is removed, a refused machine is revoked, and anything else is
// reported and tried again later.
func (h *liveHandle) fail(err error) {
	var notFound *NotFoundError
	var forbidden *ForbiddenError
	var refused *AuthError
	switch {
	case errors.As(err, &notFound):
		h.setStatus(StatusRemoved)
		h.watcher.remove(h)
	case errors.As(err, &forbidden), errors.As(err, &refused):
		h.setStatus(StatusRevoked)
		h.watcher.remove(h)
	default:
		h.mu.Lock()
		defer h.mu.Unlock()
		emit(h, h.onError.snapshot(), func(fn func(error)) { fn(err) })
		if h.retry != nil || h.status.final() {
			return
		}
		h.retryGen++
		gen := h.retryGen
		h.retry = time.AfterFunc(h.delay(), func() {
			h.mu.Lock()
			if h.retryGen != gen {
				h.mu.Unlock()
				return
			}
			h.retry = nil
			h.mu.Unlock()
			h.notify()
		})
	}
}

// emit queues a call of each listener in fns. Called with h.mu held, so events queue in the order things happened. A
// listener that panics is reported to the error listeners.
func emit[F any](h *liveHandle, fns []F, call func(F)) {
	if len(fns) == 0 {
		return
	}
	h.events.post(func() {
		for _, fn := range fns {
			h.guard(func() { call(fn) })
		}
	})
}

// guard runs one listener call. A panic in it is passed to the error listeners; a panicking error listener has nowhere
// to report to, and is dropped.
func (h *liveHandle) guard(call func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		err := fmt.Errorf("burrow: a listener panicked: %v", r)
		if cause, ok := r.(error); ok {
			err = fmt.Errorf("burrow: a listener panicked: %w", cause)
		}
		h.mu.Lock()
		fns := h.onError.snapshot()
		h.mu.Unlock()
		for _, fn := range fns {
			func() {
				defer func() { _ = recover() }()
				fn(err)
			}()
		}
	}()
	call()
}

// LiveSecret is one secret kept current. Read Current, Value or GetField whenever the value is needed; OnChange is for
// side effects. From Client.Live.
type LiveSecret struct {
	liveHandle
	coordinate string
	read       func(ctx context.Context) (*Secret, error)
	secret     *Secret
	onChange   listenerList[func(next, prev *Secret)]
}

func newLiveSecret(coordinate string, w *watcher, read func(ctx context.Context) (*Secret, error)) *LiveSecret {
	s := &LiveSecret{coordinate: coordinate, read: read}
	c := ParseSecretCoordinate(coordinate)
	s.init(strings.ToLower(c.Project+"/"+c.Environment), secretKeyOf(coordinate), w, s.load)
	return s
}

// Coordinate is the secret's project/env/NAME coordinate.
func (s *LiveSecret) Coordinate() string { return s.coordinate }

// Current is the secret as last read.
func (s *LiveSecret) Current() *Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secret
}

// Value is the single value, as last read.
func (s *LiveSecret) Value() (string, error) { return s.Current().Value() }

// GetField is one field of a structured secret, as last read.
func (s *LiveSecret) GetField(name string) (string, error) { return s.Current().GetField(name) }

// ToMap is every field of a structured secret, as last read.
func (s *LiveSecret) ToMap() (map[string]string, error) { return s.Current().ToMap() }

// OnChange calls fn with the new and the previous secret each time the value changes on the Burrow. It returns a
// function that removes fn.
func (s *LiveSecret) OnChange(fn func(next, prev *Secret)) (remove func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.onChange.add(fn)
	return func() { s.mu.Lock(); s.onChange.remove(id); s.mu.Unlock() }
}

func (s *LiveSecret) load(ctx context.Context) error {
	next, err := s.read(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.secret
	if prev != nil && sameSecret(prev, next) {
		return nil
	}
	s.secret = next
	if prev != nil {
		emit(&s.liveHandle, s.onChange.snapshot(), func(fn func(next, prev *Secret)) { fn(next, prev) })
	}
	return nil
}

// LiveEnvironment is every secret in one environment, kept current. Read Get or Secrets whenever values are needed;
// OnChange is for side effects. From Client.LiveEnvironment.
type LiveEnvironment struct {
	liveHandle
	coordinate string
	read       func(ctx context.Context) (map[string]*Secret, error)
	values     map[string]*Secret
	onChange   listenerList[func(changes []EnvironmentChange)]
}

func newLiveEnvironment(coordinate, project, environment string, w *watcher, read func(ctx context.Context) (map[string]*Secret, error)) *LiveEnvironment {
	e := &LiveEnvironment{coordinate: coordinate, read: read}
	e.init(strings.ToLower(project+"/"+environment), "", w, e.load)
	return e
}

// Coordinate is the environment's project/env coordinate.
func (e *LiveEnvironment) Coordinate() string { return e.coordinate }

// Secrets is every secret by name, as last read.
func (e *LiveEnvironment) Secrets() map[string]*Secret {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]*Secret, len(e.values))
	for name, s := range e.values {
		out[name] = s
	}
	return out
}

// Get is one secret by name, as last read, and whether the environment has it.
func (e *LiveEnvironment) Get(name string) (*Secret, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.values[name]
	return s, ok
}

// OnChange calls fn with what changed each time secrets in the environment change, are added or are removed, sorted by
// name. It returns a function that removes fn.
func (e *LiveEnvironment) OnChange(fn func(changes []EnvironmentChange)) (remove func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := e.onChange.add(fn)
	return func() { e.mu.Lock(); e.onChange.remove(id); e.mu.Unlock() }
}

func (e *LiveEnvironment) load(ctx context.Context) error {
	next, err := e.read(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.values
	e.values = next
	if prev == nil {
		return nil
	}
	var changes []EnvironmentChange
	for name, was := range prev {
		if now, ok := next[name]; !ok || !sameSecret(was, now) {
			changes = append(changes, EnvironmentChange{Name: name, Prev: was, Next: next[name]})
		}
	}
	for name, now := range next {
		if _, ok := prev[name]; !ok {
			changes = append(changes, EnvironmentChange{Name: name, Next: now})
		}
	}
	if len(changes) == 0 {
		return nil
	}
	sort.Slice(changes, func(a, b int) bool { return changes[a].Name < changes[b].Name })
	emit(&e.liveHandle, e.onChange.snapshot(), func(fn func([]EnvironmentChange)) { fn(append([]EnvironmentChange(nil), changes...)) })
	return nil
}

// LiveCertificate is a certificate from one dynamic certificate secret, kept current. It is renewed before it expires,
// once two thirds of its time have passed, and as soon as the secret's settings change, since that revokes the
// certificates issued under the old ones. Each renewal makes a new key. Read Current whenever a certificate is needed;
// OnChange is for each new one. From Client.LiveCertificate.
//
// A member revoking one certificate from the dashboard sends no event. Call Renew when a host refuses the certificate.
type LiveCertificate struct {
	liveHandle
	coordinate  string
	issue       func(ctx context.Context) (*Certificate, error)
	certificate *Certificate
	renewal     *time.Timer
	renewalGen  int
	failures    int
	onChange    listenerList[func(next, prev *Certificate)]
}

func newLiveCertificate(coordinate string, w *watcher, issue func(ctx context.Context) (*Certificate, error)) *LiveCertificate {
	l := &LiveCertificate{coordinate: coordinate, issue: issue}
	c := ParseSecretCoordinate(coordinate)
	l.init(strings.ToLower(c.Project+"/"+c.Environment), secretKeyOf(coordinate), w, l.load)
	l.delay = func() time.Duration {
		d := certificateRetry[min(l.failures, len(certificateRetry)-1)]
		l.failures++
		return d
	}
	l.ended = func() {
		l.mu.Lock()
		l.cancelRenewal()
		l.mu.Unlock()
	}
	return l
}

// Coordinate is the secret's project/env/NAME coordinate.
func (l *LiveCertificate) Coordinate() string { return l.coordinate }

// Current is the certificate as last issued, with its key.
func (l *LiveCertificate) Current() *Certificate {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.certificate
}

// Renew gets a new certificate now, with a new key, and makes it Current. It fails as GetCertificate would, and leaves
// the current one in place when it does.
func (l *LiveCertificate) Renew(ctx context.Context) (*Certificate, error) {
	if err := l.runLoad(ctx); err != nil {
		return nil, err
	}
	return l.Current(), nil
}

// OnChange calls fn with the new and the previous certificate each time a new one is issued. It returns a function that
// removes fn.
func (l *LiveCertificate) OnChange(fn func(next, prev *Certificate)) (remove func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.onChange.add(fn)
	return func() { l.mu.Lock(); l.onChange.remove(id); l.mu.Unlock() }
}

func (l *LiveCertificate) load(ctx context.Context) error {
	next, err := l.issue(ctx)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := l.certificate
	l.certificate = next
	l.failures = 0
	l.schedule(next)
	if prev != nil {
		emit(&l.liveHandle, l.onChange.snapshot(), func(fn func(next, prev *Certificate)) { fn(next, prev) })
	}
	return nil
}

// schedule sets the renewal of cert. Called with mu held.
func (l *LiveCertificate) schedule(cert *Certificate) {
	l.cancelRenewal()
	if l.status.final() {
		return
	}
	gen := l.renewalGen
	l.renewal = time.AfterFunc(renewDelay(cert, time.Now()), func() {
		l.mu.Lock()
		if l.renewalGen != gen {
			l.mu.Unlock()
			return
		}
		l.renewal = nil
		l.mu.Unlock()
		l.notify()
	})
}

// cancelRenewal stops a scheduled renewal. Called with mu held.
func (l *LiveCertificate) cancelRenewal() {
	if l.renewal != nil {
		l.renewal.Stop()
		l.renewal = nil
	}
	l.renewalGen++
}

// renewDelay is how long until a certificate is renewed: when two thirds of the time it has left have passed. Never
// sooner than a third of its lifetime, held between one and ten seconds, so a clock running a little ahead of the
// Burrow's can't make it renew in a loop.
func renewDelay(cert *Certificate, now time.Time) time.Duration {
	lifetime := cert.ValidBefore.Sub(cert.ValidAfter)
	floor := min(10*time.Second, max(time.Second, lifetime/3))
	return max(floor, cert.ValidBefore.Sub(now)*2/3).Round(time.Millisecond)
}

// secretKeyOf is a secret's coordinate as the Burrow names it on the stream: project and environment lowercase.
func secretKeyOf(coordinate string) string {
	first := strings.IndexByte(coordinate, '/')
	if first < 0 {
		return coordinate
	}
	second := strings.IndexByte(coordinate[first+1:], '/')
	if second < 0 {
		return strings.ToLower(coordinate)
	}
	second += first + 1
	return strings.ToLower(coordinate[:second]) + coordinate[second:]
}

// sameSecret reports whether two reads of a secret hold the same value.
func sameSecret(a, b *Secret) bool {
	if a.structured != b.structured {
		return false
	}
	if !a.structured {
		return a.value == b.value && a.typ == b.typ && a.version == b.version
	}
	if len(a.fields) != len(b.fields) {
		return false
	}
	for _, f := range a.fields {
		i, ok := b.byName[f.Name]
		if !ok || b.fields[i].Value != f.Value || b.fields[i].Type != f.Type {
			return false
		}
	}
	return true
}

// listenerList is a handle's listeners of one kind, in the order they were added.
type listenerList[F any] struct {
	next  int
	items []listenerEntry[F]
}

type listenerEntry[F any] struct {
	id int
	fn F
}

func (l *listenerList[F]) add(fn F) int {
	l.next++
	l.items = append(l.items, listenerEntry[F]{id: l.next, fn: fn})
	return l.next
}

func (l *listenerList[F]) remove(id int) {
	for i, item := range l.items {
		if item.id == id {
			l.items = append(l.items[:i:i], l.items[i+1:]...)
			return
		}
	}
}

func (l *listenerList[F]) snapshot() []F {
	out := make([]F, len(l.items))
	for i, item := range l.items {
		out[i] = item.fn
	}
	return out
}

// dispatcher runs a handle's listener calls on a goroutine of its own, one at a time and in the order they were queued,
// so a slow listener never holds up the stream, and a listener may call back into its handle.
type dispatcher struct {
	mu      sync.Mutex
	queue   []func()
	running bool
}

func (d *dispatcher) post(call func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queue = append(d.queue, call)
	if !d.running {
		d.running = true
		go d.drain()
	}
}

func (d *dispatcher) drain() {
	for {
		d.mu.Lock()
		if len(d.queue) == 0 {
			d.running = false
			d.mu.Unlock()
			return
		}
		call := d.queue[0]
		d.queue[0] = nil
		d.queue = d.queue[1:]
		d.mu.Unlock()
		call()
	}
}
