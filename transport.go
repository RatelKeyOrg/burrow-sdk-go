package burrow

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const requestTimeout = 15 * time.Second

// machineALPN is offered so a Burrow reached through RatelKey's relay answers with its own certificate, the one a pin
// is taken from, rather than the certificate for its relay hostname. A Burrow ignores it otherwise. It's left off under
// system trust, where only the relay hostname's certificate is one a CA vouches for. Kept in step with the ratel CLI.
const machineALPN = "ratel-machine/1"

const (
	// maxResponseBytes bounds what one response may hold, so a misbehaving server can't make the client hold unbounded
	// memory. A response past it is an error, never cut short.
	maxResponseBytes = 32 << 20
	// maxEventLine bounds one line of the event stream.
	maxEventLine = 4 << 20
)

// transport makes machine-plane requests to one Burrow under the configured TLSMode, and maps the Burrow's status and
// {"error": …} body to the SDK's error types, keeping the Burrow's own reason.
//
// A pinned Burrow's key is checked during the TLS handshake, before the HTTP request is written, so a server with the
// wrong key never sees the signed Ratel-* headers. Each request has a connection of its own, so each one is checked
// against the pin as it stands.
type transport struct {
	base   string
	mode   TLSMode
	pins   pinStore
	client *http.Client
	// stream is client without its overall timeout, for the event stream, which stays open.
	stream *http.Client

	mu sync.Mutex
	// pinned is the fingerprint enforced: TLSPinnedTo's, or under TLSPinned the one on file, or the one learned on first
	// contact. Empty under TLSPinned until the first pin is learned.
	pinned string
}

// newTransport is a transport to burrowURL; identityDir is where the Burrow's pinned key is kept, empty for memory only.
func newTransport(burrowURL string, mode TLSMode, identityDir string) *transport {
	t := &transport{base: strings.TrimRight(burrowURL, "/"), mode: mode, pins: pinStore{dir: identityDir}}
	switch mode.kind {
	case tlsPinnedTo:
		t.pinned = mode.fingerprint
	case tlsPinned, tlsDefault:
		t.pinned = t.pins.read()
	}
	httpTransport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: requestTimeout}).DialContext,
		TLSClientConfig:        t.tlsConfig(),
		TLSHandshakeTimeout:    requestTimeout,
		ResponseHeaderTimeout:  requestTimeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	t.client = &http.Client{Transport: httpTransport, Timeout: requestTimeout, CheckRedirect: refuseRedirect}
	t.stream = &http.Client{Transport: httpTransport, CheckRedirect: refuseRedirect}
	return t
}

// refuseRedirect keeps a redirect as the response: a signed request goes to the Burrow it was signed for, and nowhere
// it points.
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (t *transport) tlsConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch t.mode.kind {
	case tlsSystemTrust:
		// Full CA and hostname verification.
		return cfg
	case tlsInsecure:
		cfg.InsecureSkipVerify = true //nolint:gosec // the caller chose no verification
		cfg.NextProtos = []string{machineALPN}
		return cfg
	default:
		// The pinned modes reach a certificate by IP, or on a domain no CA vouches for, and verify its key instead.
		cfg.InsecureSkipVerify = true //nolint:gosec // verified against the pin in verifyPin
		cfg.NextProtos = []string{machineALPN}
		cfg.VerifyConnection = t.verifyPin
		return cfg
	}
}

func (t *transport) verifyPin(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return &CertificateError{Reason: "Burrow presented no certificate"}
	}
	seen := keyPin(cs.PeerCertificates[0])
	t.mu.Lock()
	pin := t.pinned
	t.mu.Unlock()
	// TLSPinnedTo always compares, so an empty fingerprint refuses every key rather than accepting the first.
	if pin == "" && t.mode.kind != tlsPinnedTo {
		return nil
	}
	if !fingerprintsEqual(seen, pin) {
		return &CertificateError{Reason: fmt.Sprintf("Burrow key does not match the pinned one (pinned=%s, got=%s)", pin, seen)}
	}
	return nil
}

// commitPin records the key seen on a successful exchange, the first time, under TLSPinned. TLSPinnedTo's pin is the
// caller's and never learned.
func (t *transport) commitPin(resp *http.Response) {
	if (t.mode.kind != tlsPinned && t.mode.kind != tlsDefault) || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return
	}
	seen := keyPin(resp.TLS.PeerCertificates[0])
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pinned != "" {
		return
	}
	t.pins.write(seen)
	t.pinned = seen
}

// get sends a GET and returns the body of a 2xx response; anything else is one of the SDK's errors.
func (t *transport) get(ctx context.Context, path string, headers map[string]string) ([]byte, error) {
	return t.send(ctx, http.MethodGet, path, headers, nil)
}

// post sends a POST with payload as its JSON body, or no body when payload is nil.
func (t *transport) post(ctx context.Context, path string, headers map[string]string, payload []byte) ([]byte, error) {
	return t.send(ctx, http.MethodPost, path, headers, payload)
}

func (t *transport) send(ctx context.Context, method, path string, headers map[string]string, payload []byte) ([]byte, error) {
	req, err := t.request(ctx, method, path, headers, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, t.reachError(err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, &TransportError{Reason: "reading the response from burrow " + t.base + ": " + err.Error(), Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errorFor(resp.StatusCode, body, refusalOf(resp))
	}
	t.commitPin(resp)
	return body, nil
}

func (t *transport) request(ctx context.Context, method, path string, headers map[string]string, payload []byte) (*http.Request, error) {
	target := t.base + path
	u, err := url.Parse(target)
	if err != nil {
		return nil, &TransportError{Reason: fmt.Sprintf("invalid burrow URL '%s': %v", target, err), Err: err}
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, &TransportError{Reason: fmt.Sprintf("burrow URL '%s' is not http(s)", t.base)}
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, &TransportError{Reason: fmt.Sprintf("invalid burrow URL '%s': %v", target, err), Err: err}
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// reachError is a request that got no response: a key that doesn't match the pin, or a Burrow that couldn't be
// reached. The Go error stays underneath, so errors.Is(err, context.Canceled) and the like still work.
func (t *transport) reachError(err error) error {
	var certificate *CertificateError
	if errors.As(err, &certificate) {
		return certificate
	}
	cause := err
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cause = urlErr.Err
	}
	return &TransportError{Reason: "reaching burrow " + t.base + ": " + cause.Error(), Err: err}
}

// errorFor maps a refused response to the SDK's error for its status, with the Burrow's reason: the "error" of its
// JSON body, or else the body itself.
func errorFor(status int, body []byte, refusal string) error {
	reason := ""
	var parsed struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		if s, ok := parsed.Error.(string); ok {
			reason = s
		}
	}
	if strings.TrimSpace(reason) == "" {
		reason = strings.TrimSpace(string(body))
		if reason == "" {
			reason = "(no message)"
		}
	}
	switch status {
	case http.StatusUnauthorized:
		return &AuthError{Reason: reason}
	case http.StatusForbidden:
		return &ForbiddenError{Reason: reason}
	case http.StatusNotFound:
		return &NotFoundError{Reason: reason}
	default:
		return &ServerError{Status: status, Reason: reason, Refusal: refusal}
	}
}

// refusalOf is the reason a refusal names in its Ratel-Refusal header, or empty.
func refusalOf(resp *http.Response) string {
	return strings.TrimSpace(resp.Header.Get("Ratel-Refusal"))
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("the response is larger than %d MiB", limit>>20)
	}
	return data, nil
}

// eventStream is an open server-sent event stream from the Burrow.
type eventStream struct {
	base string
	body io.ReadCloser
}

// openStream opens a signed event stream. It returns once the Burrow answers 200; any other answer is one of the SDK's
// errors. The stream stays open until ctx ends, the Burrow ends it, or the connection drops.
func (t *transport) openStream(ctx context.Context, path string, headers map[string]string) (*eventStream, error) {
	req, err := t.request(ctx, http.MethodGet, path, headers, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := t.stream.Do(req)
	if err != nil {
		return nil, t.reachError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := readLimited(resp.Body, 1<<20)
		return nil, errorFor(resp.StatusCode, body, refusalOf(resp))
	}
	t.commitPin(resp)
	return &eventStream{base: t.base, body: resp.Body}, nil
}

func (s *eventStream) close() { _ = s.body.Close() }

// read passes each event to onEvent as its name and data, and calls onActivity for every line, pings included. It
// returns nil when the Burrow ends the stream, and a *TransportError when the connection fails.
func (s *eventStream) read(onEvent func(event, data string), onActivity func()) error {
	r := bufio.NewReaderSize(s.body, 16<<10)
	var event, data string
	for {
		line, err := readLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return &TransportError{Reason: "lost the watch connection to " + s.base + ": " + err.Error(), Err: err}
		}
		onActivity()
		switch {
		case line == "":
			if event != "" {
				onEvent(event, data)
			}
			event, data = "", ""
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(line[len("data:"):])
		}
	}
}

// readLine reads one line without its line ending. A line cut off by the end of the stream is dropped.
func readLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > maxEventLine {
			return "", errors.New("an event line is too long")
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return strings.TrimSuffix(string(line[:len(line)-1]), "\r"), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", err
		}
	}
}
