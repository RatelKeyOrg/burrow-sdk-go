package burrow

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// watcher is a client's one event stream (GET /v1/machine/watch), shared by every live handle. It opens with the first
// handle and closes with the last. It reconnects with backoff after a dropped connection or 45 seconds of silence, and
// on reconnecting, each handle whose environment's fingerprint moved is read again. A refusal the authorizer can
// recover from (an enrolled identity whose machine was replaced) reconnects at once; any other refusal revokes every
// handle.
type watcher struct {
	// transport is the client's transport at the time of each connection.
	transport func() *transport
	auth      authorizer

	mu      sync.Mutex
	handles map[*liveHandle]struct{}
	// fingerprints is each environment's fingerprint as the stream last reported it; nil until the first ready event.
	fingerprints map[string]string
	running      bool
	// gen numbers the connection loops. Stopping moves it on, so a loop that's been stopped can't change what a newer
	// one holds.
	gen       int
	cancel    context.CancelFunc
	connected bool
	waiters   []chan error
}

func newWatcher(transport func() *transport, auth authorizer) *watcher {
	return &watcher{transport: transport, auth: auth, handles: map[*liveHandle]struct{}{}}
}

func (w *watcher) isConnected() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.connected
}

// add follows h, and returns once the stream is open. It fails when the first connection fails, or when ctx ends
// first.
func (w *watcher) add(ctx context.Context, h *liveHandle) error {
	w.mu.Lock()
	w.handles[h] = struct{}{}
	if w.connected {
		w.mu.Unlock()
		return nil
	}
	waiter := make(chan error, 1)
	w.waiters = append(w.waiters, waiter)
	if !w.running {
		w.running = true
		w.gen++
		loopCtx, cancel := context.WithCancel(context.Background())
		w.cancel = cancel
		go w.loop(loopCtx, w.gen)
	}
	w.mu.Unlock()
	select {
	case err := <-waiter:
		return err
	case <-ctx.Done():
		w.mu.Lock()
		for i, ch := range w.waiters {
			if ch == waiter {
				w.waiters = append(w.waiters[:i:i], w.waiters[i+1:]...)
				break
			}
		}
		w.mu.Unlock()
		return ctx.Err()
	}
}

// remove stops following h, and ends the stream when no handle is left.
func (w *watcher) remove(h *liveHandle) {
	w.mu.Lock()
	delete(w.handles, h)
	var finish func()
	if len(w.handles) == 0 {
		finish = w.stop()
	}
	w.mu.Unlock()
	if finish != nil {
		finish()
	}
}

// close closes every handle and the stream.
func (w *watcher) close() {
	w.mu.Lock()
	gen := w.gen
	w.mu.Unlock()
	w.endAll(gen, StatusClosed)
}

// endAll gives every handle status and ends the stream, unless loop gen has already been stopped.
func (w *watcher) endAll(gen int, status LiveStatus) {
	w.mu.Lock()
	if w.gen != gen {
		w.mu.Unlock()
		return
	}
	handles := w.snapshot()
	w.handles = map[*liveHandle]struct{}{}
	finish := w.stop()
	w.mu.Unlock()
	for _, h := range handles {
		h.setStatus(status)
	}
	finish()
}

// stop ends the current connection loop. Called with mu held; it returns what to do once mu is released.
func (w *watcher) stop() func() {
	w.running = false
	w.connected = false
	w.fingerprints = nil
	w.gen++
	cancel := w.cancel
	w.cancel = nil
	waiters := w.waiters
	w.waiters = nil
	return func() {
		if cancel != nil {
			cancel()
		}
		for _, ch := range waiters {
			ch <- errClientClosed()
		}
	}
}

func (w *watcher) snapshot() []*liveHandle {
	out := make([]*liveHandle, 0, len(w.handles))
	for h := range w.handles {
		out = append(out, h)
	}
	return out
}

// current is the handles of loop gen, or none when it has been stopped.
func (w *watcher) current(gen int) []*liveHandle {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gen != gen {
		return nil
	}
	return w.snapshot()
}

func (w *watcher) rejectWaiters(gen int, err error) {
	w.mu.Lock()
	if w.gen != gen {
		w.mu.Unlock()
		return
	}
	waiters := w.waiters
	w.waiters = nil
	w.mu.Unlock()
	for _, ch := range waiters {
		ch <- err
	}
}

func (w *watcher) loop(ctx context.Context, gen int) {
	attempt := 0
	for ctx.Err() == nil {
		headers, refused := w.auth.authorize(ctx, "watch", nil)
		if refused == nil {
			refused = w.follow(ctx, gen, headers, &attempt)
		}
		w.mu.Lock()
		if w.gen != gen {
			w.mu.Unlock()
			return
		}
		w.connected = false
		w.mu.Unlock()

		var authErr *AuthError
		if errors.As(refused, &authErr) {
			retry, err := w.auth.recover(ctx, refused, headers)
			if err != nil {
				refused = err
			} else if retry {
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		var notFound *NotFoundError
		var forbidden *ForbiddenError
		var identity *IdentityError
		switch {
		case errors.As(refused, &notFound):
			w.rejectWaiters(gen, &NotFoundError{Reason: "this Burrow has no live updates; update the Burrow to use live secrets"})
			w.endAll(gen, StatusRevoked)
			return
		case errors.As(refused, &authErr), errors.As(refused, &forbidden), errors.As(refused, &identity):
			w.rejectWaiters(gen, refused)
			w.endAll(gen, StatusRevoked)
			return
		}
		if refused != nil {
			w.rejectWaiters(gen, refused)
		}
		for _, h := range w.current(gen) {
			h.setStatus(StatusReconnecting)
		}
		delay := jitter(reconnectBackoff[min(attempt, len(reconnectBackoff)-1)])
		attempt++
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

// follow opens the stream and reads it to its end. It returns nil when the stream ended cleanly or was closed here (on
// silence, or by stopping), and otherwise why it ended.
func (w *watcher) follow(ctx context.Context, gen int, headers map[string]string, attempt *int) error {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := w.transport().openStream(streamCtx, "/v1/machine/watch", headers)
	if err != nil {
		return err
	}
	defer stream.close()
	silence := time.AfterFunc(silenceTimeout, cancel)
	defer silence.Stop()

	var refused error
	readErr := stream.read(func(event, data string) {
		switch event {
		case "ready":
			*attempt = 0
			w.onReady(gen, data)
		case "changed":
			w.onChanged(gen, data)
		case "unauthorized":
			refused = &AuthError{Reason: unauthorizedReason(data)}
			cancel()
		}
	}, func() { silence.Reset(silenceTimeout) })
	if refused != nil {
		return refused
	}
	if streamCtx.Err() != nil {
		return nil
	}
	return readErr
}

func (w *watcher) onReady(gen int, data string) {
	environments := stringMap(parseObject(data)["environments"])
	w.mu.Lock()
	if w.gen != gen {
		w.mu.Unlock()
		return
	}
	before := w.fingerprints
	w.fingerprints = environments
	w.connected = true
	waiters := w.waiters
	w.waiters = nil
	handles := w.snapshot()
	w.mu.Unlock()
	for _, ch := range waiters {
		ch <- nil
	}
	for _, h := range handles {
		if before != nil && before[h.envKey] != environments[h.envKey] {
			h.notify()
		} else {
			h.confirm()
		}
	}
}

func (w *watcher) onChanged(gen int, data string) {
	parsed := parseObject(data)
	environments := stringMap(parsed["environments"])
	secrets := map[string]bool{}
	if list, ok := parsed["secrets"].([]any); ok {
		for _, s := range list {
			if name, ok := s.(string); ok {
				secrets[name] = true
			}
		}
	}
	w.mu.Lock()
	if w.gen != gen {
		w.mu.Unlock()
		return
	}
	if w.fingerprints != nil {
		next := make(map[string]string, len(w.fingerprints))
		for env, fingerprint := range w.fingerprints {
			next[env] = fingerprint
		}
		for env, fingerprint := range environments {
			if fingerprint == "" {
				delete(next, env)
			} else {
				next[env] = fingerprint
			}
		}
		w.fingerprints = next
	}
	handles := w.snapshot()
	w.mu.Unlock()
	for _, h := range handles {
		if h.secKey != "" {
			if secrets[h.secKey] {
				h.notify()
			}
		} else if _, ok := environments[h.envKey]; ok {
			h.notify()
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + rand.Float64()*0.4))
}

func unauthorizedReason(data string) string {
	if reason, ok := parseObject(data)["error"].(string); ok && reason != "" {
		return reason
	}
	return "the Burrow ended the watch"
}

func parseObject(data string) map[string]any {
	var parsed map[string]any
	if json.Unmarshal([]byte(data), &parsed) != nil || parsed == nil {
		return map[string]any{}
	}
	return parsed
}

func stringMap(value any) map[string]string {
	out := map[string]string{}
	if m, ok := value.(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}
