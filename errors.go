package burrow

import (
	"sort"
	"strings"
)

// Every Burrow failure the SDK returns is one of the error types below, matched with errors.As:
//
//	var notFound *burrow.NotFoundError
//	if errors.As(err, &notFound) { ... }
//
// They mirror the error types of the other Burrow SDKs one for one, so a failure means the same thing in every
// language.

// AuthError is the Burrow refusing the request's credential (HTTP 401): an unknown or disabled machine, a bad
// signature, a replayed nonce, a clock outside the freshness window, or an OIDC token it doesn't accept. It is also
// returned when the CI provider gives no OIDC token. Reason is the Burrow's own message.
type AuthError struct {
	Reason string
	// Err is what failed underneath, when requesting an OIDC token from the CI provider failed.
	Err error
}

func (e *AuthError) Error() string { return "burrow: " + e.Reason }

func (e *AuthError) Unwrap() error { return e.Err }

// ForbiddenError is a machine that authenticated but holds no grant for what it asked for (HTTP 403).
type ForbiddenError struct {
	Reason string
}

func (e *ForbiddenError) Error() string { return "burrow: " + e.Reason }

// NotFoundError is a project, environment, secret or field that doesn't exist (HTTP 404).
type NotFoundError struct {
	Reason string
}

func (e *NotFoundError) Error() string { return "burrow: " + e.Reason }

// ServerError is the Burrow failing to serve a request (HTTP 5xx), or refusing it because of the secret's own state
// (HTTP 409), such as a dynamic secret that isn't issuing.
type ServerError struct {
	Status int
	Reason string
	// Refusal is the reason the Burrow names in its Ratel-Refusal header, when it names one: "certificate-secret" for a
	// secret that issues certificates, read with GetSecret. Empty otherwise.
	Refusal string
}

func (e *ServerError) Error() string { return "burrow: " + e.Reason }

// CertificateError is a Burrow whose TLS key doesn't match the pinned one. Either the Burrow's key was created again
// (delete the pin in known_cert and retry) or the connection is being intercepted. Under TLSSystemTrust, it is also a
// certificate issued through the compromised eMudhra certificate authorities (CVE-2026-91403).
type CertificateError struct {
	Reason string
}

func (e *CertificateError) Error() string { return "burrow: " + e.Reason }

// TransportError is a Burrow that couldn't be reached, or a response that couldn't be read.
type TransportError struct {
	Reason string
	Err    error
}

func (e *TransportError) Error() string { return "burrow: " + e.Reason }

func (e *TransportError) Unwrap() error { return e.Err }

// IdentityError is a machine identity that couldn't be resolved or loaded: no identity on this host, an ambiguous
// selector, a missing or invalid private key, or a malformed identity file. A closed client from Enroll returns it
// for every read.
type IdentityError struct {
	Reason string
	Err    error
}

func (e *IdentityError) Error() string { return "burrow: " + e.Reason }

func (e *IdentityError) Unwrap() error { return e.Err }

// SecretShapeError is a projection that doesn't fit the secret's shape: Value on a structured secret, or ToMap, Fields,
// GetField or GetFields on a single value.
type SecretShapeError struct {
	Reason string
}

func (e *SecretShapeError) Error() string { return "burrow: " + e.Reason }

// FieldNotFoundError is a field a structured secret doesn't have.
type FieldNotFoundError struct {
	Secret string
	Field  string
	// Available is every field the secret has.
	Available []string
}

func (e *FieldNotFoundError) Error() string {
	names := append([]string(nil), e.Available...)
	sort.Strings(names)
	return "burrow: no field '" + e.Field + "' in '" + e.Secret + "' (has: " + strings.Join(names, ", ") + ")"
}

// WebhookError is a webhook delivery that failed verification: no signature, a wrong one, or a body that isn't a
// Burrow event.
type WebhookError struct {
	Reason string
	Err    error
}

func (e *WebhookError) Error() string { return "burrow: " + e.Reason }

func (e *WebhookError) Unwrap() error { return e.Err }

// errClientClosed is what a closed client from Enroll returns for every read, and what a Live call racing Close gets.
func errClientClosed() error {
	return &IdentityError{Reason: "this Burrow client has been closed"}
}
