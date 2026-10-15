package burrow

import (
	"context"
	"crypto/ed25519"
	"time"
)

// authorizer produces the auth headers for one machine-plane request: an Ed25519 signature (signedAuthorizer and
// enrolledAuthorizer) or a bearer token from the CI provider (oidcAuthorizer). The client doesn't mind which.
type authorizer interface {
	// machineID is the machine id when it's known here; empty under OIDC, where the Burrow resolves it from the token.
	machineID() string
	// authorize returns the headers for a request. resource is what an Ed25519 signature covers.
	authorize(ctx context.Context, action string, resource []string) (map[string]string, error)
	// recover reports, after a refused request signed with headers, whether to sign it again and send it once more.
	recover(ctx context.Context, err error, headers map[string]string) (bool, error)
	// close ends the identity, for one that owns its machine's lifetime.
	close() error
}

// signedAuthorizer signs each request with the machine's Ed25519 key.
type signedAuthorizer struct {
	id        string
	key       ed25519.PrivateKey
	clientTag string
	now       func() time.Time
}

func (a *signedAuthorizer) machineID() string { return a.id }

func (a *signedAuthorizer) authorize(_ context.Context, action string, resource []string) (map[string]string, error) {
	return signRequest(a.id, a.key, action, resource, a.clientTag, a.now())
}

func (a *signedAuthorizer) recover(context.Context, error, map[string]string) (bool, error) {
	return false, nil
}

func (a *signedAuthorizer) close() error { return nil }

// oidcAuthorizer gets a token from the CI provider for each request and sends it as a bearer. There is no key: the
// Burrow knows the machine from the token's claims.
type oidcAuthorizer struct {
	audience  string
	clientTag string
}

func (a *oidcAuthorizer) machineID() string { return "" }

func (a *oidcAuthorizer) authorize(ctx context.Context, _ string, _ []string) (map[string]string, error) {
	token, err := mintOIDCToken(ctx, a.audience)
	if err != nil {
		return nil, err
	}
	return map[string]string{"Authorization": "Bearer " + token, "Ratel-Client": a.clientTag}, nil
}

func (a *oidcAuthorizer) recover(context.Context, error, map[string]string) (bool, error) {
	return false, nil
}

func (a *oidcAuthorizer) close() error { return nil }
