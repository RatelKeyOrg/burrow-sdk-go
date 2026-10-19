package burrow

import (
	"os"
	"strings"
	"time"
)

// Option configures a client: how it trusts the Burrow (WithTLS), how it names itself in the Burrow's audit trail
// (WithClientTag), whether it keeps a cache (WithCache), and for Open, which identity it acts as (WithIdentity).
type Option func(*settings)

type settings struct {
	tls         TLSMode
	clientTag   string
	identity    string
	identitySet bool
	// cache is WithCache's choice; nil leaves it to the identity's switch.
	cache *bool
}

func collect(opts []Option) settings {
	s := settings{clientTag: DefaultClientTag}
	for _, opt := range opts {
		if opt != nil {
			opt(&s)
		}
	}
	return s
}

// WithTLS sets how the client trusts the Burrow's TLS certificate, in place of its default.
func WithTLS(mode TLSMode) Option {
	return func(s *settings) { s.tls = mode }
}

// WithClientTag sets the Ratel-Client tag recorded against each request in the Burrow's audit trail, in place of
// DefaultClientTag.
func WithClientTag(tag string) Option {
	return func(s *settings) {
		if strings.TrimSpace(tag) != "" {
			s.clientTag = tag
		}
	}
}

// WithIdentity picks the identity Open acts as, when this host holds more than one: a Burrow's name, slug, machine id or
// URL, or the path of an identity directory or identity.json file.
func WithIdentity(target string) Option {
	return func(s *settings) {
		s.identity = target
		s.identitySet = true
	}
}

// WithCache turns the cache on or off for the client. Without it, Open follows the switch `ratel cache enable` sets for
// its identity, and the cache is off for Connect.
//
// With the cache on, each secret the client reads is kept, encrypted with the machine's key, in its identity's folder.
// When GetSecret fails because the Burrow can't be reached or can't answer, the copy answers instead, and
// Secret.CachedAt says when it was saved; a live handle keeps the value it holds instead. When the Burrow refuses a read
// (the machine was removed or lost access, or the secret is gone), the copy is deleted. Connect needs
// ConnectConfig.PinStoreDir for it; Enroll and OIDC keep nothing on disk and can't have one.
func WithCache(enabled bool) Option {
	return func(s *settings) { s.cache = &enabled }
}

// Open opens a client as a machine identity on this host: the one under ~/.burrow (or $BURROW_HOME), or the one
// WithIdentity picks. A machine gets its identity when it's added from the Burrow's Machines page.
//
//	client, err := burrow.Open()
//	client, err := burrow.Open(burrow.WithIdentity("burrow-a1b2c3d4e5f60718"))
//
// On a host with no identity, Open enrolls from a machine token's code in BURROW_ENROLL_CODE when it's set, as Enroll
// does.
//
// The client trusts the Burrow the way chosen when the machine was added, unless WithTLS says otherwise.
func Open(opts ...Option) (*Client, error) {
	s := collect(opts)
	if strings.TrimSpace(s.identity) == "" {
		if code := strings.TrimSpace(os.Getenv(enrollCodeEnv)); code != "" && len(DiscoverIdentities()) == 0 {
			return enroll(code, s)
		}
	}
	id, err := selectIdentity(s.identity)
	if err != nil {
		return nil, err
	}
	key, err := id.PrivateKey()
	if err != nil {
		return nil, err
	}
	mode := s.tls
	if mode.kind == tlsDefault {
		mode = identityTLS(id.TLSMode)
	}
	auth := &signedAuthorizer{id: id.MachineID, key: key, clientTag: s.clientTag, now: time.Now}
	c := newClient(id.BurrowURL, auth, mode, id.Dir())
	if (s.cache == nil && cacheSwitchOn(id.Dir())) || (s.cache != nil && *s.cache) {
		c.cache = newSecretCache(id.Dir(), id.MachineID, key.Seed())
	}
	return c, nil
}

// identityTLS is the trust for an identity, from the mode chosen when its machine was added: "encrypted" accepts the
// encrypted connection without checking the Burrow's certificate, "system" verifies it against a CA, and anything else,
// including an identity written before the mode was recorded, pins the Burrow's own key.
func identityTLS(mode string) TLSMode {
	switch mode {
	case "encrypted":
		return TLSInsecure()
	case "system":
		return TLSSystemTrust()
	default:
		return TLSPinned()
	}
}

// ConnectConfig is an explicit machine identity, for Connect.
type ConnectConfig struct {
	// BurrowURL is the Burrow's address, such as https://burrow.internal:12010.
	BurrowURL string
	// MachineID is the machine's id on the Burrow.
	MachineID string
	// PrivateKeyPEM is the machine's Ed25519 private key, as a PKCS#8 PEM.
	PrivateKeyPEM string
	// PinStoreDir is the directory TLSPinned keeps the Burrow's pinned key in, as known_cert. Use one directory per
	// Burrow: two Burrows sharing one would overwrite each other's pin. Empty keeps the pin in memory for the life of the
	// client, which suits a container with no writable state; use TLSPinnedTo there instead, so trust doesn't start
	// over on every boot.
	PinStoreDir string
}

// Connect opens a client with an explicit identity, for an app that manages its own key rather than reading
// ~/.burrow. The client pins the Burrow's key on first use unless WithTLS says otherwise.
func Connect(config ConnectConfig, opts ...Option) (*Client, error) {
	s := collect(opts)
	if s.identitySet {
		return nil, &IdentityError{Reason: "WithIdentity is for Open; Connect takes its identity in ConnectConfig"}
	}
	if strings.TrimSpace(config.BurrowURL) == "" {
		return nil, &IdentityError{Reason: "ConnectConfig needs the Burrow's URL"}
	}
	if strings.TrimSpace(config.MachineID) == "" {
		return nil, &IdentityError{Reason: "ConnectConfig needs the machine id"}
	}
	key, err := parsePrivateKey([]byte(config.PrivateKeyPEM), "provided PEM")
	if err != nil {
		return nil, err
	}
	cached := s.cache != nil && *s.cache
	if cached && strings.TrimSpace(config.PinStoreDir) == "" {
		return nil, &IdentityError{Reason: "WithCache needs ConnectConfig.PinStoreDir, the folder the cache is kept in"}
	}
	mode := s.tls
	if mode.kind == tlsDefault {
		mode = TLSPinned()
	}
	auth := &signedAuthorizer{id: config.MachineID, key: key, clientTag: s.clientTag, now: time.Now}
	c := newClient(config.BurrowURL, auth, mode, config.PinStoreDir)
	if cached {
		c.cache = newSecretCache(config.PinStoreDir, config.MachineID, key.Seed())
	}
	return c, nil
}

// Enroll opens a client from a machine token's code, from the Burrow's Machine tokens page, and keeps the identity in
// memory only. The code carries the Burrow's URL and how to trust it, so the first request is already verified. The
// machine enrolls on the first request, a fresh one replaces it shortly before it expires, and Close ends it. Nothing
// is written to disk.
func Enroll(code string, opts ...Option) (*Client, error) {
	s := collect(opts)
	if s.identitySet {
		return nil, &IdentityError{Reason: "WithIdentity is for Open; Enroll takes its identity from the code"}
	}
	return enroll(code, s)
}

func enroll(raw string, s settings) (*Client, error) {
	if s.cache != nil && *s.cache {
		return nil, &IdentityError{Reason: "WithCache needs a machine identity kept on disk; an enrolled machine keeps nothing there"}
	}
	code, err := decodeEnrollmentCode(raw)
	if err != nil {
		return nil, err
	}
	mode := s.tls
	if mode.kind == tlsDefault {
		mode = enrollmentTLS(code)
	}
	auth := newEnrolledAuthorizer(code, newTransport(code.url, mode, ""), s.clientTag)
	return newClient(code.url, auth, mode, ""), nil
}

// OIDCConfig is a Burrow to reach with OIDC, for OIDC.
type OIDCConfig struct {
	// BurrowURL is the Burrow's address.
	BurrowURL string
	// Audience is the token audience the Burrow's trust policy requires. Empty uses BurrowURL.
	Audience string
	// Fingerprint is the Burrow's public-key fingerprint to pin, from its Network settings. Leave it empty for a Burrow
	// with a certificate from a public CA. WithTLS takes its place when given.
	Fingerprint string
}

// OIDC opens a client for a CI job that reads secrets with no key: GitHub Actions, GitLab CI/CD or Bitbucket Pipelines.
// Each request gets a token from the CI provider for the audience and sends it as a bearer; the Burrow checks it
// against the machine's trust policy. There is no key, and nothing is written to disk.
//
// The client pins the Fingerprint when one is given, and otherwise verifies the Burrow against the system's CAs:
// trusting on first use means nothing on a runner that starts fresh each time.
func OIDC(config OIDCConfig, opts ...Option) (*Client, error) {
	s := collect(opts)
	if s.identitySet {
		return nil, &IdentityError{Reason: "WithIdentity is for Open; OIDC authenticates with the CI provider's token"}
	}
	if strings.TrimSpace(config.BurrowURL) == "" {
		return nil, &IdentityError{Reason: "OIDCConfig needs the Burrow's URL"}
	}
	if s.cache != nil && *s.cache {
		return nil, &IdentityError{Reason: "WithCache needs a machine identity kept on disk; OIDC keeps no key to encrypt a cache with"}
	}
	audience := config.Audience
	if audience == "" {
		audience = config.BurrowURL
	}
	mode := s.tls
	if mode.kind == tlsDefault {
		mode = TLSSystemTrust()
		if config.Fingerprint != "" {
			mode = TLSPinnedTo(config.Fingerprint)
		}
	}
	return newClient(config.BurrowURL, &oidcAuthorizer{audience: audience, clientTag: s.clientTag}, mode, ""), nil
}
