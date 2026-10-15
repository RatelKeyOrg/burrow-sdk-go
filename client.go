package burrow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// refusedCertificateSecret is the Ratel-Refusal a Burrow gives a read of a secret that issues certificates.
const refusedCertificateSecret = "certificate-secret"

// Client reads secrets from a Burrow as one machine. Every request is authenticated on its own, by an Ed25519
// signature or a fresh OIDC token, with no session held. A Client is safe for concurrent use; open one with Open,
// Connect, Enroll or OIDC, and Close it when done.
type Client struct {
	burrowURL string
	auth      authorizer
	// tls is the trust the client was opened with, which InsecureTLS(false) restores.
	tls     TLSMode
	pinDir  string
	watcher *watcher

	mu        sync.RWMutex
	transport *transport
}

func newClient(burrowURL string, auth authorizer, mode TLSMode, pinDir string) *Client {
	c := &Client{burrowURL: burrowURL, auth: auth, tls: mode, pinDir: pinDir, transport: newTransport(burrowURL, mode, pinDir)}
	c.watcher = newWatcher(c.currentTransport, auth)
	return c
}

func (c *Client) currentTransport() *transport {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.transport
}

// BurrowURL is the Burrow this client reads from.
func (c *Client) BurrowURL() string { return c.burrowURL }

// MachineID is the machine this client acts as. It's empty under OIDC, where the Burrow resolves it, and for a client
// from Enroll until its first request.
func (c *Client) MachineID() string { return c.auth.machineID() }

// InsecureTLS turns TLS verification off, or back on, for this client, and returns it. With it off, any certificate the
// Burrow presents is accepted, with no CA, hostname or pin check. Opt in only, for a network you already trust. Passing
// false restores the trust the client was opened with.
func (c *Client) InsecureTLS(enabled bool) *Client {
	mode := c.tls
	if enabled {
		mode = TLSInsecure()
	}
	t := newTransport(c.burrowURL, mode, c.pinDir)
	c.mu.Lock()
	c.transport = t
	c.mu.Unlock()
	return c
}

// GetSecret reads a secret by its project/env/NAME coordinate, whole, in one signed request. Project the result with
// Value, ToMap, GetField or GetFields; those don't fetch again.
//
// A dynamic certificate secret, such as an SSH user secret, is read with GetCertificate; GetSecret on one returns a
// *ServerError (409) naming it.
func (c *Client) GetSecret(ctx context.Context, coordinate string) (*Secret, error) {
	sc, err := secretCoordinate(coordinate)
	if err != nil {
		return nil, err
	}
	body, err := c.signed(ctx, http.MethodGet, "secret.read", []string{sc.Project, sc.Environment, sc.Name},
		"/v1/machine/secrets/"+encodeSegment(sc.Project)+"/"+encodeSegment(sc.Environment)+"/"+encodeSegment(sc.Name), nil)
	if err != nil {
		var server *ServerError
		if errors.As(err, &server) && server.Refusal == refusedCertificateSecret {
			return nil, &ServerError{
				Status:  server.Status,
				Reason:  sc.Name + " is a dynamic certificate secret. Fetch it with GetCertificate(\"" + coordinate + "\").",
				Refusal: server.Refusal,
			}
		}
		return nil, err
	}
	var dto secretDTO
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, decodeError(err)
	}
	return dto.secret(), nil
}

// GetCertificate gets a certificate from a dynamic certificate secret, such as an SSH user secret, by its
// project/env/NAME coordinate. A new Ed25519 key is made in memory, only its public half is sent, and the secret's
// certificate authority certifies it. The result holds the certificate and the key:
//
//	login, err := client.GetCertificate(ctx, "api/prod/DEPLOY_SSH")
//	login.PrivateKey()   // the OpenSSH private key
//	login.Certificate    // its certificate
//	login.Principals     // the logins it signs in as
//
// Each call issues a new certificate for a new key. WithValidity asks for one that lasts less than the secret allows.
// A secret that isn't issuing this machine a certificate returns a *ServerError (409) with the Burrow's reason.
func (c *Client) GetCertificate(ctx context.Context, coordinate string, opts ...CertificateOption) (*Certificate, error) {
	sc, err := secretCoordinate(coordinate)
	if err != nil {
		return nil, err
	}
	validity, err := validitySeconds(opts)
	if err != nil {
		return nil, err
	}
	keys, err := newSSHKeyPair(coordinate)
	if err != nil {
		return nil, err
	}
	request := map[string]any{"publicKey": keys.publicKey}
	if validity > 0 {
		request["validitySeconds"] = validity
	}
	payload, _ := json.Marshal(request)
	body, err := c.signed(ctx, http.MethodPost, "secret.certificate", []string{sc.Project, sc.Environment, sc.Name},
		"/v1/machine/secrets/"+encodeSegment(sc.Project)+"/"+encodeSegment(sc.Environment)+"/"+encodeSegment(sc.Name)+"/certificate", payload)
	if err != nil {
		return nil, err
	}
	return parseCertificate(body, keys)
}

// ListSecrets is every secret this machine can read, resolved by the Burrow.
func (c *Client) ListSecrets(ctx context.Context) ([]SecretCoordinate, error) {
	body, err := c.signed(ctx, http.MethodGet, "secrets.list", nil, "/v1/machine/secrets", nil)
	if err != nil {
		return nil, err
	}
	var dto struct {
		Secrets []string `json:"secrets"`
	}
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, decodeError(err)
	}
	out := make([]SecretCoordinate, len(dto.Secrets))
	for i, s := range dto.Secrets {
		out[i] = ParseSecretCoordinate(s)
	}
	return out, nil
}

// ListProjects is every project this machine can read, and the environment categories it holds in each.
func (c *Client) ListProjects(ctx context.Context) ([]ProjectAccess, error) {
	body, err := c.signed(ctx, http.MethodGet, "projects.list", nil, "/v1/machine/projects", nil)
	if err != nil {
		return nil, err
	}
	var dto struct {
		Projects []struct {
			Project    string   `json:"project"`
			Categories []string `json:"categories"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, decodeError(err)
	}
	out := make([]ProjectAccess, len(dto.Projects))
	for i, p := range dto.Projects {
		out[i] = ProjectAccess{Project: p.Project, Categories: append([]string{}, p.Categories...)}
	}
	return out, nil
}

// Live is one secret, kept current. It returns after the first read, then follows every change on the Burrow over one
// event stream shared by all of the client's live handles. It fails as GetSecret would, or with a *NotFoundError when
// the Burrow has no live updates.
func (c *Client) Live(ctx context.Context, coordinate string) (*LiveSecret, error) {
	if _, err := secretCoordinate(coordinate); err != nil {
		return nil, err
	}
	h := newLiveSecret(coordinate, c.watcher, func(ctx context.Context) (*Secret, error) { return c.GetSecret(ctx, coordinate) })
	if err := c.follow(ctx, &h.liveHandle); err != nil {
		return nil, err
	}
	return h, nil
}

// LiveEnvironment is every secret in one project/env environment, kept current, as Live does for one secret.
func (c *Client) LiveEnvironment(ctx context.Context, coordinate string) (*LiveEnvironment, error) {
	ec := ParseSecretCoordinate(coordinate)
	if strings.TrimSpace(ec.Project) == "" || strings.TrimSpace(ec.Environment) == "" || ec.Name != "" {
		return nil, fmt.Errorf("burrow: environment coordinate must be 'project/environment', got '%s'", coordinate)
	}
	h := newLiveEnvironment(coordinate, ec.Project, ec.Environment, c.watcher, func(ctx context.Context) (map[string]*Secret, error) {
		return c.readEnvironment(ctx, ec.Project, ec.Environment)
	})
	if err := c.follow(ctx, &h.liveHandle); err != nil {
		return nil, err
	}
	return h, nil
}

// LiveCertificate is a certificate from one dynamic certificate secret, kept current. It returns with the first one,
// then renews it before it expires and as soon as the secret's settings change, each time with a new key. It shares
// the event stream of the client's other live handles, and fails as GetCertificate would, or with a *NotFoundError
// when the Burrow has no live updates.
func (c *Client) LiveCertificate(ctx context.Context, coordinate string, opts ...CertificateOption) (*LiveCertificate, error) {
	if _, err := secretCoordinate(coordinate); err != nil {
		return nil, err
	}
	if _, err := validitySeconds(opts); err != nil {
		return nil, err
	}
	h := newLiveCertificate(coordinate, c.watcher, func(ctx context.Context) (*Certificate, error) {
		return c.GetCertificate(ctx, coordinate, opts...)
	})
	if err := c.follow(ctx, &h.liveHandle); err != nil {
		return nil, err
	}
	return h, nil
}

// Close closes every live handle and ends the event stream. For a client from Enroll (or BURROW_ENROLL_CODE), it also
// ends its machine now, so the machine shows as expired on the Burrow at once, and later reads are refused.
func (c *Client) Close() error {
	c.watcher.close()
	return c.auth.close()
}

// follow opens the stream for h, then reads it. On failure h is dropped.
func (c *Client) follow(ctx context.Context, h *liveHandle) error {
	if err := c.watcher.add(ctx, h); err != nil {
		c.watcher.remove(h)
		return err
	}
	if err := h.initialize(ctx); err != nil {
		c.watcher.remove(h)
		return err
	}
	return nil
}

// readEnvironment is every secret in one environment, by name, in one signed request.
func (c *Client) readEnvironment(ctx context.Context, project, environment string) (map[string]*Secret, error) {
	body, err := c.signed(ctx, http.MethodGet, "env.read", []string{project, environment},
		"/v1/machine/secrets/"+encodeSegment(project)+"/"+encodeSegment(environment), nil)
	if err != nil {
		return nil, err
	}
	var dto struct {
		Values     []secretDTO `json:"values"`
		Structured []secretDTO `json:"structured"`
	}
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, decodeError(err)
	}
	out := make(map[string]*Secret, len(dto.Values)+len(dto.Structured))
	for _, d := range append(dto.Values, dto.Structured...) {
		s := d.secret()
		out[s.name] = s
	}
	return out, nil
}

// signed sends one authenticated request. A refusal the authorizer recovers from is signed again and sent once more.
func (c *Client) signed(ctx context.Context, method, action string, resource []string, path string, payload []byte) ([]byte, error) {
	headers, err := c.auth.authorize(ctx, action, resource)
	if err != nil {
		return nil, err
	}
	body, err := c.currentTransport().send(ctx, method, path, headers, payload)
	if err == nil {
		return body, nil
	}
	retry, rerr := c.auth.recover(ctx, err, headers)
	if rerr != nil {
		return nil, rerr
	}
	if !retry {
		return nil, err
	}
	if headers, err = c.auth.authorize(ctx, action, resource); err != nil {
		return nil, err
	}
	return c.currentTransport().send(ctx, method, path, headers, payload)
}

// secretCoordinate is a project/env/NAME coordinate with all three parts.
func secretCoordinate(coordinate string) (SecretCoordinate, error) {
	sc := ParseSecretCoordinate(coordinate)
	if strings.TrimSpace(sc.Project) == "" || strings.TrimSpace(sc.Environment) == "" || strings.TrimSpace(sc.Name) == "" {
		return SecretCoordinate{}, fmt.Errorf("burrow: secret coordinate must be 'project/environment/NAME', got '%s'", coordinate)
	}
	return sc, nil
}

// secretDTO is a read response: value and version for a single value, fields for a structured secret. It mirrors the
// Burrow's MachineSecretView and MachineStructuredView; other keys are ignored.
type secretDTO struct {
	Name    string  `json:"name"`
	Value   *string `json:"value"`
	Type    string  `json:"type"`
	Version int     `json:"version"`
	Fields  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"fields"`
}

func (d secretDTO) secret() *Secret {
	if d.Fields != nil {
		fields := make([]SecretField, len(d.Fields))
		for i, f := range d.Fields {
			fields[i] = SecretField{Name: f.Name, Value: f.Value, Type: f.Type}
		}
		return newStructuredSecret(d.Name, fields)
	}
	value := ""
	if d.Value != nil {
		value = *d.Value
	}
	return newSingleSecret(d.Name, value, d.Type, d.Version)
}

// parseCertificate reads the certificate response, with the key it was issued for. It mirrors the Burrow's
// MachineCertificateView; times are epoch milliseconds, and other keys are ignored.
func parseCertificate(body []byte, keys sshKeyPair) (*Certificate, error) {
	var dto struct {
		Name        string         `json:"name"`
		Type        string         `json:"type"`
		Certificate string         `json:"certificate"`
		Details     map[string]any `json:"details"`
		Host        *string        `json:"host"`
		Serial      int64          `json:"serial"`
		KeyID       string         `json:"keyId"`
		ValidAfter  int64          `json:"validAfter"`
		ValidBefore int64          `json:"validBefore"`
	}
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, decodeError(err)
	}
	if dto.Certificate == "" {
		return nil, &TransportError{Reason: "decoding burrow response: no certificate in it"}
	}
	if dto.Details == nil {
		dto.Details = map[string]any{}
	}
	principals := []string{}
	if list, ok := dto.Details["principals"].([]any); ok {
		for _, p := range list {
			if s, ok := p.(string); ok {
				principals = append(principals, s)
			}
		}
	}
	host := ""
	if dto.Host != nil {
		host = strings.TrimSpace(*dto.Host)
	}
	return &Certificate{
		Name:        dto.Name,
		Type:        dto.Type,
		Certificate: dto.Certificate,
		PublicKey:   keys.publicKey,
		Principals:  principals,
		Host:        host,
		Serial:      dto.Serial,
		KeyID:       dto.KeyID,
		ValidAfter:  time.UnixMilli(dto.ValidAfter),
		ValidBefore: time.UnixMilli(dto.ValidBefore),
		Details:     dto.Details,
		privateKey:  keys.privateKey,
	}, nil
}

func decodeError(err error) error {
	return &TransportError{Reason: "decoding burrow response: " + err.Error(), Err: err}
}

// encodeSegment percent-encodes one URL path segment, keeping only RFC 3986's unreserved characters, so a coordinate
// reaches the Burrow intact and decodes back to the exact value the signature covers.
func encodeSegment(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}
