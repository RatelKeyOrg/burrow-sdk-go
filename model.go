package burrow

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// SecretField is one field of a structured secret: its name, its current value, and its declared type.
type SecretField struct {
	Name  string
	Value string
	Type  string
}

// Secret is a secret read from a Burrow, fetched whole in one signed call. Project it locally, without another
// request: Value for a single value, or ToMap, Fields, GetField and GetFields for a structured secret.
//
//	db, err := client.GetSecret(ctx, "payments/prod/DATABASE")
//	user, err := db.GetField("username")
//	all, err := db.ToMap()
//
// A projection that doesn't fit the secret's shape returns a *SecretShapeError, and a missing field a
// *FieldNotFoundError. Printing a Secret shows its name and never its value.
type Secret struct {
	name       string
	value      string
	typ        string
	version    int
	structured bool
	fields     []SecretField
	byName     map[string]int
}

func newSingleSecret(name, value, typ string, version int) *Secret {
	return &Secret{name: name, value: value, typ: typ, version: version}
}

func newStructuredSecret(name string, fields []SecretField) *Secret {
	s := &Secret{name: name, structured: true, byName: make(map[string]int, len(fields))}
	for _, f := range fields {
		if i, ok := s.byName[f.Name]; ok {
			s.fields[i] = f
			continue
		}
		s.byName[f.Name] = len(s.fields)
		s.fields = append(s.fields, f)
	}
	return s
}

// Name is the secret's name: the last part of its project/env/NAME coordinate.
func (s *Secret) Name() string { return s.name }

// IsStructured reports whether the secret has fields rather than a single value.
func (s *Secret) IsStructured() bool { return s.structured }

// Value is a single-value secret's value.
func (s *Secret) Value() (string, error) {
	if s.structured {
		return "", &SecretShapeError{Reason: fmt.Sprintf("'%s' is a structured secret; use ToMap, GetField or GetFields", s.name)}
	}
	return s.value, nil
}

// Type is a single-value secret's declared type; empty for a structured secret.
func (s *Secret) Type() string { return s.typ }

// Version is a single-value secret's current version; 0 for a structured secret.
func (s *Secret) Version() int { return s.version }

// ToMap is every field of a structured secret, by name.
func (s *Secret) ToMap() (map[string]string, error) {
	if err := s.needFields(); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(s.fields))
	for _, f := range s.fields {
		out[f.Name] = f.Value
	}
	return out, nil
}

// Fields is a structured secret's fields, with their types, in the order the Burrow keeps them.
func (s *Secret) Fields() ([]SecretField, error) {
	if err := s.needFields(); err != nil {
		return nil, err
	}
	return append([]SecretField(nil), s.fields...), nil
}

// GetField is one field's value.
func (s *Secret) GetField(name string) (string, error) {
	if err := s.needFields(); err != nil {
		return "", err
	}
	i, ok := s.byName[name]
	if !ok {
		return "", s.missing(name)
	}
	return s.fields[i].Value, nil
}

// GetFields is the named fields' values, in the order asked for:
//
//	creds, err := db.GetFields("username", "password")
//	user, pass := creds[0], creds[1]
func (s *Secret) GetFields(names ...string) ([]string, error) {
	if err := s.needFields(); err != nil {
		return nil, err
	}
	out := make([]string, len(names))
	for i, name := range names {
		j, ok := s.byName[name]
		if !ok {
			return nil, s.missing(name)
		}
		out[i] = s.fields[j].Value
	}
	return out, nil
}

func (s *Secret) needFields() error {
	if !s.structured {
		return &SecretShapeError{Reason: fmt.Sprintf("'%s' is a single-value secret; use Value", s.name)}
	}
	return nil
}

func (s *Secret) missing(field string) error {
	names := make([]string, len(s.fields))
	for i, f := range s.fields {
		names[i] = f.Name
	}
	return &FieldNotFoundError{Secret: s.name, Field: field, Available: names}
}

// String is "Secret(NAME)": the name only, never the value.
func (s Secret) String() string { return "Secret(" + s.name + ")" }

// GoString keeps %#v to the name, as String does.
func (s Secret) GoString() string { return s.String() }

// Format prints String for every verb, so no format prints a value.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// SecretCoordinate is a secret this machine can read, addressed by its project, environment and name.
type SecretCoordinate struct {
	Project     string
	Environment string
	Name        string
}

// String is the project/env/NAME form, as the Burrow lists it and GetSecret takes it.
func (c SecretCoordinate) String() string { return c.Project + "/" + c.Environment + "/" + c.Name }

// ParseSecretCoordinate splits a project/env/NAME coordinate into its parts. It splits at the first two slashes only: a
// secret's name may hold a slash, its project and environment may not.
func ParseSecretCoordinate(slug string) SecretCoordinate {
	parts := strings.SplitN(slug, "/", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return SecretCoordinate{Project: parts[0], Environment: parts[1], Name: parts[2]}
}

// ProjectAccess is a project this machine can read, and the environment categories it holds a grant for.
type ProjectAccess struct {
	Project    string
	Categories []string
}

// Certificate is a certificate a dynamic certificate secret issued to this machine, with the key it certifies. The key
// was made in memory for this certificate, and only its public half was sent to the Burrow.
//
// For an SSH user secret, hand PrivateKey and Certificate to your SSH client, or write them to id_ed25519 (mode 600)
// and id_ed25519-cert.pub for `ssh -i`. Printing a Certificate, or encoding it as JSON, leaves the private key out.
type Certificate struct {
	// Name is the secret's name.
	Name string
	// Type is the certificate type, such as "ssh-user".
	Type string
	// Certificate is the certificate in its type's own format: for SSH, the `ssh-ed25519-cert-v01@openssh.com …` line.
	Certificate string
	// PublicKey is the key the certificate is for, as an `ssh-ed25519 …` public key line.
	PublicKey string
	// Principals are the logins an SSH certificate signs in as; empty for other types.
	Principals []string
	// Host is where the secret says its machines connect, when it names a host; empty otherwise.
	Host string
	// Serial is the certificate's serial, as its certificate authority numbered it.
	Serial int64
	// KeyID is the identity written into the certificate, which the host logs for each login it accepts.
	KeyID string
	// ValidAfter is when the certificate starts being accepted.
	ValidAfter time.Time
	// ValidBefore is when the certificate stops being accepted.
	ValidBefore time.Time
	// Details is everything the certificate says, as its type recorded it: for SSH, also its source addresses, forced
	// command and extensions. Values are strings, float64 numbers, bools, nil, []any and map[string]any.
	Details map[string]any

	privateKey string
}

// PrivateKey is the private key the certificate is for, as an OpenSSH private key file.
func (c Certificate) PrivateKey() string { return c.privateKey }

// String is "Certificate(NAME, serial N, valid until TIME)", without the private key.
func (c Certificate) String() string {
	return fmt.Sprintf("Certificate(%s, serial %d, valid until %s)", c.Name, c.Serial, c.ValidBefore.UTC().Format(time.RFC3339))
}

// GoString keeps %#v to String, without the private key.
func (c Certificate) GoString() string { return c.String() }

// Format prints String for every verb, so no format prints the private key.
func (c Certificate) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// CertificateOption shapes the certificates GetCertificate and LiveCertificate ask for.
type CertificateOption func(*certificateSettings)

type certificateSettings struct {
	validity time.Duration
	set      bool
}

// WithValidity asks for certificates that last d, when that's less than the secret allows. The Burrow never issues one
// for longer than the secret's own lifetime, and refuses one shorter than a minute. d counts in whole seconds.
func WithValidity(d time.Duration) CertificateOption {
	return func(s *certificateSettings) {
		s.validity = d
		s.set = true
	}
}

// validitySeconds is the validity asked for, in whole seconds; 0 for as long as the secret allows.
func validitySeconds(opts []CertificateOption) (int64, error) {
	var s certificateSettings
	for _, opt := range opts {
		if opt != nil {
			opt(&s)
		}
	}
	if !s.set {
		return 0, nil
	}
	seconds := int64(s.validity / time.Second)
	if seconds < 1 {
		return 0, fmt.Errorf("burrow: validity must be at least one second, got %s", s.validity)
	}
	return seconds, nil
}
