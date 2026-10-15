package burrow

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MachineIdentity is a machine's identity in one Burrow: the record that adding the machine writes to
// ~/.burrow/burrows/<slug>/identity.json, and the Ed25519 private key it refers to. One identity per Burrow; a client
// acts as exactly one of them.
//
// The private key never leaves the machine: it stays in its PEM file and only signs requests.
type MachineIdentity struct {
	BurrowURL      string `json:"burrowUrl"`
	MachineID      string `json:"machineId"`
	PrivateKeyPath string `json:"privateKeyPath"`
	Slug           string `json:"slug"`
	BurrowName     string `json:"burrowName"`
	Name           string `json:"name"`
	// TLSMode is how the machine was set to trust the Burrow when it was added: "encrypted", "pinned" (the Burrow's own
	// key) or "system" (a CA-issued certificate, on a custom domain or behind a proxy). Empty on an identity written
	// before it existed, which is treated as pinned. It sets the client's trust when WithTLS isn't given.
	TLSMode string `json:"tlsMode"`
}

// Label is the Burrow's name, falling back to its slug, then its URL's host.
func (i MachineIdentity) Label() string {
	for _, s := range []string{i.BurrowName, i.Slug, hostOf(i.BurrowURL)} {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return "(unnamed burrow)"
}

// Dir is the directory the identity lives in, <home>/burrows/<slug>/, where the Burrow's pinned key is kept beside it.
// The identity file doesn't record it: the private key is written into it as identity.pem, so it is the key's
// directory.
func (i MachineIdentity) Dir() string { return filepath.Dir(i.PrivateKeyPath) }

// PrivateKey loads the Ed25519 private key (PKCS#8 PEM) the identity refers to.
func (i MachineIdentity) PrivateKey() (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(i.PrivateKeyPath)
	if err != nil {
		return nil, &IdentityError{Reason: fmt.Sprintf("reading private key %s: %v", i.PrivateKeyPath, err), Err: err}
	}
	return parsePrivateKey(data, i.PrivateKeyPath)
}

func (i MachineIdentity) matches(selector string) bool {
	s := strings.TrimSpace(selector)
	for _, v := range []string{i.BurrowName, i.Slug, i.MachineID, i.BurrowURL, i.Label()} {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// IdentityHome is where machine identities are kept: $BURROW_HOME when it's set, otherwise ~/.burrow.
func IdentityHome() string {
	if env := os.Getenv("BURROW_HOME"); strings.TrimSpace(env) != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".burrow"
	}
	return filepath.Join(home, ".burrow")
}

// DiscoverIdentities returns every identity under <IdentityHome>/burrows/<slug>/identity.json, sorted by label, then
// machine id. A directory without a readable, well-formed identity.json is skipped.
func DiscoverIdentities() []MachineIdentity {
	burrows := filepath.Join(IdentityHome(), "burrows")
	entries, err := os.ReadDir(burrows)
	if err != nil {
		return nil
	}
	var found []MachineIdentity
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// A half-written or foreign file is not this host's identity; it is skipped rather than failing discovery.
		if id, err := readIdentityFile(filepath.Join(burrows, entry.Name(), "identity.json")); err == nil {
			found = append(found, id)
		}
	}
	// Ordinal, not locale-aware: every host that reads the same identities has to put them in the same order.
	sort.SliceStable(found, func(a, b int) bool {
		la, lb := strings.ToLower(found[a].Label()), strings.ToLower(found[b].Label())
		if la != lb {
			return la < lb
		}
		return found[a].MachineID < found[b].MachineID
	})
	return found
}

// ResolveIdentity returns the identity a client should act as. With one identity on this host, an empty selector
// resolves to it; with several, the selector (a Burrow's name, slug, machine id or URL) picks one.
func ResolveIdentity(selector string) (MachineIdentity, error) {
	ids := DiscoverIdentities()
	if len(ids) == 0 {
		return MachineIdentity{}, &IdentityError{Reason: "no Burrow identities under " + filepath.Join(IdentityHome(), "burrows") +
			". Bootstrap this machine into a Burrow first (its Machines page, Add machine)."}
	}
	if strings.TrimSpace(selector) == "" {
		if len(ids) == 1 {
			return ids[0], nil
		}
		return MachineIdentity{}, &IdentityError{Reason: fmt.Sprintf("this machine holds %d Burrow identities; select one by name, slug, or machine id. Known: %s",
			len(ids), labels(ids))}
	}
	var matched []MachineIdentity
	for _, id := range ids {
		if id.matches(selector) {
			matched = append(matched, id)
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return MachineIdentity{}, &IdentityError{Reason: fmt.Sprintf("no Burrow identity matches %q. Known: %s", selector, labels(ids))}
	default:
		return MachineIdentity{}, &IdentityError{Reason: fmt.Sprintf("%q matches more than one identity; select by machine id.", selector)}
	}
}

// selectIdentity resolves target for Open: empty is the one identity on this host, a filesystem path (an identity
// directory or an identity.json) is loaded directly, and anything else is a selector. A URL (it contains "://") is
// always a selector.
func selectIdentity(target string) (MachineIdentity, error) {
	if strings.TrimSpace(target) == "" {
		return ResolveIdentity("")
	}
	if !strings.Contains(target, "://") && looksLikePath(target) {
		return loadIdentityPath(expandUser(target))
	}
	return ResolveIdentity(target)
}

func labels(ids []MachineIdentity) string {
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = id.Label()
	}
	return strings.Join(names, ", ")
}

// readIdentityFile reads one identity record. The three fields adding a machine always writes are required; the rest
// are for display, and a file written by hand may leave them out.
func readIdentityFile(path string) (MachineIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MachineIdentity{}, err
	}
	var id MachineIdentity
	if err := json.Unmarshal(data, &id); err != nil {
		return MachineIdentity{}, err
	}
	for _, field := range []struct{ name, value string }{
		{"burrowUrl", id.BurrowURL}, {"machineId", id.MachineID}, {"privateKeyPath", id.PrivateKeyPath},
	} {
		if field.value == "" {
			return MachineIdentity{}, fmt.Errorf("identity is missing '%s'", field.name)
		}
	}
	return id, nil
}

func loadIdentityPath(path string) (MachineIdentity, error) {
	file := path
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		file = filepath.Join(path, "identity.json")
	}
	if _, err := os.Stat(file); err != nil {
		return MachineIdentity{}, &IdentityError{Reason: "no identity file at " + file, Err: err}
	}
	id, err := readIdentityFile(file)
	if err != nil {
		return MachineIdentity{}, &IdentityError{Reason: fmt.Sprintf("failed to parse identity file %s: %v", file, err), Err: err}
	}
	return id, nil
}

// parsePrivateKey reads an Ed25519 private key from a PKCS#8 PEM, as `openssl genpkey -algorithm ed25519` writes it.
// source names where it came from, for the error.
func parsePrivateKey(data []byte, source string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &IdentityError{Reason: "no PEM private-key block in " + source}
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &IdentityError{Reason: fmt.Sprintf("parsing Ed25519 private key in %s: %v", source, err), Err: err}
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, &IdentityError{Reason: fmt.Sprintf("parsing Ed25519 private key in %s: key is %T, not Ed25519", source, key)}
	}
	return ed, nil
}

// hostOf is a URL's host[:port], for a label when nothing better names the Burrow.
func hostOf(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func looksLikePath(s string) bool {
	sep := string(filepath.Separator)
	for _, prefix := range []string{"/", "~", "./", "../", "." + sep, ".." + sep} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	if strings.HasSuffix(s, ".json") || filepath.IsAbs(s) {
		return true
	}
	_, err := os.Stat(s)
	return err == nil
}

func expandUser(s string) string {
	if !strings.HasPrefix(s, "~") {
		return s
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return s
	}
	rest := strings.TrimLeft(s[1:], `/\`)
	return filepath.Join(home, rest)
}
