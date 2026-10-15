package burrow

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// TLSMode is how a client trusts the Burrow's TLS certificate: TLSPinned, TLSPinnedTo, TLSSystemTrust or TLSInsecure.
// The zero value chooses nothing, and the client's default applies.
type TLSMode struct {
	kind        tlsKind
	fingerprint string
}

type tlsKind int

const (
	tlsDefault tlsKind = iota
	tlsPinned
	tlsPinnedTo
	tlsSystemTrust
	tlsInsecure
)

// TLSPinned trusts the Burrow's key on first use. A Burrow serves HTTPS with a certificate of its own, so there is no
// public CA to check it against: its public key is pinned on first contact, and a changed key is refused after that,
// as SSH does with host keys. The key rather than the certificate, so a Burrow that adds a domain or renews its
// certificate stays the same Burrow. The pin is kept beside the Burrow's identity, in
// ~/.burrow/burrows/<slug>/known_cert, which the ratel CLI shares.
func TLSPinned() TLSMode { return TLSMode{kind: tlsPinned} }

// TLSPinnedTo trusts only the Burrow whose public key has this fingerprint: the SHA-256 of its key as the Burrow's
// Network settings show it, as colon-separated hex (colons and case are ignored). It must match from the very first
// request.
func TLSPinnedTo(fingerprint string) TLSMode {
	return TLSMode{kind: tlsPinnedTo, fingerprint: fingerprint}
}

// TLSSystemTrust verifies the Burrow's certificate against the system's CA store and its hostname, for a Burrow that
// serves a certificate from a CA: on a custom domain, behind a proxy, or with Let's Encrypt.
func TLSSystemTrust() TLSMode { return TLSMode{kind: tlsSystemTrust} }

// TLSInsecure accepts any certificate the Burrow presents, with no CA, hostname or pin check. The connection is
// encrypted, and nothing checks which server is at the other end. Opt in only, for a network you already trust.
func TLSInsecure() TLSMode { return TLSMode{kind: tlsInsecure} }

// String names the mode: "pinned", "pinned to <fingerprint>", "system trust" or "insecure".
func (m TLSMode) String() string {
	switch m.kind {
	case tlsPinned:
		return "pinned"
	case tlsPinnedTo:
		return "pinned to " + m.fingerprint
	case tlsSystemTrust:
		return "system trust"
	case tlsInsecure:
		return "insecure"
	default:
		return "default"
	}
}

// keyPin is the SHA-256 of a certificate's public key (its SubjectPublicKeyInfo) as lowercase colon-separated hex: the
// form the Burrow shows in its Network settings and carries in an enrollment code.
//
// The key rather than the whole certificate. A Burrow's certificate changes for good reasons (a custom domain added to
// it, a renewal) while the Burrow stays the same one, and a pin on the certificate would refuse it each time.
func keyPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":")
}

// fingerprintsEqual compares two fingerprints ignoring case and separators, so "AA:BB…" and "aabb…" match. An empty
// fingerprint matches nothing.
func fingerprintsEqual(a, b string) bool {
	na := normalizeFingerprint(a)
	return na != "" && na == normalizeFingerprint(b)
}

func normalizeFingerprint(s string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// pinStore is one Burrow's pinned key, in <identity dir>/known_cert, which the ratel CLI shares.
//
// One file per Burrow: the pin and the identity are the same trust relationship, so removing a Burrow's identity
// forgets its pin too. It holds one value rather than one per URL, because the pin is the Burrow's key, and the same
// Burrow reached by its LAN address, its public address or its relay hostname presents the same one.
//
// A missing or unreadable file reads as no pin. Writes replace the file in one rename, so processes sharing it never
// see half of one. An empty dir keeps the pin in memory only.
type pinStore struct {
	dir string
}

func (s pinStore) path() string { return filepath.Join(s.dir, "known_cert") }

func (s pinStore) read() string {
	if s.dir == "" {
		return ""
	}
	data, err := os.ReadFile(s.path())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// write records pin. It's best effort: with a home that can't be written, the next process pins again, and a read is
// never failed over it.
func (s pinStore) write(pin string) {
	if s.dir == "" || s.read() == pin {
		return
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return
	}
	f, err := os.CreateTemp(s.dir, ".known_cert-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, werr := f.WriteString(pin + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return
	}
	_ = os.Chmod(tmp, 0o600)
	_ = os.Rename(tmp, s.path())
}
