package burrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// canonical is the message a machine request's signature covers. It must match the Burrow's
// MachineSignature.canonical byte for byte, or every request is refused with 401:
//
//	ACTION \n resource[0] \n … \n resource[n] \n TIMESTAMP \n NONCE \n CLIENT
//
// with no trailing newline. TIMESTAMP is unix milliseconds in decimal, the same string the header carries.
func canonical(action string, resource []string, timestamp, nonce, client string) []byte {
	var b strings.Builder
	b.WriteString(action)
	b.WriteByte('\n')
	for _, part := range resource {
		b.WriteString(part)
		b.WriteByte('\n')
	}
	b.WriteString(timestamp)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(client)
	return []byte(b.String())
}

// signRequest returns the signed Ratel-* headers for one request, with a fresh timestamp and nonce. A captured request
// can't be sent again: the Burrow allows a tight timestamp window and takes each nonce once.
func signRequest(machineID string, key ed25519.PrivateKey, action string, resource []string, client string, now time.Time) (map[string]string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &TransportError{Reason: "reading random bytes for a request nonce: " + err.Error(), Err: err}
	}
	// Standard base64 with padding, which the Burrow decodes; 16 bytes is 24 characters, inside its 64-character bound.
	return signWith(machineID, key, action, resource, client, strconv.FormatInt(now.UnixMilli(), 10), base64.StdEncoding.EncodeToString(nonce)), nil
}

// signWith signs with a given timestamp and nonce.
func signWith(machineID string, key ed25519.PrivateKey, action string, resource []string, client, timestamp, nonce string) map[string]string {
	signature := ed25519.Sign(key, canonical(action, resource, timestamp, nonce, client))
	return map[string]string{
		"Ratel-Machine":   machineID,
		"Ratel-Timestamp": timestamp,
		"Ratel-Nonce":     nonce,
		"Ratel-Signature": base64.StdEncoding.EncodeToString(signature),
		"Ratel-Client":    client,
	}
}
