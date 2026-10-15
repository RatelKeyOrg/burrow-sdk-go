package burrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

const sshKeyType = "ssh-ed25519"

// sshKeyPair is an Ed25519 key pair in OpenSSH's formats: the `ssh-ed25519 …` public key line and the private key file.
type sshKeyPair struct {
	publicKey  string
	privateKey string
}

// newSSHKeyPair makes a fresh Ed25519 key pair in memory. comment is written into the private key, as `ssh-keygen -C`
// does.
func newSSHKeyPair(comment string) (sshKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return sshKeyPair{}, &TransportError{Reason: "making a key: " + err.Error(), Err: err}
	}
	seed := priv.Seed()
	defer clear(priv)
	defer clear(seed)
	private, err := openSSHPrivateKey(seed, pub, comment)
	if err != nil {
		return sshKeyPair{}, err
	}
	return sshKeyPair{publicKey: openSSHPublicKey(pub), privateKey: private}, nil
}

// openSSHPublicKey is the `ssh-ed25519 <base64>` line for a raw 32-byte Ed25519 public key.
func openSSHPublicKey(pub []byte) string {
	return sshKeyType + " " + base64.StdEncoding.EncodeToString(publicBlob(pub))
}

// openSSHPrivateKey is the unencrypted openssh-key-v1 file for an Ed25519 key, as ssh-keygen writes it: the public key,
// then a private section of two matching check numbers, the key, its comment and padding to a multiple of 8 bytes.
func openSSHPrivateKey(seed, pub []byte, comment string) (string, error) {
	check := make([]byte, 4)
	if _, err := rand.Read(check); err != nil {
		return "", &TransportError{Reason: "reading random bytes for a key: " + err.Error(), Err: err}
	}
	secret := append(append([]byte(nil), seed...), pub...)
	defer clear(secret)

	section := append([]byte(nil), check...)
	section = append(section, check...)
	section = appendSSHString(section, []byte(sshKeyType))
	section = appendSSHString(section, pub)
	section = appendSSHString(section, secret)
	section = appendSSHString(section, []byte(comment))
	for i := byte(1); len(section)%8 != 0; i++ {
		section = append(section, i)
	}
	defer clear(section)

	file := []byte("openssh-key-v1\x00")
	file = appendSSHString(file, []byte("none"))
	file = appendSSHString(file, []byte("none"))
	file = appendSSHString(file, nil)
	file = binary.BigEndian.AppendUint32(file, 1)
	file = appendSSHString(file, publicBlob(pub))
	file = appendSSHString(file, section)
	defer clear(file)

	encoded := base64.StdEncoding.EncodeToString(file)
	var out strings.Builder
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(encoded) > 70 {
		out.WriteString(encoded[:70])
		out.WriteByte('\n')
		encoded = encoded[70:]
	}
	out.WriteString(encoded)
	out.WriteString("\n-----END OPENSSH PRIVATE KEY-----\n")
	return out.String(), nil
}

func publicBlob(pub []byte) []byte {
	return appendSSHString(appendSSHString(nil, []byte(sshKeyType)), pub)
}

// appendSSHString appends SSH's string encoding of value: a 4-byte big-endian length, then the bytes.
func appendSSHString(b, value []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(value)))
	return append(b, value...)
}
