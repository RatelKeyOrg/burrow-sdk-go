package burrow

// The cache: a copy of each secret a client reads, kept encrypted with the machine's key in its identity's folder, that
// answers a read the Burrow can't. It's off until it's turned on, by `ratel cache enable` for an identity or WithCache
// for a client.
//
// A copy is a file at <identity folder>/cache/<project>/<env>/<NAME> holding the secret as the Burrow returned it. An
// environment read also writes <project>/<env>/.environment, naming the secrets it held, so the Ratel CLI answers an
// environment from the cache only whole. The Ratel CLI and the other Burrow SDKs keep their copies in the same files,
// the same way, so each reads what the others saved:
//
//	key  = HKDF-SHA256(ikm = the identity's Ed25519 seed, salt = its machine id, info = "ratel-cache-v1"), 32 bytes
//	aad  = "ratel-cache-v1" 0x00 machine id 0x00 "project/env/NAME" 0x00 cachedAt (Unix milliseconds, in decimal)
//	file = {"v":1,"cachedAt":<ms>,"nonce":"<base64, 12 bytes>","ct":"<base64, AES-256-GCM ciphertext and tag>"}
//
// The .environment file is sealed the same way with an empty NAME ("project/env/"), over {"names":[...]}. A name Windows
// keeps for a device (CON, NUL, COM1...) is written with a "~" after it, which no real name contains.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	cacheFormatVersion = 1
	cacheDomain        = "ratel-cache-v1"
	cacheSwitchFile    = "cache.json"
	cacheFolderName    = "cache"
	cacheEnvironment   = ".environment"
)

// cacheSwitchOn reports whether `ratel cache enable` turned the cache on for the identity in identityDir.
func cacheSwitchOn(identityDir string) bool {
	data, err := os.ReadFile(filepath.Join(identityDir, cacheSwitchFile))
	if err != nil {
		return false
	}
	var s struct {
		Enabled bool `json:"enabled"`
	}
	return json.Unmarshal(data, &s) == nil && s.Enabled
}

// secretCache is one identity's copies, opened with its key.
type secretCache struct {
	root      string
	machineID string
	key       []byte
}

func newSecretCache(identityDir, machineID string, seed []byte) *secretCache {
	return &secretCache{root: filepath.Join(identityDir, cacheFolderName), machineID: machineID, key: cacheKey(seed, machineID)}
}

type cacheEntry struct {
	body     []byte
	cachedAt time.Time
}

// put saves body as the copy of project/env/NAME. A copy that can't be written never fails the read.
func (sc *secretCache) put(project, env, name string, body []byte) {
	path, err := sc.path(project, env, name)
	if err != nil {
		return
	}
	if data, err := sc.seal(project, env, name, body, time.Now().UnixMilli()); err == nil {
		_ = cacheWriteAtomic(path, data)
	}
}

// get is the copy of project/env/NAME, or nil when there's none that opens.
func (sc *secretCache) get(project, env, name string) *cacheEntry {
	path, err := sc.path(project, env, name)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	entry, err := sc.open(project, env, name, data)
	if err != nil {
		return nil
	}
	return entry
}

// putEnvironment saves every secret an environment read held, records which they were, and deletes the copies of any
// other secret of the environment.
func (sc *secretCache) putEnvironment(project, env string, bodies map[string][]byte) {
	dir, err := sc.folder(project, env)
	if err != nil {
		return
	}
	at := time.Now().UnixMilli()
	names := make([]string, 0, len(bodies))
	keep := map[string]bool{cacheEnvironment: true}
	for name, body := range bodies {
		path, err := sc.path(project, env, name)
		if err != nil {
			continue
		}
		names = append(names, name)
		keep[filepath.Base(path)] = true
		if data, err := sc.seal(project, env, name, body, at); err == nil {
			_ = cacheWriteAtomic(path, data)
		}
	}
	sort.Strings(names)
	list, _ := json.Marshal(struct {
		Names []string `json:"names"`
	}{names})
	if data, err := sc.seal(project, env, "", list, at); err == nil {
		_ = cacheWriteAtomic(filepath.Join(dir, cacheEnvironment), data)
	}
	if items, err := os.ReadDir(dir); err == nil {
		for _, item := range items {
			if !item.IsDir() && !keep[item.Name()] && !strings.HasPrefix(item.Name(), ".") {
				_ = os.Remove(filepath.Join(dir, item.Name()))
			}
		}
	}
}

// forget deletes copies: all of them with an empty project, an environment's with an empty name, or one secret's.
func (sc *secretCache) forget(project, env, name string) {
	parts := []string{sc.root}
	for _, s := range []string{project, env, name} {
		if s == "" {
			break
		}
		d, err := cacheDiskName(s)
		if err != nil {
			return
		}
		parts = append(parts, d)
	}
	_ = os.RemoveAll(filepath.Join(parts...))
}

// mayAnswer handles a read of project/env/NAME (or of the environment, with an empty name) that failed with err. A
// refusal from the Burrow deletes the copies it refuses and returns false: the machine refused (401) deletes every
// copy, no grant for the environment (403) the environment's, and gone (404) or refused by the secret's own settings
// (409) what was read. A failure to reach the Burrow, or of the Burrow to answer, returns true: a copy may answer.
func (sc *secretCache) mayAnswer(err error, project, env, name string) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var auth *AuthError
	var forbidden *ForbiddenError
	var notFound *NotFoundError
	var server *ServerError
	switch {
	case errors.As(err, &auth):
		sc.forget("", "", "")
		return false
	case errors.As(err, &forbidden):
		sc.forget(project, env, "")
		return false
	case errors.As(err, &notFound), errors.As(err, &server) && server.Status == http.StatusConflict:
		sc.forget(project, env, name)
		return false
	}
	var transport *TransportError
	var certificate *CertificateError
	return errors.As(err, &transport) || errors.As(err, &certificate) || errors.As(err, &server)
}

func (sc *secretCache) path(project, env, name string) (string, error) {
	dir, err := sc.folder(project, env)
	if err != nil {
		return "", err
	}
	d, err := cacheDiskName(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, d), nil
}

func (sc *secretCache) folder(project, env string) (string, error) {
	p, err := cacheDiskName(project)
	if err != nil {
		return "", err
	}
	e, err := cacheDiskName(env)
	if err != nil {
		return "", err
	}
	return filepath.Join(sc.root, p, e), nil
}

// A name the cache can hold: what project, environment and secret names are made of, no longer than a file name can be.
var cacheSafeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$`)

// The names Windows keeps for devices, which no file there can have, whatever its case.
var cacheDeviceName = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$`)

// cacheDiskName is how a project, environment or secret name is written as a folder or file name.
func cacheDiskName(s string) (string, error) {
	if !cacheSafeName.MatchString(s) {
		return "", fmt.Errorf("burrow: %q isn't a name the cache can hold", s)
	}
	if cacheDeviceName.MatchString(s) {
		return s + "~", nil
	}
	return s, nil
}

type cacheEnvelope struct {
	V        int    `json:"v"`
	CachedAt int64  `json:"cachedAt"`
	Nonce    string `json:"nonce"`
	CT       string `json:"ct"`
}

func (sc *secretCache) seal(project, env, name string, body []byte, cachedAt int64) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct, err := cacheSealWith(sc.key, nonce, body, cacheAAD(sc.machineID, project, env, name, cachedAt))
	if err != nil {
		return nil, err
	}
	return json.Marshal(cacheEnvelope{
		V:        cacheFormatVersion,
		CachedAt: cachedAt,
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
		CT:       base64.StdEncoding.EncodeToString(ct),
	})
}

func (sc *secretCache) open(project, env, name string, data []byte) (*cacheEntry, error) {
	var f cacheEnvelope
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.V != cacheFormatVersion {
		return nil, fmt.Errorf("a copy in format %d", f.V)
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(f.CT)
	if err != nil {
		return nil, err
	}
	gcm, err := cacheGCM(sc.key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("a copy with a nonce of the wrong size")
	}
	body, err := gcm.Open(nil, nonce, ct, cacheAAD(sc.machineID, project, env, name, f.CachedAt))
	if err != nil {
		return nil, errors.New("a copy that doesn't open with this identity's key")
	}
	return &cacheEntry{body: body, cachedAt: time.UnixMilli(f.CachedAt)}, nil
}

// cacheKey is HKDF-SHA256 (RFC 5869) of the seed, salted with the machine id, written out here so the SDK keeps no
// dependencies.
func cacheKey(seed []byte, machineID string) []byte {
	extract := hmac.New(sha256.New, []byte(machineID))
	extract.Write(seed)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte(cacheDomain))
	expand.Write([]byte{1})
	return expand.Sum(nil) // one block of SHA-256 is the 32 bytes wanted
}

func cacheAAD(machineID, project, env, name string, cachedAt int64) []byte {
	return []byte(cacheDomain + "\x00" + machineID + "\x00" + project + "/" + env + "/" + name + "\x00" + strconv.FormatInt(cachedAt, 10))
}

func cacheSealWith(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := cacheGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func cacheGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// cacheWriteAtomic writes data to path through a file beside it that's renamed into place, so a reader never sees half
// a copy. Folders it makes are 0700 and the file 0600.
func cacheWriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // gone once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
