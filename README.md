<p align="center">
  <a href="https://ratelkey.com"><img src="assets/ratelkey.png" alt="RatelKey" height="64"></a>
  &emsp;
  <img src="assets/burrow.png" alt="Burrow" height="64">
</p>

<h1 align="center">Burrow SDK for Go</h1>

<p align="center">
  <a href="https://pkg.go.dev/github.com/RatelKeyOrg/burrow-sdk-go"><img src="https://pkg.go.dev/badge/github.com/RatelKeyOrg/burrow-sdk-go.svg" alt="Go Reference"></a>
</p>

Read secrets from a self-hosted [RatelKey](https://ratelkey.com) Burrow with a machine identity.

- Single and structured secrets, and individual fields of a structured secret.
- The machine's own access map (`ListProjects`, `ListSecrets`).
- Certificate pinning, or standard CA trust (`WithTLS`).
- Live secrets that follow every change on the Burrow (`Live`, `LiveEnvironment`).
- An encrypted copy of each read that answers when the Burrow can't be reached (`WithCache`).
- Certificates from a dynamic certificate secret, such as SSH logins, for a key made in memory (`GetCertificate`, `LiveCertificate`).
- An identity enrolled in memory from a machine token's code (`Enroll`).
- An OIDC token instead of a key (`OIDC`).

## Requirements

- Go 1.22 or later.
- No dependencies outside the standard library.

```sh
go get github.com/RatelKeyOrg/burrow-sdk-go
```

## Bootstrap a machine

From the Burrow dashboard, **Machines → Add machine**, and run the install it gives you on the target host.
The identity lands at `~/.burrow/burrows/<slug>/identity.json`.

## Quick start

```go
import "github.com/RatelKeyOrg/burrow-sdk-go"

// The single machine identity on this host (under ~/.burrow, or $BURROW_HOME).
client, err := burrow.Open()
if err != nil {
	log.Fatal(err)
}
defer client.Close()

// A single-value secret:
key, err := client.GetSecret(ctx, "payments/prod/API_KEY")
apiKey, err := key.Value()

// A structured secret, read once and projected locally:
db, err := client.GetSecret(ctx, "payments/prod/DATABASE")
all, err := db.ToMap()                                // every field by name
host, err := db.GetField("host")                      // one field
creds, err := db.GetFields("username", "password")    // in order

// What this machine can read:
projects, err := client.ListProjects(ctx)
```

Point it at a specific identity by selector or path:

```go
burrow.Open(burrow.WithIdentity("burrow-a1b2c3d4e5f60718"))                          // slug, name, machine id or URL
burrow.Open(burrow.WithIdentity("/home/you/.burrow/burrows/burrow-a1b2c3d4e5f60718")) // a burrow dir or identity.json
```

## Without `~/.burrow`

For an app that manages its own key material:

```go
client, err := burrow.Connect(burrow.ConnectConfig{
	BurrowURL:     "https://burrow.internal:12010",
	MachineID:     "…",
	PrivateKeyPEM: os.Getenv("BURROW_MACHINE_KEY"), // PKCS#8 PEM
})
```

## Live secrets

A live handle holds a secret's current value and follows every change on the Burrow as it happens.

```go
db, err := client.Live(ctx, "payments/prod/DATABASE")

password, err := db.GetField("password") // always the current value
db.OnChange(func(next, prev *burrow.Secret) { pool.Reconnect(next) })
```

`client.LiveEnvironment(ctx, "payments/prod")` does the same for a whole environment: `env.Get("API_KEY")`, and
`OnChange` lists what changed, was added or was removed.

- `Live` returns after the first read. A missing secret or grant is refused there.
- All live handles on a client share one connection. It reconnects on its own and reads again anything that changed
  while it was down.
- `Status()` is `StatusLive`, `StatusReconnecting`, `StatusRevoked` (access was taken away) or `StatusRemoved` (deleted
  on the Burrow). The last two are final, and the handle keeps its last value.
- Listeners run one at a time, in order, on a goroutine of the handle's own. A listener that panics is reported to
  `OnError`.
- `client.Close()` closes every handle.
- Needs a Burrow with live updates; an older one is refused at `Live`.

## Fallback cache

The fallback cache keeps a copy of each secret the client reads, and answers with it when your Burrow can't be reached.
It's off until you turn it on:

```go
client, err := burrow.Open(burrow.WithCache(true))
```

Without `WithCache`, a client from `Open` uses the cache when `ratel cache enable` turned it on for the machine, and
`WithCache(false)` keeps it off. With `Connect`, it needs `ConnectConfig.PinStoreDir` to keep the copies in. `Enroll`
and `OIDC` can't use it.

A read uses the cache only when it fails because your Burrow can't be reached or can't answer. A secret answered from
the cache says when its copy was saved:

```go
key, err := client.GetSecret(ctx, "payments/prod/API_KEY")
if !key.CachedAt().IsZero() {
	log.Printf("using the copy saved at %s", key.CachedAt())
}
```

A live secret or environment doesn't answer from the cache. While your Burrow can't be reached it keeps the value it
last read, and each read it makes keeps the copies up to date. When your Burrow refuses a read, because the machine was
removed or disabled, lost access, or the secret is gone, the read fails as usual and the refused copies are deleted. A
dynamic secret's login comes back as it was saved, so it may have expired.

## Certificates

A dynamic certificate secret, such as an SSH user secret, gives each machine that asks a short-lived certificate of
its own. The SDK makes a new Ed25519 key in memory for each one and sends only its public half.

```go
login, err := client.GetCertificate(ctx, "api/prod/DEPLOY_SSH")

login.PrivateKey()   // the OpenSSH private key
login.Certificate    // its certificate (ssh-ed25519-cert-v01@openssh.com …)
login.Principals     // the logins it signs in as
login.Host           // where the secret says to connect, or ""
login.ValidBefore    // when it stops being accepted
```

Hand the key and certificate to your SSH library, or write them to `id_ed25519` (mode 600) and
`id_ed25519-cert.pub` for `ssh -i`. `burrow.WithValidity(5*time.Minute)` asks for one that lasts less than the secret
allows. Printing a `Certificate` leaves the private key out.

`LiveCertificate` keeps one current:

```go
login, err := client.LiveCertificate(ctx, "api/prod/DEPLOY_SSH")

login.Current()                                                                // the certificate and key to use now
login.OnChange(func(next, prev *burrow.Certificate) { connections.UseKey(next) })
renewed, err := login.Renew(ctx)                                               // a new one at once, e.g. after a host refused it
```

- It renews once two thirds of the certificate's time have passed, and as soon as the secret's settings change.
  Each renewal makes a new key.
- Revoking one certificate from the dashboard sends no event; `Renew` gets a new one.
- `GetSecret` on a certificate secret returns a `*burrow.ServerError` (409) naming `GetCertificate`.

## In-memory identity

Enroll with a machine token's code from **Machine tokens** on the Burrow. The key is generated and kept in
memory; nothing is written to disk.

```go
client, err := burrow.Enroll(os.Getenv("BURROW_ENROLL_CODE"))

key, err := client.GetSecret(ctx, "payments/prod/API_KEY")

client.Close() // on shutdown: the machine shows as expired on the Burrow at once
```

- The machine enrolls on the first read. The code sets how the Burrow's certificate is trusted.
- Before the machine expires, the client enrolls a fresh one with the same code and ends the old one.
- `burrow.Open()` enrolls from `BURROW_ENROLL_CODE` when the host has no identity under `~/.burrow`.
- A one-time invitation code is refused; use a machine token.

## OIDC

```go
client, err := burrow.OIDC(burrow.OIDCConfig{
	BurrowURL:   "https://burrow.example.com",
	Fingerprint: os.Getenv("BURROW_FINGERPRINT"), // leave empty for a publicly-trusted certificate
})

key, err := client.GetSecret(ctx, "payments/prod/API_KEY")
```

`Audience` defaults to `BurrowURL`. GitHub Actions requires `permissions: id-token: write`. GitLab CI/CD (gitlab.com) requires the job to declare its token as `RATEL_ID_TOKEN`:

```yaml
id_tokens:
  RATEL_ID_TOKEN:
    aud: https://burrow.example.com
```

Bitbucket Pipelines requires the step to list the Burrow as an OIDC audience:

```yaml
- step:
    oidc:
      audiences:
        - https://burrow.example.com
```

## Certificate trust

```go
client, err := burrow.Open(burrow.WithTLS(burrow.TLSSystemTrust()))
```

Without `WithTLS`, the SDK uses the trust chosen when the machine was added: encrypted by default (works everywhere), or verified against the Burrow's own key or a CA if that was selected.

- `burrow.TLSPinned()`: trust on first use, stored at `~/.burrow/burrows/<slug>/known_cert`.
- `burrow.TLSPinnedTo("aa:bb:…")`: a fixed fingerprint, from the Burrow's network settings.
- `burrow.TLSSystemTrust()`: CA and hostname verification, for a Burrow on a custom domain or Let's Encrypt.
- `burrow.TLSInsecure()`: no verification; accepts any certificate. Opt in only, for a network you already trust. Shortcut: `client.InsecureTLS(true)`.

## Webhooks

Verify a delivery from a Burrow's Signed webhook. Needs only the webhook's signing secret, not a machine identity.

```go
http.HandleFunc("/hooks/burrow", func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	event, err := burrow.VerifyWebhook(body, r.Header, os.Getenv("BURROW_WEBHOOK_SECRET"))
	if err != nil {
		http.Error(w, "unverified", http.StatusUnauthorized)
		return
	}
	log.Println(event.Event, event.Data.Summary)
	w.WriteHeader(http.StatusNoContent)
})
```

Pass the raw body, before JSON parsing. A retry of the same event carries the same `event.ID`, so keep the ids you've handled to ignore repeats.

## Errors

Every failure is one of the SDK's error types, matched with `errors.As`: `*burrow.AuthError` (401),
`*burrow.ForbiddenError` (403, no grant), `*burrow.NotFoundError` (404), `*burrow.ServerError` (5xx, or 409 when a
secret refuses the request), `*burrow.CertificateError` (pin mismatch), `*burrow.TransportError` (unreachable or
unparsable), `*burrow.IdentityError` (no, ambiguous or invalid identity), plus two projection errors on a secret:
`*burrow.SecretShapeError` (such as `Value` on a structured secret) and `*burrow.FieldNotFoundError`. The message
carries the Burrow's own reason. `VerifyWebhook` returns a `*burrow.WebhookError` for a missing or wrong signature.

```go
var notFound *burrow.NotFoundError
if errors.As(err, &notFound) {
	// the secret doesn't exist
}
```

## License

MIT. See [LICENSE](LICENSE).
