package burrow

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// A CI job reads secrets with a short-lived token its provider signs, instead of a key: GitHub Actions, GitLab CI/CD
// and Bitbucket Pipelines are the providers. The token's audience must be the one the Burrow's trust policy requires;
// the Burrow checks the token's signature against the provider's keys and matches its claims (repository or project,
// workflow or CI file, environment) to that policy. Nothing here is a secret at rest: a token lives for minutes.

const (
	// gitlabTokenVariable is where a GitLab job's ID token is read from: the job declares it under id_tokens.
	gitlabTokenVariable = "RATEL_ID_TOKEN"
	// bitbucketTokenVariable is where Bitbucket Pipelines puts a step's token when the step has oidc set.
	bitbucketTokenVariable = "BITBUCKET_STEP_OIDC_TOKEN"
)

// oidcTransport is what a token request goes out on: Go's default transport as it stands, so an application's own
// settings for it (a proxy, say) still apply, with refuseCompromised after its certificate checks.
func oidcTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	before := t.TLSClientConfig.VerifyConnection
	t.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if before != nil {
			if err := before(cs); err != nil {
				return err
			}
		}
		return refuseCompromised(cs)
	}
	return t
}

func isGitHub() bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

func isGitLab() bool { return os.Getenv("GITLAB_CI") == "true" }

// isBitbucket is set in every Bitbucket pipeline, so a step without oidc is still recognized and told what it lacks.
func isBitbucket() bool {
	return os.Getenv("BITBUCKET_BUILD_NUMBER") != "" || os.Getenv(bitbucketTokenVariable) != ""
}

// oidcProviderDetected reports whether this process can get an OIDC token now.
func oidcProviderDetected() bool { return isGitHub() || isGitLab() || isBitbucket() }

// mintOIDCToken gets a token for audience from the CI provider this process runs under.
func mintOIDCToken(ctx context.Context, audience string) (string, error) {
	switch {
	case isGitHub():
		return mintGitHub(ctx, audience)
	case isGitLab():
		return envToken(gitlabTokenVariable, audience,
			fmt.Sprintf("The GitLab job needs 'id_tokens: %s:' with 'aud: %s'", gitlabTokenVariable, audience))
	case isBitbucket():
		return envToken(bitbucketTokenVariable, audience,
			fmt.Sprintf("The Bitbucket step needs 'oidc:' with 'audiences: [%s]'", audience))
	}
	return "", &AuthError{Reason: "no OIDC provider detected. In GitHub Actions the workflow needs 'permissions: id-token: write'; in GitLab " +
		"CI/CD the job needs 'id_tokens: " + gitlabTokenVariable + ":' with 'aud' set to the Burrow; in Bitbucket " +
		"Pipelines the step needs 'oidc:' with the Burrow among its 'audiences'"}
}

// mintGitHub requests a token for audience from the GitHub Actions token service, which is publicly trusted: its
// certificate is checked as TLSSystemTrust checks a Burrow's.
func mintGitHub(ctx context.Context, audience string) (string, error) {
	u, err := url.Parse(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	if err != nil {
		return "", &AuthError{Reason: "requesting an OIDC token from the provider: " + err.Error(), Err: err}
	}
	if audience != "" {
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", &AuthError{Reason: "requesting an OIDC token from the provider: " + err.Error(), Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	req.Header.Set("Accept", "application/json")
	transport := oidcTransport()
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: requestTimeout}).Do(req)
	if err != nil {
		cause := err
		if urlErr, ok := err.(*url.Error); ok {
			cause = urlErr.Err
		}
		return "", &AuthError{Reason: "requesting an OIDC token from the provider: " + cause.Error(), Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", &AuthError{Reason: fmt.Sprintf("the OIDC token request failed (HTTP %d)", resp.StatusCode)}
	}
	body, _ := readLimited(resp.Body, 1<<20)
	var out struct {
		Value any `json:"value"`
	}
	_ = json.Unmarshal(body, &out)
	token, _ := out.Value.(string)
	if token == "" {
		return "", &AuthError{Reason: "the OIDC provider returned no token"}
	}
	return token, nil
}

// envToken is the token the CI provider put in the variable name (GitLab, Bitbucket). The provider sets its audience
// from the pipeline's config, so a token for another audience is refused here, where the fix can be named, rather than
// by the Burrow. fix says what the pipeline needs when there's no token at all.
func envToken(name, audience, fix string) (string, error) {
	token := strings.TrimSpace(os.Getenv(name))
	if token == "" {
		return "", &AuthError{Reason: "no ID token in " + name + ". " + fix}
	}
	if audience != "" {
		if auds, ok := tokenAudiences(token); ok && !hasAudience(auds, audience) {
			return "", &AuthError{Reason: fmt.Sprintf("the ID token in %s is for %s; set its audience to %s", name, strings.Join(auds, ", "), audience)}
		}
	}
	return token, nil
}

// tokenAudiences is a JWT's aud claim (a string or a list), read without verifying the token.
func tokenAudiences(token string) ([]string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil || len(claims.Aud) == 0 {
		return nil, false
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(claims.Aud, &many) == nil {
		return many, true
	}
	return nil, false
}

// hasAudience reports whether auds holds audience; an address with or without its trailing slash is the same address.
func hasAudience(auds []string, audience string) bool {
	for _, a := range auds {
		if strings.TrimRight(a, "/") == strings.TrimRight(audience, "/") {
			return true
		}
	}
	return false
}
