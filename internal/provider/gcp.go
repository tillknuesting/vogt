package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vogt/internal/secmem"
)

// GCP mints short-lived access tokens for a target service account with
// the IAM Credentials API. The master secret is a service-account key file
// for a broker account that may impersonate the target (roles/
// iam.serviceAccountTokenCreator). Google cannot revoke these tokens, so
// the lifetime is kept to the grant's TTL.
type GCP struct {
	Client        *http.Client
	CredsEndpoint string // default https://iamcredentials.googleapis.com
	Now           func() time.Time
}

type gcpScope struct {
	ServiceAccount string   `json:"service_account"`
	Scopes         []string `json:"scopes"`
}

type gcpKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

func (g *GCP) Name() string { return "gcp" }

func (g *GCP) Guarantees() Guarantees {
	return Guarantees{MaxDirectTTL: time.Hour, Revoke: RevokeNone}
}

func (g *GCP) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return http.DefaultClient
}

func (g *GCP) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *GCP) scope(req Request) (gcpScope, error) {
	var s gcpScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return s, err
	}
	if !strings.HasSuffix(s.ServiceAccount, ".iam.gserviceaccount.com") || len(s.Scopes) == 0 {
		return s, errors.New("gcp scope needs a service_account and scopes")
	}
	return s, nil
}

func (g *GCP) Permissions(req Request) ([]string, error) {
	s, err := g.scope(req)
	if err != nil {
		return nil, err
	}
	out := []string{"gcp:impersonate=" + s.ServiceAccount}
	for _, sc := range s.Scopes {
		out = append(out, "gcp:"+strings.TrimPrefix(sc, "https://www.googleapis.com/auth/"))
	}
	return Sorted(out), nil
}

func (g *GCP) Mint(ctx context.Context, req Request, master []byte) (Credential, error) {
	s, err := g.scope(req)
	if err != nil {
		return nil, err
	}
	var k gcpKey
	if err := json.Unmarshal(master, &k); err != nil || k.ClientEmail == "" || k.PrivateKey == "" {
		return nil, errors.New("gcp master secret must be a service-account key file")
	}
	if k.TokenURI == "" {
		k.TokenURI = "https://oauth2.googleapis.com/token"
	}
	key, err := ParseRSAKey([]byte(k.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("gcp key: %w", err)
	}
	now := g.now()
	assertion, err := SignJWTRS256(key, map[string]any{
		"iss": k.ClientEmail, "scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud": k.TokenURI, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, k.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client().Do(hr)
	if err != nil {
		return nil, err
	}
	var broker struct {
		AccessToken string `json:"access_token"`
	}
	if err := ReadJSON(resp, &broker); err != nil {
		return nil, fmt.Errorf("gcp: broker token: %w", err)
	}

	secs := int(req.TTL.Seconds())
	if secs > 3600 {
		secs = 3600
	}
	body, _ := json.Marshal(map[string]any{"scope": s.Scopes, "lifetime": fmt.Sprintf("%ds", secs)})
	base := g.CredsEndpoint
	if base == "" {
		base = "https://iamcredentials.googleapis.com"
	}
	u := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken", base, url.PathEscape(s.ServiceAccount))
	hr, err = http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+broker.AccessToken)
	resp, err = g.client().Do(hr)
	if err != nil {
		return nil, err
	}
	var out struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	if err := ReadJSON(resp, &out); err != nil {
		return nil, fmt.Errorf("gcp: generate access token: %w", err)
	}
	tok, err := secmem.FromBytes([]byte(out.AccessToken))
	if err != nil {
		return nil, err
	}
	return &bearerCred{token: tok, expires: out.ExpireTime, envName: "GOOGLE_OAUTH_ACCESS_TOKEN", route: gcpRoute}, nil
}

// gcpRoute maps /<host>.googleapis.com/<path> to https://<host>.googleapis.com/<path>.
func gcpRoute(rest string) (string, string, error) {
	host, path, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	if !strings.HasSuffix(host, ".googleapis.com") || strings.ContainsAny(host, ":@") {
		return "", "", errors.New("gcp: first path segment must be a googleapis.com host")
	}
	return "https://" + host, "/" + path, nil
}

func (g *GCP) Revoke(context.Context, []byte) error { return nil }

func (g *GCP) ProxyEnv(req Request, base, token string) []string {
	return []string{"VOGT_GCP_BASE=" + base, "VOGT_GCP_TOKEN=" + token}
}

// bearerCred injects "Authorization: Bearer <token>".
type bearerCred struct {
	token   *secmem.Buffer
	expires time.Time
	envName string
	// route maps the proxied path to an upstream base and path.
	route func(rest string) (base, path string, err error)
}

func (c *bearerCred) Inject(r *http.Request, rest string) error {
	base, path, err := c.route(rest)
	if err != nil {
		return err
	}
	if err := PointAt(r, base, path); err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+string(c.token.Bytes()))
	return nil
}

func (c *bearerCred) Env() []string      { return []string{c.envName + "=" + string(c.token.Bytes())} }
func (c *bearerCred) Handle() []byte     { return nil }
func (c *bearerCred) Expires() time.Time { return c.expires }
func (c *bearerCred) Wipe()              { c.token.Destroy() }
