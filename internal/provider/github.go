package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"vogt/internal/secmem"
)

// GitHub mints GitHub App installation tokens scoped to one repository and
// the capability's permissions, and revokes them when the grant ends.
//
// The master secret is JSON: {"app_id": "...", "installation_id": "...",
// "private_key": "-----BEGIN RSA PRIVATE KEY-----..."}.
type GitHub struct {
	APIBase string // default https://api.github.com
	GitBase string // default https://github.com
	Client  *http.Client
	Now     func() time.Time
}

type githubScope struct {
	Permissions map[string]string `json:"permissions"`
}

type githubMaster struct {
	AppID          json.Number `json:"app_id"`
	InstallationID json.Number `json:"installation_id"`
	PrivateKey     string      `json:"private_key"`
}

var repoTarget = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) Guarantees() Guarantees {
	return Guarantees{MinDirectTTL: time.Hour, MaxDirectTTL: time.Hour, Revoke: RevokeImmediate}
}

func (g *GitHub) api() string {
	if g.APIBase != "" {
		return strings.TrimSuffix(g.APIBase, "/")
	}
	return "https://api.github.com"
}

func (g *GitHub) git() string {
	if g.GitBase != "" {
		return strings.TrimSuffix(g.GitBase, "/")
	}
	return "https://github.com"
}

func (g *GitHub) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return http.DefaultClient
}

func (g *GitHub) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *GitHub) Permissions(req Request) ([]string, error) {
	var s githubScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return nil, err
	}
	if len(s.Permissions) == 0 {
		return nil, errors.New("github scope needs permissions")
	}
	var out []string
	for k, v := range s.Permissions {
		if v != "read" && v != "write" {
			return nil, fmt.Errorf("github permission %s must be read or write", k)
		}
		out = append(out, "github:"+k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

func (g *GitHub) Mint(ctx context.Context, req Request, master []byte) (Credential, error) {
	if !repoTarget.MatchString(req.Target) {
		return nil, fmt.Errorf("github target %q is not owner/repo", req.Target)
	}
	var s githubScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return nil, err
	}
	var m githubMaster
	if err := json.Unmarshal(master, &m); err != nil {
		return nil, errors.New("github master secret is not valid JSON")
	}
	pemBytes := []byte(m.PrivateKey)
	defer clear(pemBytes)
	key, err := ParseRSAKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("github app key: %w", err)
	}
	now := g.now()
	jwt, err := SignJWTRS256(key, map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": m.AppID.String(),
	})
	if err != nil {
		return nil, err
	}
	repo := req.Target[strings.IndexByte(req.Target, '/')+1:]
	body, _ := json.Marshal(map[string]any{"repositories": []string{repo}, "permissions": s.Permissions})
	u := fmt.Sprintf("%s/app/installations/%s/access_tokens", g.api(), m.InstallationID.String())
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	setGitHubHeaders(hr)
	hr.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := g.client().Do(hr)
	if err != nil {
		return nil, err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := ReadJSON(resp, &out); err != nil {
		return nil, fmt.Errorf("github: create installation token: %w", err)
	}
	if out.Token == "" {
		return nil, errors.New("github: empty installation token")
	}
	tok, err := secmem.FromBytes([]byte(out.Token))
	if err != nil {
		return nil, err
	}
	return &githubCred{g: g, token: tok, expires: out.ExpiresAt}, nil
}

func setGitHubHeaders(r *http.Request) {
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	r.Header.Set("User-Agent", UserAgent)
}

func (g *GitHub) Revoke(ctx context.Context, handle []byte) error {
	if len(handle) == 0 {
		return nil
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodDelete, g.api()+"/installation/token", nil)
	if err != nil {
		return err
	}
	setGitHubHeaders(hr)
	hr.Header.Set("Authorization", "token "+string(handle))
	resp, err := g.client().Do(hr)
	if err != nil {
		return err
	}
	resp.Body.Close()
	// 401 means the token is already dead.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("github: revoke returned %s", resp.Status)
	}
	return nil
}

// ProxyEnv points git at the proxy for github.com and exposes the API base.
func (g *GitHub) ProxyEnv(req Request, base, token string) []string {
	gitBase := strings.Replace(base, "://", "://vogt:"+token+"@", 1) + "/git/"
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=url." + gitBase + ".insteadOf",
		"GIT_CONFIG_VALUE_0=https://github.com/",
		"VOGT_GITHUB_API=" + base + "/api",
		"VOGT_GITHUB_TOKEN=" + token,
	}
}

type githubCred struct {
	g       *GitHub
	token   *secmem.Buffer
	expires time.Time
}

func (c *githubCred) Inject(r *http.Request, rest string) error {
	tok := string(c.token.Bytes())
	switch {
	case strings.HasPrefix(rest, "/api/"):
		if err := PointAt(r, c.g.api(), strings.TrimPrefix(rest, "/api")); err != nil {
			return err
		}
		r.Header.Set("Authorization", "token "+tok)
	case strings.HasPrefix(rest, "/git/"):
		if err := PointAt(r, c.g.git(), strings.TrimPrefix(rest, "/git")); err != nil {
			return err
		}
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok)))
	default:
		return errors.New("github: path must start with /api/ or /git/")
	}
	return nil
}

func (c *githubCred) Env() []string {
	t := string(c.token.Bytes())
	return []string{"GITHUB_TOKEN=" + t, "GH_TOKEN=" + t}
}

func (c *githubCred) Handle() []byte     { return append([]byte(nil), c.token.Bytes()...) }
func (c *githubCred) Expires() time.Time { return c.expires }
func (c *githubCred) Wipe()              { c.token.Destroy() }
