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

// OAuth refreshes an access token from a stored refresh token for APIs such
// as Google Workspace or Microsoft Graph. The refresh token never leaves
// the broker, so this provider is proxy-only.
//
// The master secret is JSON: {"token_url": "...", "client_id": "...",
// "client_secret": "...", "refresh_token": "..."}.
type OAuth struct {
	Client *http.Client
}

type oauthScope struct {
	Scope string `json:"scope,omitempty"`
}

type oauthMaster struct {
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

func (o *OAuth) Name() string { return "oauth" }

func (o *OAuth) Guarantees() Guarantees { return Guarantees{Revoke: RevokeImmediate} }

func (o *OAuth) Permissions(req Request) ([]string, error) {
	var s oauthScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return nil, err
	}
	if req.Upstream == "" {
		return nil, errors.New("oauth provider needs an upstream")
	}
	var out []string
	for sc := range strings.FieldsSeq(s.Scope) {
		out = append(out, "oauth:"+sc)
	}
	return out, nil
}

// RotatedMaster is implemented by credentials whose minting replaced the
// master secret, such as a rotated refresh token.
type RotatedMaster interface {
	NewMaster() []byte
}

func (o *OAuth) Mint(ctx context.Context, req Request, master []byte) (Credential, error) {
	if req.Direct {
		return nil, errors.New("oauth credentials are proxy-only")
	}
	var s oauthScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return nil, err
	}
	var m oauthMaster
	if err := json.Unmarshal(master, &m); err != nil || m.TokenURL == "" || m.RefreshToken == "" {
		return nil, errors.New("oauth master secret needs token_url and refresh_token")
	}
	if !strings.HasPrefix(m.TokenURL, "https://") && !strings.HasPrefix(m.TokenURL, "http://127.0.0.1") {
		return nil, errors.New("oauth token_url must be HTTPS")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {m.RefreshToken}, "client_id": {m.ClientID}}
	if m.ClientSecret != "" {
		form.Set("client_secret", m.ClientSecret)
	}
	if s.Scope != "" {
		form.Set("scope", s.Scope)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hr.Header.Set("Accept", "application/json")
	c := o.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(hr)
	if err != nil {
		return nil, err
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := ReadJSON(resp, &out); err != nil {
		return nil, fmt.Errorf("oauth: refresh: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("oauth: empty access token")
	}
	tok, err := secmem.FromBytes([]byte(out.AccessToken))
	if err != nil {
		return nil, err
	}
	cred := &oauthCred{token: tok, envName: "VOGT_OAUTH_TOKEN", route: fixedRoute(req.Upstream)}
	if out.ExpiresIn > 0 {
		cred.expires = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	if out.RefreshToken != "" && out.RefreshToken != m.RefreshToken {
		m.RefreshToken = out.RefreshToken
		cred.newMaster, _ = json.Marshal(m)
	}
	return cred, nil
}

func fixedRoute(upstream string) func(string) (string, string, error) {
	return func(rest string) (string, string, error) { return upstream, rest, nil }
}

func (o *OAuth) Revoke(context.Context, []byte) error { return nil }

func (o *OAuth) ProxyEnv(req Request, base, token string) []string {
	return []string{"VOGT_OAUTH_BASE=" + base, "VOGT_OAUTH_TOKEN=" + token}
}

type oauthCred struct {
	bearerCred
	newMaster []byte
}

func (c *oauthCred) NewMaster() []byte {
	m := c.newMaster
	c.newMaster = nil
	return m
}
