package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"vogt/internal/secmem"
)

// Static injects a static API key into proxied requests. The key never
// leaves the broker in proxy mode; reveal mode hands it over only if the
// capability allows it.
type Static struct{}

type staticScope struct {
	Header string `json:"header"` // e.g. "Authorization" or "x-api-key"
	Format string `json:"format"` // e.g. "Bearer {key}"
	// Env names what the agent needs in proxy mode (base URL and key
	// variables) and reveal mode (key variable).
	BaseEnv    string `json:"base_env,omitempty"`
	BaseSuffix string `json:"base_suffix,omitempty"`
	KeyEnv     string `json:"key_env,omitempty"`
}

func (Static) Name() string { return "static" }

func (Static) Guarantees() Guarantees {
	return Guarantees{Revoke: RevokeImmediate}
}

func (Static) Permissions(req Request) ([]string, error) {
	var s staticScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return nil, err
	}
	if req.Upstream == "" {
		return nil, errors.New("static provider needs an upstream")
	}
	return []string{"static:" + strings.TrimPrefix(req.Upstream, "https://")}, nil
}

func (Static) Mint(_ context.Context, req Request, master []byte) (Credential, error) {
	var s staticScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return nil, err
	}
	if s.Header == "" || !strings.Contains(s.Format, "{key}") {
		return nil, errors.New("static scope needs a header and a format containing {key}")
	}
	key, err := secmem.FromBytes(append([]byte(nil), master...))
	if err != nil {
		return nil, err
	}
	return &staticCred{key: key, scope: s, upstream: req.Upstream}, nil
}

func (Static) Revoke(context.Context, []byte) error { return nil }

func (Static) ProxyEnv(req Request, base, token string) []string {
	var s staticScope
	if DecodeScope(req.Scope, &s) != nil {
		return nil
	}
	var env []string
	if s.BaseEnv != "" {
		env = append(env, s.BaseEnv+"="+base+s.BaseSuffix)
	}
	if s.KeyEnv != "" {
		env = append(env, s.KeyEnv+"="+token)
	}
	return env
}

type staticCred struct {
	key      *secmem.Buffer
	scope    staticScope
	upstream string
}

func (c *staticCred) Inject(r *http.Request, rest string) error {
	if err := PointAt(r, c.upstream, rest); err != nil {
		return err
	}
	r.Header.Set(c.scope.Header, strings.ReplaceAll(c.scope.Format, "{key}", string(c.key.Bytes())))
	return nil
}

func (c *staticCred) Env() []string {
	name := c.scope.KeyEnv
	if name == "" {
		name = "VOGT_SECRET"
	}
	return []string{name + "=" + string(c.key.Bytes())}
}

func (c *staticCred) Handle() []byte     { return nil }
func (c *staticCred) Expires() time.Time { return time.Time{} }
func (c *staticCred) Wipe()              { c.key.Destroy() }
