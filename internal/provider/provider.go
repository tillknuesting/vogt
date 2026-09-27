// Package provider defines how Vogt turns a master secret into a
// short-lived credential for one grant, and how the proxy uses it.
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// RevokeKind says how quickly a provider can kill a credential early.
type RevokeKind uint8

const (
	RevokeNone      RevokeKind = iota // lives until the provider expires it
	RevokeImmediate                   // killed by an API call
	RevokeDelayed                     // killed by a policy change that takes time to apply
)

// Guarantees are what a provider can enforce, shown on direct-mode approvals.
type Guarantees struct {
	// MinDirectTTL is the shortest lifetime the provider issues. A direct-mode
	// credential lives at least this long if Vogt cannot revoke it.
	MinDirectTTL time.Duration
	// MaxDirectTTL is the longest lifetime the provider issues; 0 if fixed.
	MaxDirectTTL time.Duration
	Revoke       RevokeKind
}

// Request is what an adapter needs to mint for one grant.
type Request struct {
	GrantID    string
	Capability string
	Target     string
	Scope      json.RawMessage
	Upstream   string
	TTL        time.Duration
	Direct     bool // the agent will hold the credential itself
}

// Credential is a minted credential. Its secret bytes live in locked memory
// until Wipe.
type Credential interface {
	// Inject points r at the upstream and authenticates it. rest is the
	// request path after the proxy route prefix.
	Inject(r *http.Request, rest string) error
	// Env returns KEY=value pairs for direct and reveal modes.
	Env() []string
	// Handle is what Revoke needs to kill the credential after a crash.
	Handle() []byte
	// Expires is when the provider itself expires the credential; zero if never.
	Expires() time.Time
	Wipe()
}

// Adapter is one provider.
type Adapter interface {
	Name() string
	Guarantees() Guarantees
	// Permissions lists what the scope grants, as "provider:permission"
	// strings, for display and the forbidden-permission check.
	Permissions(req Request) ([]string, error)
	Mint(ctx context.Context, req Request, master []byte) (Credential, error)
	// Revoke kills a credential by its handle. Adapters that cannot revoke
	// return nil.
	Revoke(ctx context.Context, handle []byte) error
	// ProxyEnv returns the environment an agent needs to reach the proxy,
	// given the route's base URL and the grant's broker token.
	ProxyEnv(req Request, base, token string) []string
}

// Registry maps provider names to adapters.
type Registry map[string]Adapter

// Get returns the adapter for name.
func (r Registry) Get(name string) (Adapter, error) {
	a, ok := r[name]
	if !ok {
		return nil, fmt.Errorf("provider: unknown provider %q", name)
	}
	return a, nil
}

// DecodeScope decodes a capability scope strictly.
func DecodeScope(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	return nil
}

// Sorted returns a sorted copy of s.
func Sorted(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

// UserAgent is sent on every request Vogt makes itself.
const UserAgent = "vogt/1"
