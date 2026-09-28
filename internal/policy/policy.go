// Package policy parses and evaluates Vogt's policy file.
//
// A policy holds a capability catalogue (what each named capability means for
// a provider and the proxy), ordered rules (allow, ask or deny per capability
// and target), permissions that no grant may ever include, and rate limits.
// The daemon only loads a policy the human signed with Touch ID, and only if
// its version is higher than the last one loaded.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Decision is what a rule says to do with a request.
type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

// Mode is how a credential reaches the agent.
type Mode string

const (
	ModeProxy  Mode = "proxy"
	ModeDirect Mode = "direct"
	ModeReveal Mode = "reveal"
)

// MaxTTL is the longest grant any rule may allow.
const MaxTTL = time.Hour

// Duration is a time.Duration written as a Go duration string, such as "10m".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Policy is a parsed, validated policy file.
type Policy struct {
	Version      uint64                `json:"version"`
	Capabilities map[string]Capability `json:"capabilities"`
	Rules        []Rule                `json:"rules"`
	Forbidden    []string              `json:"forbidden_permissions"`
	Limits       Limits                `json:"limits"`
}

// Capability describes one thing an agent can ask for.
type Capability struct {
	Provider string `json:"provider"`           // github, postgres, oauth, static
	Secret   string `json:"secret"`             // vault record holding the master credential
	Route    string `json:"route"`              // proxy route name: base URL is /<route>
	Upstream string `json:"upstream,omitempty"` // for static and oauth providers
	Display  string `json:"display"`            // approval text; {target} is replaced
	// Permissions are shown on approval and checked against the forbidden
	// list, together with the permissions the provider derives from Scope.
	Permissions []string        `json:"permissions,omitempty"`
	Scope       json.RawMessage `json:"scope,omitempty"` // provider-specific
	Allow       []ProxyRule     `json:"allow,omitempty"` // requests the proxy lets through
	Modes       []Mode          `json:"modes,omitempty"` // default: proxy only
	Target      string          `json:"target,omitempty"`
	Hosts       []string        `json:"hosts,omitempty"` // TLS-interception fallback only
}

// ProxyRule lets requests with one of Methods and a path matching Path
// through. In Path, {target} is replaced by the grant's target, * matches
// within one path segment and ** matches across segments.
type ProxyRule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

// Rule decides requests for capabilities and targets matching its globs.
type Rule struct {
	Capability string   `json:"capability"`
	Target     string   `json:"target,omitempty"`
	Decision   Decision `json:"decision"`
	MaxTTL     Duration `json:"max_ttl,omitempty"`
	DenyRefs   []string `json:"deny_refs,omitempty"` // git refs the proxy refuses to update
	MaxBundle  Duration `json:"max_bundle,omitempty"`
}

// Limits bound how hard an agent can push the approver.
type Limits struct {
	MaxPendingPerSession int      `json:"max_pending_per_session,omitempty"`
	MaxPendingTotal      int      `json:"max_pending_total,omitempty"`
	DenialsBeforeLock    int      `json:"denials_before_lock,omitempty"`
	DenialWindow         Duration `json:"denial_window,omitempty"`
	ApprovalTimeout      Duration `json:"approval_timeout,omitempty"`
}

// Parse decodes and validates a policy.
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("policy: trailing data")
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.Version == 0 {
		return errors.New("version must be at least 1")
	}
	for name, c := range p.Capabilities {
		if !validName(name, ".-_") {
			return fmt.Errorf("capability %q: invalid name", name)
		}
		if c.Provider == "" || c.Secret == "" || c.Display == "" {
			return fmt.Errorf("capability %q: provider, secret and display are required", name)
		}
		if !validName(c.Route, "-") {
			return fmt.Errorf("capability %q: route must be lowercase letters, digits and dashes", name)
		}
		for _, m := range c.Modes {
			if m != ModeProxy && m != ModeDirect && m != ModeReveal {
				return fmt.Errorf("capability %q: unknown mode %q", name, m)
			}
		}
		for _, r := range c.Allow {
			if !strings.HasPrefix(r.Path, "/") || len(r.Methods) == 0 {
				return fmt.Errorf("capability %q: allow rules need methods and a path starting with /", name)
			}
		}
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Capability == "" {
			return fmt.Errorf("rule %d: capability is required", i)
		}
		if r.Target == "" {
			r.Target = "*"
		}
		switch r.Decision {
		case Allow, Ask, Deny:
		default:
			return fmt.Errorf("rule %d: decision must be allow, ask or deny", i)
		}
		if r.MaxTTL == 0 {
			r.MaxTTL = Duration(10 * time.Minute)
		}
		if time.Duration(r.MaxTTL) > MaxTTL || r.MaxTTL < 0 {
			return fmt.Errorf("rule %d: max_ttl must be at most %v", i, MaxTTL)
		}
		if time.Duration(r.MaxBundle) > 4*time.Hour || r.MaxBundle < 0 {
			return fmt.Errorf("rule %d: max_bundle must be at most 4h", i)
		}
	}
	if slices.Contains(p.Forbidden, "") {
		return errors.New("empty forbidden permission")
	}
	l := &p.Limits
	setDefault(&l.MaxPendingPerSession, 1)
	setDefault(&l.MaxPendingTotal, 3)
	setDefault(&l.DenialsBeforeLock, 3)
	if l.DenialWindow == 0 {
		l.DenialWindow = Duration(10 * time.Minute)
	}
	if l.ApprovalTimeout == 0 {
		l.ApprovalTimeout = Duration(60 * time.Second)
	}
	return nil
}

func setDefault(v *int, d int) {
	if *v <= 0 {
		*v = d
	}
}

func validName(s, extra string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune(extra, c)) {
			return false
		}
	}
	return true
}

var defaultRule = Rule{Capability: "*", Target: "*", Decision: Ask, MaxTTL: Duration(10 * time.Minute)}

// Decide returns the first rule matching the capability and target, or an
// "ask" rule with a 10-minute ceiling when none matches.
func (p *Policy) Decide(capability, target string) Rule {
	for _, r := range p.Rules {
		if Match(r.Capability, capability) && Match(r.Target, target) {
			return r
		}
	}
	return defaultRule
}

// AllowsMode reports whether the capability may be granted in mode m.
func (c Capability) AllowsMode(m Mode) bool {
	if len(c.Modes) == 0 {
		return m == ModeProxy
	}
	return slices.Contains(c.Modes, m)
}

// CheckForbidden fails if any permission overlaps a forbidden one. Either
// side may use * wildcards; comparison ignores case.
func (p *Policy) CheckForbidden(perms []string) error {
	for _, have := range perms {
		for _, bad := range p.Forbidden {
			h, b := strings.ToLower(have), strings.ToLower(bad)
			if Match(b, h) || Match(h, b) {
				return fmt.Errorf("permission %q is forbidden by %q", have, bad)
			}
		}
	}
	return nil
}

// Match reports whether s matches pattern, where * matches any run of
// characters, including none.
func Match(pattern, s string) bool {
	for {
		i := strings.IndexByte(pattern, '*')
		if i < 0 {
			return pattern == s
		}
		if !strings.HasPrefix(s, pattern[:i]) {
			return false
		}
		s, pattern = s[i:], pattern[i+1:]
		for pattern != "" && pattern[0] == '*' {
			pattern = pattern[1:]
		}
		if pattern == "" {
			return true
		}
		for j := 0; j <= len(s); j++ {
			if Match(pattern, s[j:]) {
				return true
			}
		}
		return false
	}
}

// MatchPath reports whether path matches pattern, where ** matches any run of
// characters and * matches a run without '/'.
func MatchPath(pattern, path string) bool {
	if pattern == "" {
		return path == ""
	}
	if strings.HasPrefix(pattern, "**") {
		rest := pattern[2:]
		for j := 0; j <= len(path); j++ {
			if MatchPath(rest, path[j:]) {
				return true
			}
		}
		return false
	}
	if pattern[0] == '*' {
		rest := pattern[1:]
		for j := 0; j <= len(path); j++ {
			if MatchPath(rest, path[j:]) {
				return true
			}
			if j < len(path) && path[j] == '/' {
				return false
			}
		}
		return false
	}
	if path == "" || pattern[0] != path[0] {
		return false
	}
	return MatchPath(pattern[1:], path[1:])
}

// Permits reports whether a proxied request with this method and path is
// allowed for the given target.
func (c Capability) Permits(method, path, target string) bool {
	for _, r := range c.Allow {
		p := strings.ReplaceAll(r.Path, "{target}", target)
		if !MatchPath(p, path) {
			continue
		}
		for _, m := range r.Methods {
			if m == "*" || strings.EqualFold(m, method) {
				return true
			}
		}
	}
	return false
}

// DisplayFor renders the approval text for a target.
func (c Capability) DisplayFor(target string) string {
	return strings.ReplaceAll(c.Display, "{target}", target)
}
