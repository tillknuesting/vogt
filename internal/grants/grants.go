// Package grants holds the lifecycle of every grant: pending until the
// human or the policy decides, active until surrendered, revoked or expired.
package grants

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"vogt/internal/policy"
	"vogt/internal/provider"
	"vogt/internal/secmem"
	"vogt/internal/wire"
)

// State is where a grant is in its lifecycle.
type State string

const (
	Pending State = "pending"
	Active  State = "active"
	Revoked State = "revoked"
	Expired State = "expired"
	Denied  State = "denied"
)

// Final reports whether a state ends the grant.
func (s State) Final() bool { return s == Revoked || s == Expired || s == Denied }

// Delivery is what the agent receives once, when the grant becomes active.
type Delivery struct {
	Token    string   `json:"token,omitempty"`
	ProxyURL string   `json:"proxy_url,omitempty"`
	Env      []string `json:"env,omitempty"`
}

// Grant is one approved, pending or finished request.
type Grant struct {
	ID          string
	Session     string
	SessionName string
	Capability  string
	Target      string
	Mode        policy.Mode
	Provider    string
	Route       string
	Display     string
	Reason      string
	Command     []string
	Permissions []string
	DenyRefs    []string
	Cap         policy.Capability
	Request     provider.Request

	TTL       time.Duration
	Created   time.Time
	NotAfter  time.Time
	WorstCase time.Time
	State     State
	EndReason string
	Digest    [32]byte
	Evidence  []byte // hash of the approval signature, for the audit log

	TokenHash [32]byte
	VerifyKey *secmem.Buffer // AWS grants: the broker token, to check SigV4
	Cred      provider.Credential

	delivery *Delivery
	done     chan struct{}
	timer    *time.Timer
}

// ComputeDigest fixes what the human approves: who, what, which target, how
// and for how long.
func (g *Grant) ComputeDigest() {
	cmd := make([][]byte, len(g.Command))
	for i, c := range g.Command {
		cmd[i] = []byte(c)
	}
	m := wire.NewEncoder("vogt/v1/grant").
		PutString(g.ID).PutString(g.Session).PutString(g.Capability).PutString(g.Target).
		PutString(string(g.Mode)).PutString(g.Display).PutUint(uint64(g.TTL)).PutList(cmd).
		Finish()
	g.Digest = sha256.Sum256(m)
}

// View is a grant as shown to agents and in listings. It never holds secrets.
type View struct {
	ID         string      `json:"id"`
	Session    string      `json:"session"`
	Capability string      `json:"capability"`
	Target     string      `json:"target"`
	Mode       policy.Mode `json:"mode"`
	State      State       `json:"state"`
	EndReason  string      `json:"end_reason,omitempty"`
	Created    time.Time   `json:"created"`
	NotAfter   time.Time   `json:"not_after,omitzero"`
	WorstCase  time.Time   `json:"worst_case,omitzero"`
	Display    string      `json:"display"`
	Delivery   *Delivery   `json:"delivery,omitempty"`
}

// Store holds grants in memory.
type Store struct {
	mu      sync.Mutex
	byID    map[string]*Grant
	byToken map[[32]byte]*Grant
	now     func() time.Time
	// OnExpire is called when an active grant reaches NotAfter.
	OnExpire func(g *Grant)
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{byID: map[string]*Grant{}, byToken: map[[32]byte]*Grant{}, now: time.Now}
}

// Add stores a new pending grant.
func (s *Store) Add(g *Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.State = Pending
	g.done = make(chan struct{})
	s.byID[g.ID] = g
}

// Get returns a grant by ID.
func (s *Store) Get(id string) (*Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[id]
	return g, ok
}

// ByToken returns the active grant for a broker token hash.
func (s *Store) ByToken(h [32]byte) (*Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byToken[h]
	if !ok || g.State != Active {
		return nil, false
	}
	return g, true
}

// Activate moves a pending grant to active and starts its expiry timer.
func (s *Store) Activate(g *Grant, d *Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.State != Pending {
		return errors.New("grants: grant is no longer pending")
	}
	g.State = Active
	g.delivery = d
	if g.TokenHash != ([32]byte{}) {
		s.byToken[g.TokenHash] = g
	}
	wait := g.NotAfter.Sub(s.now())
	g.timer = time.AfterFunc(wait, func() {
		if s.OnExpire != nil {
			s.OnExpire(g)
		}
	})
	close(g.done)
	return nil
}

// Deny ends a pending grant.
func (s *Store) Deny(g *Grant, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.State != Pending {
		return
	}
	g.State, g.EndReason = Denied, reason
	close(g.done)
}

// End moves an active grant to a final state and returns true if it was
// active. The caller wipes and revokes the credential.
func (s *Store) End(g *Grant, state State, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch g.State {
	case Active:
		if g.timer != nil {
			g.timer.Stop()
		}
		delete(s.byToken, g.TokenHash)
		g.State, g.EndReason, g.delivery = state, reason, nil
		return true
	case Pending:
		g.State, g.EndReason = state, reason
		close(g.done)
	}
	return false
}

// Wait blocks until the grant leaves pending or ctx ends.
func (s *Store) Wait(ctx context.Context, g *Grant) {
	select {
	case <-g.done:
	case <-ctx.Done():
	}
}

// View returns the grant's public view. If take is true and the grant is
// active, the one-time delivery is included and then cleared.
func (s *Store) View(g *Grant, take bool) View {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{
		ID: g.ID, Session: g.Session, Capability: g.Capability, Target: g.Target, Mode: g.Mode,
		State: g.State, EndReason: g.EndReason, Created: g.Created, NotAfter: g.NotAfter,
		WorstCase: g.WorstCase, Display: g.Display,
	}
	if take && g.State == Active && g.delivery != nil {
		v.Delivery = g.delivery
		g.delivery = nil
	}
	return v
}

// List returns every grant, optionally for one session only.
func (s *Store) List(session string) []*Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Grant
	for _, g := range s.byID {
		if session == "" || g.Session == session {
			out = append(out, g)
		}
	}
	return out
}

// Active returns every active grant.
func (s *Store) Active() []*Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Grant
	for _, g := range s.byID {
		if g.State == Active || g.State == Pending {
			out = append(out, g)
		}
	}
	return out
}

// Prune forgets finished grants older than age.
func (s *Store) Prune(age time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-age)
	for id, g := range s.byID {
		if g.State.Final() && g.Created.Before(cutoff) {
			delete(s.byID, id)
		}
	}
}
