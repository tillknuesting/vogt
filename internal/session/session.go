// Package session tracks agent sessions and the limits that stop an agent
// from wearing down the human with prompts.
//
// A session starts with `vogt run`, which hands the agent a fresh session
// secret. The secret is the agent's identity; the registry keeps only its
// hash. Each session may have a limited number of pending requests, and
// repeated denials lock it until the human unlocks it.
package session

import (
	"errors"
	"sync"
	"time"

	"uuid"

	"vogt/internal/token"
)

// Limits configure the registry. Zero values are replaced by defaults.
type Limits struct {
	MaxPendingPerSession int
	MaxPendingTotal      int
	DenialsBeforeLock    int
	DenialWindow         time.Duration
}

var (
	ErrUnknown      = errors.New("session: unknown or ended session")
	ErrLocked       = errors.New("session: locked after repeated denials; unlock it with `vogt session unlock`")
	ErrBusy         = errors.New("session: a request is already waiting for approval")
	ErrApproverBusy = errors.New("session: too many requests are waiting for approval")
)

// Session is one running agent.
type Session struct {
	ID      string
	Name    string
	Created time.Time

	hash    [32]byte
	pending int
	denials []time.Time
	locked  bool
}

// Registry holds live sessions.
type Registry struct {
	mu      sync.Mutex
	limits  Limits
	byHash  map[[32]byte]*Session
	byID    map[string]*Session
	pending int
	now     func() time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry(l Limits) *Registry {
	if l.MaxPendingPerSession <= 0 {
		l.MaxPendingPerSession = 1
	}
	if l.MaxPendingTotal <= 0 {
		l.MaxPendingTotal = 3
	}
	if l.DenialsBeforeLock <= 0 {
		l.DenialsBeforeLock = 3
	}
	if l.DenialWindow <= 0 {
		l.DenialWindow = 10 * time.Minute
	}
	return &Registry{limits: l, byHash: map[[32]byte]*Session{}, byID: map[string]*Session{}, now: time.Now}
}

// SetLimits replaces the limits, for example after a policy reload.
func (r *Registry) SetLimits(l Limits) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.MaxPendingPerSession > 0 {
		r.limits.MaxPendingPerSession = l.MaxPendingPerSession
	}
	if l.MaxPendingTotal > 0 {
		r.limits.MaxPendingTotal = l.MaxPendingTotal
	}
	if l.DenialsBeforeLock > 0 {
		r.limits.DenialsBeforeLock = l.DenialsBeforeLock
	}
	if l.DenialWindow > 0 {
		r.limits.DenialWindow = l.DenialWindow
	}
}

// Create starts a session and returns its secret. The secret is not stored.
func (r *Registry) Create(name string) (string, *Session) {
	tok, h := token.New(token.Session)
	s := &Session{ID: uuid.New().String(), Name: name, Created: r.now(), hash: h}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byHash[h] = s
	r.byID[s.ID] = s
	return tok, s
}

// Lookup finds the session for a secret.
func (r *Registry) Lookup(secret string) (*Session, error) {
	if k, ok := token.Parse(secret); !ok || k != token.Session {
		return nil, ErrUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byHash[token.Hash(secret)]
	if !ok {
		return nil, ErrUnknown
	}
	return s, nil
}

// Get finds a session by ID.
func (r *Registry) Get(id string) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	return s, ok
}

// End removes a session. Its pending requests stop counting.
func (r *Registry) End(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	if !ok {
		return
	}
	r.pending -= s.pending
	delete(r.byID, id)
	delete(r.byHash, s.hash)
}

// List returns all live sessions.
func (r *Registry) List() []Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Session, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, *s)
	}
	return out
}

// BeginPending reserves an approval slot for the session. Call EndPending
// when the approval is decided.
func (r *Registry) BeginPending(s *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[s.ID]; !ok {
		return ErrUnknown
	}
	if s.locked {
		return ErrLocked
	}
	if s.pending >= r.limits.MaxPendingPerSession {
		return ErrBusy
	}
	if r.pending >= r.limits.MaxPendingTotal {
		return ErrApproverBusy
	}
	s.pending++
	r.pending++
	return nil
}

// EndPending releases an approval slot. If the human denied the request,
// it counts toward the lockout.
func (r *Registry) EndPending(s *Session, denied bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.pending > 0 {
		s.pending--
		if _, ok := r.byID[s.ID]; ok {
			r.pending--
		}
	}
	if !denied {
		return
	}
	now := r.now()
	cutoff := now.Add(-r.limits.DenialWindow)
	kept := s.denials[:0]
	for _, t := range s.denials {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.denials = append(kept, now)
	if len(s.denials) >= r.limits.DenialsBeforeLock {
		s.locked = true
	}
}

// Locked reports whether the session is locked.
func (r *Registry) Locked(s *Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return s.locked
}

// Unlock clears a session's lock and its denial history.
func (r *Registry) Unlock(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.byID[id]
	if !ok {
		return ErrUnknown
	}
	s.locked, s.denials = false, nil
	return nil
}
