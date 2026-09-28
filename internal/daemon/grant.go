package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"uuid"

	"vogt/internal/envelope"
	"vogt/internal/grants"
	"vogt/internal/helperlink"
	"vogt/internal/policy"
	"vogt/internal/provider"
	"vogt/internal/secmem"
	"vogt/internal/session"
	"vogt/internal/token"
	"vogt/internal/vault"
)

type tierT = envelope.Tier

// GrantRequest is what an agent asks for.
type GrantRequest struct {
	Capability string      `json:"capability"`
	Target     string      `json:"target"`
	TTL        string      `json:"ttl,omitempty"`
	Mode       policy.Mode `json:"mode,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Command    []string    `json:"command,omitempty"` // direct and reveal modes
}

// ErrDenied is returned for requests the policy refuses outright.
var ErrDenied = errors.New("denied by policy")

// RequestGrant validates a request, records it as pending and starts the
// approval in the background. Agents wait for it with WaitGrant.
func (d *Daemon) RequestGrant(s *session.Session, req GrantRequest) (*grants.Grant, error) {
	p := d.Policy()
	if p == nil {
		return nil, ErrNoPolicy
	}
	c, ok := p.Capabilities[req.Capability]
	if !ok {
		return nil, fmt.Errorf("unknown capability %q", req.Capability)
	}
	target := req.Target
	if target == "" {
		target = "default"
	}
	if sanitize(target, 200) != target || strings.ContainsAny(target, " \"'`") {
		return nil, errors.New("target contains characters that are not allowed")
	}
	if c.Target != "" && !policy.Match(c.Target, target) {
		return nil, fmt.Errorf("target %q does not fit %q", target, c.Target)
	}
	mode := req.Mode
	if mode == "" {
		mode = policy.ModeProxy
	}
	if !c.AllowsMode(mode) {
		return nil, fmt.Errorf("capability %s does not allow %s mode", req.Capability, mode)
	}
	if mode == policy.ModeReveal && c.Provider != "static" {
		return nil, errors.New("reveal mode is only for static keys")
	}
	if mode != policy.ModeProxy && len(req.Command) == 0 {
		return nil, fmt.Errorf("%s mode needs the command that will receive the credential", mode)
	}

	rule := p.Decide(req.Capability, target)
	fields := map[string]string{"session": s.ID, "capability": req.Capability, "target": target, "mode": string(mode)}
	if rule.Decision == policy.Deny {
		fields["reason"] = "policy"
		d.Audit("grant.refused", fields)
		return nil, ErrDenied
	}
	ttl := min(time.Duration(rule.MaxTTL), 10*time.Minute)
	if req.TTL != "" {
		v, err := time.ParseDuration(req.TTL)
		if err != nil {
			return nil, fmt.Errorf("ttl: %w", err)
		}
		ttl = v
	}
	if ttl < 30*time.Second || ttl > time.Duration(rule.MaxTTL) {
		return nil, fmt.Errorf("ttl must be between 30s and %v", time.Duration(rule.MaxTTL))
	}

	a, err := d.adapters.Get(c.Provider)
	if err != nil {
		return nil, err
	}
	id := uuid.New().String()
	preq := provider.Request{GrantID: id, Capability: req.Capability, Target: target, Scope: expandScope(c.Scope, target), Upstream: c.Upstream, TTL: ttl, Direct: mode != policy.ModeProxy}
	derived, err := a.Permissions(preq)
	if err != nil {
		return nil, err
	}
	perms := provider.Sorted(append(append([]string(nil), c.Permissions...), derived...))
	if err := p.CheckForbidden(perms); err != nil {
		fields["reason"] = err.Error()
		d.Audit("grant.refused", fields)
		return nil, err
	}

	now := time.Now()
	g := &grants.Grant{
		ID: id, Session: s.ID, SessionName: s.Name, Capability: req.Capability, Target: target,
		Mode: mode, Provider: c.Provider, Route: c.Route, Reason: sanitize(req.Reason, 200),
		Command: req.Command, Permissions: perms, DenyRefs: rule.DenyRefs, Cap: c, Request: preq,
		TTL: ttl, Created: now,
	}
	if mode != policy.ModeProxy {
		worst := ttl
		if min := a.Guarantees().MinDirectTTL; min > worst {
			worst = min
		}
		if mode == policy.ModeReveal {
			worst = 0 // a revealed static key lives until rotated
		}
		if worst > 0 {
			g.WorstCase = now.Add(worst)
		}
	}
	g.Display = d.display(g, c)
	g.ComputeDigest()
	d.grants.Add(g)
	fields["grant"] = g.ID
	d.Audit("grant.requested", fields)
	go d.process(g, rule, s)
	return g, nil
}

// expandScope replaces {target} in a capability's scope.
func expandScope(scope []byte, target string) []byte {
	if len(scope) == 0 {
		return scope
	}
	return []byte(strings.ReplaceAll(string(scope), "{target}", target))
}

func (d *Daemon) display(g *grants.Grant, c policy.Capability) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (session %s) requests:\n", g.SessionName, short(g.Session))
	fmt.Fprintf(&b, "  %s\n", c.DisplayFor(g.Target))
	if len(g.Permissions) > 0 {
		fmt.Fprintf(&b, "  Permissions: %s\n", strings.Join(g.Permissions, ", "))
	}
	end := g.Created.Add(g.TTL)
	fmt.Fprintf(&b, "  Mode: %s · ends %s (%v)\n", g.Mode, end.Format("15:04"), g.TTL)
	switch g.Mode {
	case policy.ModeDirect:
		fmt.Fprintf(&b, "  The agent will HOLD the credential, via: %s\n", quoteCommand(g.Command))
		fmt.Fprintf(&b, "  Valid until %s if Vogt cannot revoke it\n", g.WorstCase.Format("15:04"))
	case policy.ModeReveal:
		fmt.Fprintf(&b, "  REVEALS the raw key to: %s\n", quoteCommand(g.Command))
		b.WriteString("  It stays valid until you rotate it\n")
	}
	if g.Reason != "" {
		fmt.Fprintf(&b, "  Agent says: %q [unverified]", g.Reason)
	}
	return strings.TrimRight(b.String(), "\n")
}

func quoteCommand(cmd []string) string {
	q := make([]string, len(cmd))
	for i, c := range cmd {
		c = sanitize(c, 120)
		if strings.ContainsAny(c, " \t'\"$`\\") || c == "" {
			c = "'" + strings.ReplaceAll(c, "'", `'\''`) + "'"
		}
		q[i] = c
	}
	s := strings.Join(q, " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// process runs the approval and minting for a pending grant.
func (d *Daemon) process(g *grants.Grant, rule policy.Rule, s *session.Session) {
	fail := func(reason string) {
		d.grants.Deny(g, reason)
		d.Audit("grant.denied", map[string]string{"grant": g.ID, "reason": reason})
	}
	a, err := d.adapters.Get(g.Provider)
	if err != nil {
		fail(err.Error())
		return
	}
	master, evidence, err := d.approve(g, rule, s)
	if err != nil {
		fail(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cred, err := a.Mint(ctx, g.Request, master.Bytes())
	cancel()
	master.Destroy()
	if err != nil {
		fail("mint failed: " + err.Error())
		return
	}
	if rm, ok := cred.(provider.RotatedMaster); ok {
		d.storeRotatedMaster(g, rm.NewMaster())
	}

	now := time.Now()
	g.NotAfter = now.Add(g.TTL)
	if g.Mode == policy.ModeDirect && !cred.Expires().IsZero() {
		g.WorstCase = cred.Expires()
	}
	delivery := &grants.Delivery{}
	switch g.Mode {
	case policy.ModeProxy:
		tok, h := token.New(token.Proxy)
		g.TokenHash = h
		base := d.ProxyBase() + "/" + g.Route
		delivery.Token, delivery.ProxyURL = tok, base
		delivery.Env = a.ProxyEnv(g.Request, base, tok)
	default:
		delivery.Env = cred.Env()
	}
	g.Cred = cred
	if err := d.journal.Start(g.ID, g.Provider, cred.Handle()); err != nil {
		d.log.Error("journal write failed", "err", err)
	}
	if err := d.grants.Activate(g, delivery); err != nil {
		d.EndGrant(g, grants.Revoked, "session ended during approval")
		return
	}
	f := map[string]string{"grant": g.ID, "session": g.Session, "capability": g.Capability, "target": g.Target, "mode": string(g.Mode), "not_after": g.NotAfter.UTC().Format(time.RFC3339), "approval": evidence}
	if !g.WorstCase.IsZero() {
		f["worst_case"] = g.WorstCase.UTC().Format(time.RFC3339)
	}
	d.Audit("grant.issued", f)
}

// approve gets the master secret for a grant: from a bundle the human
// approved earlier, or through the helper. Every high-tier secret needs a
// tap; a policy "allow" only skips the tap for low-tier secrets.
func (d *Daemon) approve(g *grants.Grant, rule policy.Rule, s *session.Session) (*secmem.Buffer, string, error) {
	if m := d.bundleMaster(s.ID, g); m != nil {
		return m, "bundle", nil
	}
	entry, err := d.vault.Get(g.Cap.Secret)
	if err != nil {
		return nil, "", fmt.Errorf("secret %q: %w", g.Cap.Secret, err)
	}
	if entry.Provider != g.Provider {
		return nil, "", fmt.Errorf("secret %q is for provider %s, not %s", entry.ID, entry.Provider, g.Provider)
	}
	wrapped, ok := entry.Wraps[vault.WrapSE]
	if !ok {
		return nil, "", errors.New("secret has no helper wrap")
	}
	req := helperlink.DEKRequest{Tier: entry.Tier, Wrapped: wrapped, AAD: vault.WrapAAD(entry.ID, entry.KeyVersion)}
	ch := helperlink.Challenge{ID: g.ID, Display: g.Display, Digest: g.Digest, DEKs: []helperlink.DEKRequest{req}}

	tap := rule.Decision == policy.Ask || entry.Tier == envelope.TierHigh
	if tap {
		ch.Kind = helperlink.KindGrant
		if g.Mode == policy.ModeProxy {
			ch.MaxBundle = uint64(time.Duration(rule.MaxBundle) / time.Minute)
		}
		if err := d.sessions.BeginPending(s); err != nil {
			return nil, "", err
		}
	} else {
		ch.Kind = helperlink.KindUnwrap
	}
	res, err := d.helper.Ask(context.Background(), ch, d.approvalTimeout())
	if errors.Is(err, helperlink.ErrNoHelper) && d.phoneReady(entry) {
		// The Mac's helper is away: a passkey on the phone can approve.
		if !tap {
			if err := d.sessions.BeginPending(s); err != nil {
				return nil, "", err
			}
		}
		master, evidence, perr := d.askPhone(context.Background(), g.ID, g.Display, g.Digest, entry)
		d.sessions.EndPending(s, perr != nil && strings.Contains(perr.Error(), "denied"))
		return master, evidence, perr
	}
	if tap {
		d.sessions.EndPending(s, err == nil && res != nil && !res.Approved)
	}
	if err != nil {
		return nil, "", err
	}
	defer res.Destroy()
	if !res.Approved {
		return nil, "", errors.New("the human denied the request")
	}
	master, err := vault.Decrypt(entry, res.DEKs[0].Bytes())
	if err != nil {
		return nil, "", errors.New("secret did not decrypt")
	}
	evidence := "policy"
	if len(res.ApprovalSig) > 0 {
		h := sha256.Sum256(res.ApprovalSig)
		evidence = hex.EncodeToString(h[:8])
	}
	if res.Bundle > 0 {
		d.addBundle(s.ID, g, master, res.Bundle)
		d.Audit("bundle.started", map[string]string{"session": s.ID, "capability": g.Capability, "target": g.Target, "minutes": fmt.Sprint(int(res.Bundle.Minutes()))})
	}
	return master, evidence, nil
}

// WaitGrant waits up to timeout for a pending grant to be decided and
// returns its view, with the one-time delivery if it just became active.
func (d *Daemon) WaitGrant(ctx context.Context, s *session.Session, id string, timeout time.Duration) (grants.View, error) {
	g, ok := d.grants.Get(id)
	if !ok || g.Session != s.ID {
		return grants.View{}, errors.New("no such grant")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d.grants.Wait(ctx, g)
	return d.grants.View(g, true), nil
}

// SurrenderGrant ends a grant on the agent's request.
func (d *Daemon) SurrenderGrant(s *session.Session, id string) error {
	g, ok := d.grants.Get(id)
	if !ok || g.Session != s.ID {
		return errors.New("no such grant")
	}
	d.EndGrant(g, grants.Revoked, "surrendered by the agent")
	return nil
}

// Grants lists grants, all of them or one session's.
func (d *Daemon) Grants(sessionID string) []grants.View {
	var out []grants.View
	for _, g := range d.grants.List(sessionID) {
		out = append(out, d.grants.View(g, false))
	}
	return out
}

// RevokeGrant ends any grant by ID. Anyone may revoke; it only removes access.
func (d *Daemon) RevokeGrant(id string) error {
	g, ok := d.grants.Get(id)
	if !ok {
		return errors.New("no such grant")
	}
	d.EndGrant(g, grants.Revoked, "revoked by the human")
	return nil
}

// EndGrant ends a grant: the proxy stops accepting its token at once, the
// credential is wiped, and the provider is asked to revoke it.
func (d *Daemon) EndGrant(g *grants.Grant, state grants.State, reason string) {
	if !d.grants.End(g, state, reason) {
		return
	}
	cred := g.Cred
	handle := cred.Handle()
	defer cred.Wipe()
	f := map[string]string{"grant": g.ID, "state": string(state), "reason": reason}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	var err error
	if r, ok := cred.(provider.Revoker); ok {
		err = r.Revoke(ctx)
	} else if a, aerr := d.adapters.Get(g.Provider); aerr == nil {
		err = a.Revoke(ctx, handle)
	} else {
		err = aerr
	}
	cancel()
	clear(handle)
	if err != nil {
		f["revoke"] = "failed: " + err.Error()
	} else {
		f["revoke"] = "ok"
	}
	d.journal.End(g.ID)
	d.Audit("grant.ended", f)
}

// RevokeAll ends every grant and bundle.
func (d *Daemon) RevokeAll(reason string) int {
	n := 0
	for _, g := range d.grants.Active() {
		d.EndGrant(g, grants.Revoked, reason)
		n++
	}
	d.dropBundles("")
	d.Audit("revoke.all", map[string]string{"reason": reason, "grants": fmt.Sprint(n)})
	return n
}

// --- proxy backend ------------------------------------------------------

// GrantByToken implements proxy.Backend.
func (d *Daemon) GrantByToken(h [32]byte) (*grants.Grant, bool) { return d.grants.ByToken(h) }

// GrantByID implements proxy.Backend. Only active grants are returned.
func (d *Daemon) GrantByID(id string) (*grants.Grant, bool) {
	g, ok := d.grants.Get(id)
	if !ok || g.State != grants.Active {
		return nil, false
	}
	return g, true
}

// --- bundles ---------------------------------------------------------------

type bundleKey struct{ session, capability, target string }

type bundle struct {
	master *secmem.Buffer
	until  time.Time
}

func (d *Daemon) addBundle(sessionID string, g *grants.Grant, master *secmem.Buffer, dur time.Duration) {
	cp, err := secmem.FromBytes(append([]byte(nil), master.Bytes()...))
	if err != nil {
		return
	}
	k := bundleKey{sessionID, g.Capability, g.Target}
	d.mu.Lock()
	if old := d.bundles[k]; old != nil {
		old.master.Destroy()
	}
	d.bundles[k] = &bundle{master: cp, until: time.Now().Add(dur)}
	d.mu.Unlock()
}

func (d *Daemon) bundleMaster(sessionID string, g *grants.Grant) *secmem.Buffer {
	if g.Mode != policy.ModeProxy {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.bundles[bundleKey{sessionID, g.Capability, g.Target}]
	if b == nil || time.Now().After(b.until) {
		return nil
	}
	cp, err := secmem.FromBytes(append([]byte(nil), b.master.Bytes()...))
	if err != nil {
		return nil
	}
	return cp
}

func (d *Daemon) expireBundles() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, b := range d.bundles {
		if now.After(b.until) {
			b.master.Destroy()
			delete(d.bundles, k)
		}
	}
}

func (d *Daemon) dropBundles(sessionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, b := range d.bundles {
		if sessionID == "" || k.session == sessionID {
			b.master.Destroy()
			delete(d.bundles, k)
		}
	}
}

// storeRotatedMaster re-seals a master secret the provider replaced, such as
// a rotated OAuth refresh token. Sealing needs only the tier's public key.
func (d *Daemon) storeRotatedMaster(g *grants.Grant, m []byte) {
	if len(m) == 0 {
		return
	}
	entry, err := d.vault.Get(g.Cap.Secret)
	if err != nil {
		clear(m)
		return
	}
	if _, err := d.vault.Put(entry.ID, entry.Provider, entry.Tier, m); err != nil {
		d.Audit("secret.rotate_failed", map[string]string{"secret": entry.ID, "reason": err.Error()})
		return
	}
	d.Audit("secret.rotated", map[string]string{"secret": entry.ID, "by": g.Provider})
}
