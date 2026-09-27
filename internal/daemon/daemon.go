// Package daemon is the Vogt broker: it owns the vault, policy, sessions,
// grants, the helper link, the audit log and the proxy.
package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"vogt/internal/audit"
	"vogt/internal/grants"
	"vogt/internal/helperlink"
	"vogt/internal/policy"
	"vogt/internal/provider"
	"vogt/internal/proxy"
	"vogt/internal/secmem"
	"vogt/internal/session"
	"vogt/internal/sig"
	"vogt/internal/vault"
	"vogt/internal/wire"
)

// Config configures a daemon.
type Config struct {
	StateDir  string // identity, pairing, policy, vault, audit log, journal
	RunDir    string // sockets
	ProxyAddr string // TCP address for the proxy; default 127.0.0.1:7853
	// WebAuthnAddr serves the phone and security-key approval page; empty
	// disables it.
	WebAuthnAddr string
	// Adapters overrides the provider adapters, for tests.
	Adapters provider.Registry
	// Transport overrides the proxy's upstream transport, for tests.
	Transport http.RoundTripper
	Logger    *slog.Logger
}

// State file names.
const (
	fileIdentity   = "identity.key"
	filePairing    = "pairing.bin"
	filePolicy     = "policy.json"
	filePolicySig  = "policy.sig"
	fileMaxVersion = "policy.maxversion"
	fileAudit      = "audit.log"
	fileJournal    = "grants.journal"
	fileJournalKey = "grants.key"
	dirVault       = "vault"

	// SocketName is the API socket in the run directory.
	SocketName = "vogt.sock"
	// HelperSocketName is the helper socket in the run directory.
	HelperSocketName = "helper.sock"
)

var (
	ErrNoPolicy  = errors.New("no signed policy is loaded; run `vogt policy load`")
	ErrNotPaired = errors.New("no helper is paired; run `vogt pair`")
)

// Daemon is a running broker.
type Daemon struct {
	cfg      Config
	log      *slog.Logger
	identity *sig.PrivateKey
	audit    *audit.Log
	vault    *vault.Store
	journal  *grants.Journal
	sessions *session.Registry
	grants   *grants.Store
	helper   *helperlink.Server
	adapters provider.Registry
	proxy    *proxy.Proxy

	mu        sync.RWMutex
	pol       *policy.Policy
	pairing   *helperlink.HelperKeys
	bundles   map[bundleKey]*bundle
	proxyBase string

	listeners []net.Listener
	servers   []*http.Server
	wg        sync.WaitGroup
}

// New loads state and prepares a daemon. Call Start to serve.
func New(cfg Config) (*Daemon, error) {
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = "127.0.0.1:7853"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	for _, dir := range []string{cfg.StateDir, cfg.RunDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := secmem.DisableCoreDumps(); err != nil {
		return nil, fmt.Errorf("disable core dumps: %w", err)
	}

	d := &Daemon{cfg: cfg, log: cfg.Logger, sessions: session.NewRegistry(session.Limits{}), grants: grants.NewStore(), bundles: map[bundleKey]*bundle{}}
	var err error
	if d.identity, err = loadOrCreateIdentity(d.state(fileIdentity)); err != nil {
		return nil, err
	}
	if d.audit, err = audit.Open(d.state(fileAudit), d.identity); err != nil {
		return nil, err
	}
	if d.journal, err = grants.OpenJournal(d.state(fileJournal), d.state(fileJournalKey)); err != nil {
		return nil, err
	}
	d.adapters = cfg.Adapters
	if d.adapters == nil {
		d.adapters = provider.Defaults(nil)
	}
	if err := d.loadPairing(); err != nil {
		return nil, err
	}
	var tiers vault.TierKeys
	if d.pairing != nil {
		tiers = vault.TierKeys{High: d.pairing.High, Low: d.pairing.Low}
	}
	if d.vault, err = vault.Open(d.state(dirVault), tiers); err != nil {
		return nil, err
	}
	d.helper = helperlink.NewServer(d.identity, d.pairing)
	d.helper.OnRevokeAll = func() { d.RevokeAll("kill switch in the helper") }
	d.helper.OnConnect = func(up bool) {
		ev := "helper.disconnected"
		if up {
			ev = "helper.connected"
		}
		d.Audit(ev, nil)
	}
	if err := d.loadPolicy(); err != nil {
		d.log.Warn("policy not loaded", "err", err)
		d.Audit("policy.rejected", map[string]string{"reason": err.Error()})
	}
	d.grants.OnExpire = func(g *grants.Grant) { d.EndGrant(g, grants.Expired, "time to live reached") }

	transport := cfg.Transport
	if transport == nil {
		transport = proxy.DefaultTransport()
	}
	d.proxy = &proxy.Proxy{Backend: d, Transport: transport}
	d.proxy.SigV4 = d.sigV4Grant
	d.recover()
	d.Audit("daemon.started", map[string]string{"identity": hex.EncodeToString(fp(d.identity.Public().Bytes()))})
	return d, nil
}

func (d *Daemon) state(name string) string { return filepath.Join(d.cfg.StateDir, name) }

func fp(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:8]
}

// IdentityPublic returns the daemon's public identity key.
func (d *Daemon) IdentityPublic() *sig.PublicKey { return d.identity.Public() }

func loadOrCreateIdentity(path string) (*sig.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		defer clear(b)
		return sig.ParsePrivateKey(b)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	k, err := sig.GenerateKey()
	if err != nil {
		return nil, err
	}
	raw, err := k.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return k, vault.WriteFileAtomic(path, raw, 0o600)
}

// Audit appends to the audit log. Failures are logged; they do not stop the
// daemon, but they are visible to `vogt audit verify`.
func (d *Daemon) Audit(event string, fields map[string]string) {
	if err := d.audit.Append(event, fields); err != nil {
		d.log.Error("audit append failed", "event", event, "err", err)
	}
}

// Start opens the sockets and the proxy listener and serves until Close.
func (d *Daemon) Start(api http.Handler) error {
	apiL, err := listenUnix(filepath.Join(d.cfg.RunDir, SocketName), 0o660)
	if err != nil {
		return err
	}
	helperL, err := listenUnix(filepath.Join(d.cfg.RunDir, HelperSocketName), 0o660)
	if err != nil {
		apiL.Close()
		return err
	}
	proxyL, err := net.Listen("tcp", d.cfg.ProxyAddr)
	if err != nil {
		apiL.Close()
		helperL.Close()
		return err
	}
	d.mu.Lock()
	d.proxyBase = "http://" + proxyL.Addr().String()
	d.mu.Unlock()
	d.listeners = []net.Listener{apiL, helperL, proxyL}

	apiSrv := &http.Server{Handler: api, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
	proxySrv := &http.Server{Handler: d.proxy, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
	d.servers = []*http.Server{apiSrv, proxySrv}
	d.wg.Add(3)
	go func() { defer d.wg.Done(); apiSrv.Serve(apiL) }()
	go func() { defer d.wg.Done(); d.helper.Serve(helperL) }()
	go func() { defer d.wg.Done(); proxySrv.Serve(proxyL) }()
	go d.housekeeping()
	d.log.Info("vogt daemon started", "api", apiL.Addr(), "proxy", d.proxyBase)
	return nil
}

func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// ProxyBase returns the proxy's base URL, such as http://127.0.0.1:7853.
func (d *Daemon) ProxyBase() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.proxyBase
}

// Close revokes every grant, stops serving and closes the audit log.
func (d *Daemon) Close() error {
	d.RevokeAll("daemon stopping")
	for _, s := range d.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.Shutdown(ctx)
		cancel()
	}
	for _, l := range d.listeners {
		l.Close()
	}
	d.wg.Wait()
	d.Audit("daemon.stopped", nil)
	return d.audit.Close()
}

func (d *Daemon) housekeeping() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		d.grants.Prune(24 * time.Hour)
		d.expireBundles()
	}
}

// recover revokes credentials a previous run left live.
func (d *Daemon) recover() {
	left, err := d.journal.Recover()
	if err != nil {
		d.log.Error("journal recovery failed", "err", err)
		return
	}
	for _, lo := range left {
		a, err := d.adapters.Get(lo.Provider)
		status := "revoked"
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err = a.Revoke(ctx, lo.Handle)
			cancel()
		}
		clear(lo.Handle)
		if err != nil {
			status = "revoke failed: " + err.Error()
		}
		d.Audit("grant.recovered", map[string]string{"grant": lo.ID, "provider": lo.Provider, "result": status})
	}
}

// --- pairing and policy -----------------------------------------------------

func (d *Daemon) loadPairing() error {
	b, err := os.ReadFile(d.state(filePairing))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	k, err := helperlink.DecodeHelperKeys(b)
	if err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	d.pairing = k
	return nil
}

// Reload re-reads the pairing file, after `vogt pair` changed it.
func (d *Daemon) Reload() error {
	d.mu.Lock()
	old := d.pairing
	d.mu.Unlock()
	if err := d.loadPairing(); err != nil {
		return err
	}
	d.mu.Lock()
	k := d.pairing
	d.mu.Unlock()
	if k == nil || (old != nil && bytes.Equal(old.Encode(), k.Encode())) {
		return nil
	}
	d.helper.SetKeys(k)
	d.vault.SetKeys(vault.TierKeys{High: k.High, Low: k.Low})
	d.Audit("helper.paired", map[string]string{"fingerprint": hex.EncodeToString(fp(k.Encode()))})
	// A different helper cannot approve the old policy's signature.
	if err := d.loadPolicy(); err != nil {
		d.mu.Lock()
		d.pol = nil
		d.mu.Unlock()
	}
	return nil
}

const labelPolicySig = "vogt/v1/policy-approval"

func (d *Daemon) loadPolicy() error {
	raw, err := os.ReadFile(d.state(filePolicy))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	sigb, err := os.ReadFile(d.state(filePolicySig))
	if err != nil {
		return fmt.Errorf("policy signature: %w", err)
	}
	if d.pairing == nil {
		return ErrNotPaired
	}
	if err := verifyPolicySig(raw, sigb, d.pairing.Approval); err != nil {
		return err
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return err
	}
	if p.Version < d.maxPolicyVersion() {
		return fmt.Errorf("policy version %d is older than %d, the newest loaded", p.Version, d.maxPolicyVersion())
	}
	d.applyPolicy(p)
	return nil
}

func verifyPolicySig(raw, sigb []byte, approval *sig.PublicKey) error {
	dec := wire.NewDecoder(sigb, labelPolicySig)
	id, nonce, s := dec.ReadString(), dec.ReadBytes(), dec.ReadBytes()
	if err := dec.Finish(); err != nil || len(nonce) != 32 {
		return errors.New("policy signature is malformed")
	}
	var n [32]byte
	copy(n[:], nonce)
	msg := helperlink.ApprovalMessage(id, sha256.Sum256(raw), n, helperlink.Approve, 0)
	if approval.Verify(helperlink.PurposeApproval, msg, s) != nil {
		return errors.New("policy signature does not verify against the paired helper")
	}
	return nil
}

func (d *Daemon) maxPolicyVersion() uint64 {
	b, err := os.ReadFile(d.state(fileMaxVersion))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func (d *Daemon) applyPolicy(p *policy.Policy) {
	d.mu.Lock()
	d.pol = p
	d.mu.Unlock()
	d.sessions.SetLimits(session.Limits{
		MaxPendingPerSession: p.Limits.MaxPendingPerSession,
		MaxPendingTotal:      p.Limits.MaxPendingTotal,
		DenialsBeforeLock:    p.Limits.DenialsBeforeLock,
		DenialWindow:         time.Duration(p.Limits.DenialWindow),
	})
}

// Policy returns the loaded policy, or nil.
func (d *Daemon) Policy() *policy.Policy {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.pol
}

// PolicyRaw returns the loaded policy file.
func (d *Daemon) PolicyRaw() ([]byte, error) {
	if d.Policy() == nil {
		return nil, ErrNoPolicy
	}
	return os.ReadFile(d.state(filePolicy))
}

// LoadPolicy asks the human to approve a new policy and installs it.
func (d *Daemon) LoadPolicy(ctx context.Context, raw []byte) error {
	p, err := policy.Parse(raw)
	if err != nil {
		return err
	}
	cur := d.Policy()
	min := d.maxPolicyVersion() + 1
	if cur != nil && cur.Version+1 > min {
		min = cur.Version + 1
	}
	if p.Version < min {
		return fmt.Errorf("policy version must be at least %d", min)
	}
	res, err := d.askAdmin(ctx, policySummary(cur, p), sha256.Sum256(raw))
	if err != nil {
		return err
	}
	if !res.Approved {
		d.Audit("policy.denied", map[string]string{"version": strconv.FormatUint(p.Version, 10)})
		return errors.New("the human denied the policy")
	}
	dec := wire.NewDecoder(res.ApprovalMessage, "vogt/v1/hl-approval")
	id, _, nonce := dec.ReadString(), dec.ReadBytes(), dec.ReadBytes()
	sigFile := wire.NewEncoder(labelPolicySig).PutString(id).PutBytes(nonce).PutBytes(res.ApprovalSig).Finish()
	if err := vault.WriteFileAtomic(d.state(filePolicy), raw, 0o600); err != nil {
		return err
	}
	if err := vault.WriteFileAtomic(d.state(filePolicySig), sigFile, 0o600); err != nil {
		return err
	}
	if err := vault.WriteFileAtomic(d.state(fileMaxVersion), []byte(strconv.FormatUint(p.Version, 10)), 0o600); err != nil {
		return err
	}
	d.applyPolicy(p)
	d.Audit("policy.loaded", map[string]string{"version": strconv.FormatUint(p.Version, 10), "sha256": hex.EncodeToString(fp(raw))})
	return nil
}

func policySummary(old, p *policy.Policy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Load policy version %d", p.Version)
	if old != nil {
		fmt.Fprintf(&b, " (replacing version %d)", old.Version)
	}
	fmt.Fprintf(&b, "\n  %d capabilities, %d rules, %d forbidden permissions", len(p.Capabilities), len(p.Rules), len(p.Forbidden))
	if old != nil {
		var added, removed []string
		for n := range p.Capabilities {
			if _, ok := old.Capabilities[n]; !ok {
				added = append(added, n)
			}
		}
		for n := range old.Capabilities {
			if _, ok := p.Capabilities[n]; !ok {
				removed = append(removed, n)
			}
		}
		if len(added) > 0 {
			fmt.Fprintf(&b, "\n  Added: %s", strings.Join(provider.Sorted(added), ", "))
		}
		if len(removed) > 0 {
			fmt.Fprintf(&b, "\n  Removed: %s", strings.Join(provider.Sorted(removed), ", "))
		}
	}
	for _, r := range p.Rules {
		if r.Decision == policy.Allow {
			fmt.Fprintf(&b, "\n  Allows without a prompt: %s on %s", r.Capability, r.Target)
		}
	}
	return b.String()
}

func (d *Daemon) askAdmin(ctx context.Context, display string, digest [32]byte) (*helperlink.Result, error) {
	d.mu.RLock()
	paired := d.pairing != nil
	d.mu.RUnlock()
	if !paired {
		return nil, ErrNotPaired
	}
	return d.helper.Ask(ctx, helperlink.Challenge{Kind: helperlink.KindAdmin, Display: display, Digest: digest}, d.approvalTimeout())
}

func (d *Daemon) approvalTimeout() time.Duration {
	if p := d.Policy(); p != nil {
		return time.Duration(p.Limits.ApprovalTimeout)
	}
	return 60 * time.Second
}

// --- secrets -----------------------------------------------------------------

// AddSecret asks the human, then stores a secret. It wipes secret.
func (d *Daemon) AddSecret(ctx context.Context, id, providerName string, tier uint8, secret []byte) (vault.Meta, error) {
	defer clear(secret)
	if !vault.ValidID(id) {
		return vault.Meta{}, fmt.Errorf("invalid secret name %q", id)
	}
	if _, err := d.adapters.Get(providerName); err != nil {
		return vault.Meta{}, err
	}
	tierName := map[uint8]string{1: "high", 2: "low"}[tier]
	if tierName == "" {
		return vault.Meta{}, errors.New("tier must be high or low")
	}
	action := "Store new"
	if old, err := d.vault.Get(id); err == nil {
		action = fmt.Sprintf("REPLACE version %d of", old.KeyVersion)
	}
	h := sha256.Sum256(secret)
	digest := sha256.Sum256(wire.NewEncoder("vogt/v1/secret-add").PutString(id).PutString(providerName).PutUint(uint64(tier)).PutBytes(h[:]).Finish())
	display := fmt.Sprintf("%s secret %q\n  provider %s, %s tier, %d bytes", action, id, providerName, tierName, len(secret))
	res, err := d.askAdmin(ctx, display, digest)
	if err != nil {
		return vault.Meta{}, err
	}
	if !res.Approved {
		d.Audit("secret.denied", map[string]string{"secret": id})
		return vault.Meta{}, errors.New("the human denied storing the secret")
	}
	m, err := d.vault.Put(id, providerName, tierFrom(tier), secret)
	if err != nil {
		return vault.Meta{}, err
	}
	d.Audit("secret.stored", map[string]string{"secret": id, "provider": providerName, "tier": tierName, "version": strconv.FormatUint(m.KeyVersion, 10)})
	return m, nil
}

// DeleteSecret asks the human, then deletes a secret.
func (d *Daemon) DeleteSecret(ctx context.Context, id string) error {
	if _, err := d.vault.Get(id); err != nil {
		return err
	}
	res, err := d.askAdmin(ctx, fmt.Sprintf("DELETE secret %q", id), sha256.Sum256([]byte("vogt/v1/secret-delete/"+id)))
	if err != nil {
		return err
	}
	if !res.Approved {
		return errors.New("the human denied deleting the secret")
	}
	if err := d.vault.Delete(id); err != nil {
		return err
	}
	d.Audit("secret.deleted", map[string]string{"secret": id})
	return nil
}

// Secrets lists stored secrets without their contents.
func (d *Daemon) Secrets() ([]vault.Meta, error) { return d.vault.List() }

// --- sessions -------------------------------------------------------------

// CreateSession starts an agent session and returns its secret.
func (d *Daemon) CreateSession(name string) (string, *session.Session) {
	name = sanitize(name, 40)
	tok, s := d.sessions.Create(name)
	d.Audit("session.started", map[string]string{"session": s.ID, "name": name})
	return tok, s
}

// LookupSession finds a session by its secret.
func (d *Daemon) LookupSession(secret string) (*session.Session, error) {
	return d.sessions.Lookup(secret)
}

// EndSession revokes a session's grants and forgets it.
func (d *Daemon) EndSession(id string) {
	for _, g := range d.grants.List(id) {
		d.EndGrant(g, grants.Revoked, "session ended")
	}
	d.dropBundles(id)
	d.sessions.End(id)
	d.Audit("session.ended", map[string]string{"session": id})
}

// UnlockSession asks the human, then lifts a session's lockout.
func (d *Daemon) UnlockSession(ctx context.Context, id string) error {
	s, ok := d.sessions.Get(id)
	if !ok {
		return session.ErrUnknown
	}
	res, err := d.askAdmin(ctx, fmt.Sprintf("UNLOCK session %s (%s)", s.Name, short(s.ID)), sha256.Sum256([]byte("vogt/v1/unlock/"+id)))
	if err != nil {
		return err
	}
	if !res.Approved {
		return errors.New("the human denied the unlock")
	}
	d.Audit("session.unlocked", map[string]string{"session": id})
	return d.sessions.Unlock(id)
}

// Sessions lists live sessions.
func (d *Daemon) Sessions() []session.Session { return d.sessions.List() }

// --- status ----------------------------------------------------------------

// Status is a snapshot for `vogt status`.
type Status struct {
	Paired          bool   `json:"paired"`
	HelperConnected bool   `json:"helper_connected"`
	PolicyVersion   uint64 `json:"policy_version"`
	Sessions        int    `json:"sessions"`
	ActiveGrants    int    `json:"active_grants"`
	ProxyURL        string `json:"proxy_url"`
	Identity        string `json:"identity_fingerprint"`
}

// Status reports the daemon's state.
func (d *Daemon) Status() Status {
	s := Status{
		HelperConnected: d.helper.Connected(),
		Sessions:        len(d.sessions.List()),
		ProxyURL:        d.ProxyBase(),
		Identity:        hex.EncodeToString(fp(d.identity.Public().Bytes())),
	}
	d.mu.RLock()
	s.Paired = d.pairing != nil
	if d.pol != nil {
		s.PolicyVersion = d.pol.Version
	}
	d.mu.RUnlock()
	for _, g := range d.grants.Active() {
		if g.State == grants.Active {
			s.ActiveGrants++
		}
	}
	return s
}

// VerifyAudit checks the audit log's chain and checkpoint signatures.
func (d *Daemon) VerifyAudit() (audit.Result, error) {
	return audit.Verify(d.state(fileAudit), d.identity.Public())
}

// AuditPath is the audit log's location.
func (d *Daemon) AuditPath() string { return d.state(fileAudit) }

func tierFrom(t uint8) tierT { return tierT(t) }

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// sanitize drops control characters and truncates, so agent-supplied text
// cannot forge lines on the approval screen.
func sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}
