package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vogt/internal/grants"
	"vogt/internal/helperlink"
	"vogt/internal/policy"
	"vogt/internal/provider"
	"vogt/internal/session"
	"vogt/internal/softhelper"
)

// fakeGitHub plays api.github.com and github.com.
type fakeGitHub struct {
	srv     *httptest.Server
	appKey  *rsa.PrivateKey
	mu      sync.Mutex
	tokens  map[string]bool // live installation tokens
	revoked []string
	pushes  []string
	minted  []map[string]any
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{tokens: map[string]bool{}}
	var err error
	if f.appKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	m := http.NewServeMux()
	m.HandleFunc("POST /app/installations/42/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
			http.Error(w, "no jwt", 401)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		tok := fmt.Sprintf("ghs_fake_%d", time.Now().UnixNano())
		f.mu.Lock()
		f.tokens[tok] = true
		f.minted = append(f.minted, body)
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	})
	m.HandleFunc("DELETE /installation/token", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
		f.mu.Lock()
		delete(f.tokens, tok)
		f.revoked = append(f.revoked, tok)
		f.mu.Unlock()
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		if !f.live(strings.TrimPrefix(r.Header.Get("Authorization"), "token ")) {
			http.Error(w, "bad token", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"full_name": r.PathValue("owner") + "/" + r.PathValue("repo")})
	})
	m.HandleFunc("POST /{owner}/{repo}/git-receive-pack", func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != "x-access-token" || !f.live(pass) {
			http.Error(w, "bad token", 401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.pushes = append(f.pushes, string(b))
		f.mu.Unlock()
		w.Write([]byte("0000"))
	})
	f.srv = httptest.NewTLSServer(m)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) live(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[tok]
}

func (f *fakeGitHub) master(t *testing.T) []byte {
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.appKey)})
	b, _ := json.Marshal(map[string]string{"app_id": "7", "installation_id": "42", "private_key": string(pemKey)})
	return b
}

type env struct {
	t        *testing.T
	d        *Daemon
	cfg      Config
	gh       *fakeGitHub
	static   *httptest.Server
	staticIn chan http.Header
	keys     *softhelper.Keys
	approver *softhelper.Auto
	client   *http.Client
}

func testPolicy(staticURL string) []byte {
	var p map[string]any
	json.Unmarshal(policy.Example, &p)
	caps := p["capabilities"].(map[string]any)
	oa := caps["openai.api"].(map[string]any)
	oa["upstream"] = staticURL
	oa["modes"] = []string{"proxy", "reveal"}
	caps["github.admin.bad"] = map[string]any{
		"provider": "github", "secret": "github-write", "route": "github", "display": "ADMIN {target}",
		"scope": map[string]any{"permissions": map[string]string{"workflows": "write"}},
	}
	b, _ := json.Marshal(p)
	return b
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, gh: newFakeGitHub(t), staticIn: make(chan http.Header, 8), approver: &softhelper.Auto{Yes: true}}
	e.static = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.staticIn <- r.Header.Clone()
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(e.static.Close)

	var err error
	if e.keys, err = softhelper.Generate(); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "vogt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	state := filepath.Join(base, "state")
	os.MkdirAll(state, 0o700)
	if err := os.WriteFile(filepath.Join(state, filePairing), e.keys.Public().Encode(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Both fake upstreams use httptest's certificate; trust it everywhere.
	transport := e.gh.srv.Client().Transport.(*http.Transport).Clone()
	client := &http.Client{Transport: transport}
	adapters := provider.Registry{
		"github": &provider.GitHub{APIBase: e.gh.srv.URL, GitBase: e.gh.srv.URL, Client: client},
		"static": provider.Static{},
	}
	e.cfg = Config{StateDir: state, RunDir: filepath.Join(base, "run"), ProxyAddr: "127.0.0.1:0", Adapters: adapters, Transport: transport}
	e.start()

	ctx := context.Background()
	if err := e.d.LoadPolicy(ctx, testPolicy(e.static.URL)); err != nil {
		t.Fatal("load policy:", err)
	}
	if _, err := e.d.AddSecret(ctx, "github-write", "github", 1, e.gh.master(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.AddSecret(ctx, "github-read", "github", 2, e.gh.master(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.AddSecret(ctx, "openai", "static", 1, []byte("sk-real-openai-key")); err != nil {
		t.Fatal(err)
	}
	e.approver.Seen = nil
	return e
}

// start runs a daemon on the env's state and connects the soft helper.
func (e *env) start() {
	t := e.t
	d, err := New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.d = d
	up := make(chan bool, 4)
	d.helper.OnConnect = func(ok bool) { up <- ok }
	if err := d.Start(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	fp := helperlink.Fingerprint(d.IdentityPublic().Bytes())
	cl := &helperlink.Client{Keyring: e.keys, Approver: e.approver, DaemonPin: &fp}
	c, err := net.Dial("unix", filepath.Join(e.cfg.RunDir, HelperSocketName))
	if err != nil {
		t.Fatal(err)
	}
	go cl.Serve(c)
	select {
	case <-up:
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not connect")
	}
}

func (e *env) grant(s *session.Session, req GrantRequest) grants.View {
	e.t.Helper()
	g, err := e.d.RequestGrant(s, req)
	if err != nil {
		e.t.Fatal(err)
	}
	v, err := e.d.WaitGrant(context.Background(), s, g.ID, 10*time.Second)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) proxyDo(method, path string, hdr map[string]string, body io.Reader) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.d.ProxyBase()+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func pushBody(ref string) string {
	return pkt("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 "+ref+"\x00report-status\n") + "0000PACK..."
}

func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("vogt:"+tok))
}

func TestPushThroughProxy(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	v := e.grant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt", Reason: "push the fix"})
	if v.State != grants.Active || v.Delivery == nil {
		t.Fatalf("grant = %+v", v)
	}
	tok := v.Delivery.Token

	seen := e.approver.Challenges()
	if len(seen) != 1 || !strings.Contains(seen[0].Display, "PUSH to github.com/tillknuesting/vogt") || !strings.Contains(seen[0].Display, `"push the fix" [unverified]`) {
		t.Fatalf("approval screen = %+v", seen)
	}

	// A push to a feature branch goes through with the real token upstream.
	resp := e.proxyDo("POST", "/github/git/tillknuesting/vogt.git/git-receive-pack", map[string]string{"Authorization": basic(tok)}, strings.NewReader(pushBody("refs/heads/feature")))
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("push: %s %s", resp.Status, b)
	}
	e.gh.mu.Lock()
	pushed := len(e.gh.pushes) == 1 && strings.Contains(e.gh.pushes[0], "refs/heads/feature")
	e.gh.mu.Unlock()
	if !pushed {
		t.Fatal("upstream did not receive the push")
	}

	// main is protected by deny_refs.
	resp = e.proxyDo("POST", "/github/git/tillknuesting/vogt.git/git-receive-pack", map[string]string{"Authorization": basic(tok)}, strings.NewReader(pushBody("refs/heads/main")))
	if resp.StatusCode != 403 {
		t.Fatalf("push to main: %s", resp.Status)
	}

	// The API works for the granted repo only.
	if r := e.proxyDo("GET", "/github/api/repos/tillknuesting/vogt", map[string]string{"Authorization": "Bearer " + tok}, nil); r.StatusCode != 200 {
		t.Fatalf("api: %s", r.Status)
	}
	if r := e.proxyDo("GET", "/github/api/repos/someone/else", map[string]string{"Authorization": "Bearer " + tok}, nil); r.StatusCode != 403 {
		t.Fatalf("other repo: %s", r.Status)
	}

	// Minted token was scoped to the one repository.
	e.gh.mu.Lock()
	repos := e.gh.minted[0]["repositories"]
	e.gh.mu.Unlock()
	if fmt.Sprint(repos) != "[vogt]" {
		t.Fatalf("minted for %v", repos)
	}

	// Surrender: the proxy refuses at once and GitHub is told to revoke.
	if err := e.d.SurrenderGrant(s, v.ID); err != nil {
		t.Fatal(err)
	}
	if r := e.proxyDo("GET", "/github/api/repos/tillknuesting/vogt", map[string]string{"Authorization": "Bearer " + tok}, nil); r.StatusCode != 401 {
		t.Fatalf("after surrender: %s", r.Status)
	}
	e.gh.mu.Lock()
	revoked := len(e.gh.revoked)
	e.gh.mu.Unlock()
	if revoked != 1 {
		t.Fatalf("upstream revocations = %d", revoked)
	}
}

func TestLowTierReadNeedsNoTap(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	v := e.grant(s, GrantRequest{Capability: "github.repo.read", Target: "tillknuesting/vogt"})
	if v.State != grants.Active {
		t.Fatalf("state = %s (%s)", v.State, v.EndReason)
	}
	if n := len(e.approver.Challenges()); n != 0 {
		t.Fatalf("human was asked %d times", n)
	}
	// Reading another owner's repo is not auto-allowed: it asks.
	e.grant(s, GrantRequest{Capability: "github.repo.read", Target: "someone/else"})
	if n := len(e.approver.Challenges()); n != 1 {
		t.Fatalf("human was asked %d times for a non-allowed target", n)
	}
}

func TestDenialsLockSession(t *testing.T) {
	e := newEnv(t)
	e.approver.Yes = false
	_, s := e.d.CreateSession("claude")
	for i := range 3 {
		v := e.grant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt"})
		if v.State != grants.Denied {
			t.Fatalf("attempt %d: %s", i, v.State)
		}
	}
	v := e.grant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt"})
	if v.State != grants.Denied || !strings.Contains(v.EndReason, "locked") {
		t.Fatalf("fourth attempt = %+v", v)
	}
	if n := len(e.approver.Challenges()); n != 3 {
		t.Fatalf("human was asked %d times", n)
	}
}

func TestStaticKeyNeverReachesAgent(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	v := e.grant(s, GrantRequest{Capability: "openai.api", Target: "default"})
	if v.State != grants.Active {
		t.Fatalf("state = %s (%s)", v.State, v.EndReason)
	}
	for _, kv := range v.Delivery.Env {
		if strings.Contains(kv, "sk-real") {
			t.Fatal("real key in the agent's environment")
		}
	}
	r := e.proxyDo("POST", "/openai/v1/chat/completions", map[string]string{"Authorization": "Bearer " + v.Delivery.Token}, strings.NewReader("{}"))
	if r.StatusCode != 200 {
		t.Fatalf("call: %s", r.Status)
	}
	h := <-e.staticIn
	if h.Get("Authorization") != "Bearer sk-real-openai-key" {
		t.Fatalf("upstream auth = %q", h.Get("Authorization"))
	}
	if strings.Contains(fmt.Sprint(h), v.Delivery.Token) {
		t.Fatal("broker token forwarded upstream")
	}
}

func TestProxyRefusals(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	v := e.grant(s, GrantRequest{Capability: "openai.api"})
	auth := map[string]string{"Authorization": "Bearer " + v.Delivery.Token}
	cases := []struct {
		name string
		path string
		hdr  map[string]string
		want int
	}{
		{"no token", "/openai/v1/models", nil, 401},
		{"wrong route", "/github/api/repos/tillknuesting/vogt", auth, 403},
		{"dot segments", "/openai/v1/../../admin", auth, 400},
		{"browser origin", "/openai/v1/models", map[string]string{"Authorization": auth["Authorization"], "Origin": "https://evil.example"}, 403},
		{"forged token", "/openai/v1/models", map[string]string{"Authorization": "Bearer vogt_p_aaaa"}, 401},
	}
	for _, c := range cases {
		if r := e.proxyDo("GET", c.path, c.hdr, nil); r.StatusCode != c.want {
			t.Errorf("%s: %s, want %d", c.name, r.Status, c.want)
		}
	}
}

func TestPolicyRules(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	if _, err := e.d.RequestGrant(s, GrantRequest{Capability: "github.admin.bad", Target: "tillknuesting/vogt"}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("workflows write: %v", err)
	}
	if _, err := e.d.RequestGrant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt", Mode: policy.ModeDirect}); err == nil {
		t.Error("direct mode without a command was accepted")
	}
	if _, err := e.d.RequestGrant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt", TTL: "2h"}); err == nil {
		t.Error("TTL above the rule's max was accepted")
	}
	// Direct mode shows the command and the worst case on the approval screen.
	v := e.grant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt", Mode: policy.ModeDirect, Command: []string{"git", "push"}})
	if v.State != grants.Active || v.WorstCase.IsZero() {
		t.Fatalf("direct grant = %+v", v)
	}
	last := e.approver.Challenges()
	if d := last[len(last)-1].Display; !strings.Contains(d, "HOLD the credential, via: git push") || !strings.Contains(d, "if Vogt cannot revoke") {
		t.Fatalf("direct approval screen:\n%s", d)
	}
	// Policy rollback is refused.
	if err := e.d.LoadPolicy(context.Background(), testPolicy(e.static.URL)); err == nil {
		t.Error("reloading the same version was accepted")
	}
}

func TestTamperedPolicyIsNotLoaded(t *testing.T) {
	e := newEnv(t)
	e.d.Close()
	path := filepath.Join(e.cfg.StateDir, filePolicy)
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(raw, []byte(`"ask"`), []byte(`"allow"`), -1), 0o600)
	e.start()
	if e.d.Policy() != nil {
		t.Fatal("tampered policy was loaded")
	}
	_, s := e.d.CreateSession("claude")
	if _, err := e.d.RequestGrant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt"}); err == nil {
		t.Fatal("grant issued without a valid policy")
	}
}

func TestCrashRecoveryRevokes(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	e.grant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt"})
	// Simulate a crash: stop serving without revoking anything.
	for _, l := range e.d.listeners {
		l.Close()
	}
	for _, srv := range e.d.servers {
		srv.Close()
	}
	e.d.audit.Close()
	e.gh.mu.Lock()
	before := len(e.gh.revoked)
	e.gh.mu.Unlock()
	e.start()
	e.gh.mu.Lock()
	after := len(e.gh.revoked)
	e.gh.mu.Unlock()
	if after != before+1 {
		t.Fatalf("revocations after restart = %d, want %d", after, before+1)
	}
}

func TestRevokeAllAndAudit(t *testing.T) {
	e := newEnv(t)
	_, s := e.d.CreateSession("claude")
	v := e.grant(s, GrantRequest{Capability: "openai.api"})
	if n := e.d.RevokeAll("test"); n != 1 {
		t.Fatalf("revoked %d", n)
	}
	if r := e.proxyDo("GET", "/openai/v1/models", map[string]string{"Authorization": "Bearer " + v.Delivery.Token}, nil); r.StatusCode != 401 {
		t.Fatalf("after revoke-all: %s", r.Status)
	}
	res, err := e.d.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries < 5 {
		t.Fatalf("audit has %d entries", res.Entries)
	}
	raw, _ := os.ReadFile(e.d.AuditPath())
	if bytes.Contains(raw, []byte(v.Delivery.Token)) || bytes.Contains(raw, []byte("sk-real")) {
		t.Fatal("audit log contains a secret")
	}
}
