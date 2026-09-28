package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"vogt/internal/grants"
	"vogt/internal/webauthn"
)

type pageClient struct {
	t      *testing.T
	addr   string // 127.0.0.1:port
	origin string // http://localhost:port
}

func (p *pageClient) do(method, path string, body any, out any) int {
	p.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, "http://"+p.addr+path, rd)
	req.Host = strings.TrimPrefix(p.origin, "http://")
	req.Header.Set("Origin", p.origin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestPhoneApproval(t *testing.T) {
	e := newEnvWith(t, func(c *Config) { c.WebAuthnAddr = "127.0.0.1:0" })
	pc := &pageClient{t: t, addr: e.d.listeners[len(e.d.listeners)-1].Addr().String(), origin: e.d.ph.origin}

	// The page refuses any other Host, which stops DNS rebinding.
	req, _ := http.NewRequest("GET", "http://"+pc.addr+"/api/pending", nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("raw IP host: %s", r.Status)
	}

	// Enroll a passkey; the helper's tap unwraps the secrets once.
	u, err := e.d.StartEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	token := u[strings.Index(u, "#t=")+3:]
	var opts struct{ Challenge, UserID, PRFSalt string }
	var raw map[string]string
	if pc.do("GET", "/api/enroll?t="+token, nil, &raw) != 200 {
		t.Fatal("enroll options")
	}
	opts.Challenge, opts.PRFSalt = raw["challenge"], raw["prf_salt"]
	dec := func(s string) []byte { b, _ := b64.DecodeString(s); return b }
	auth := webauthn.NewSoftAuthenticator()
	cd, ad, spki := auth.Register(dec(opts.Challenge), pc.origin, rpID)
	prf := auth.PRF(dec(opts.PRFSalt))
	if code := pc.do("POST", "/api/enroll", map[string]any{
		"t": token, "name": "test phone", "client_data": b64.EncodeToString(cd), "authenticator_data": b64.EncodeToString(ad),
		"public_key": b64.EncodeToString(spki), "alg": webauthn.AlgES256, "prf": b64.EncodeToString(prf),
	}, nil); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	if n := len(e.d.WebAuthnCredentials()); n != 1 {
		t.Fatalf("%d credentials", n)
	}

	// The Mac's helper goes away.
	e.helperC.Close()
	for i := 0; e.d.helper.Connected() && i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
	}

	_, s := e.d.CreateSession("claude")
	g, err := e.d.RequestGrant(s, GrantRequest{Capability: "github.repo.push", Target: "tillknuesting/vogt"})
	if err != nil {
		t.Fatal(err)
	}
	var pending []struct {
		ID, Display, Challenge string
		Allow                  []struct{ ID, Salt string }
	}
	for i := 0; len(pending) == 0 && i < 100; i++ {
		pc.do("GET", "/api/pending", nil, &pending)
		time.Sleep(20 * time.Millisecond)
	}
	if len(pending) != 1 || !strings.Contains(pending[0].Display, "PUSH to github.com/tillknuesting/vogt") || len(pending[0].Allow) != 1 {
		t.Fatalf("pending = %+v", pending)
	}
	p := pending[0]

	// A signature over a different challenge is refused.
	cd, ad, sig := auth.Assert([]byte("not the challenge"), pc.origin, rpID)
	if code := pc.do("POST", "/api/decide", map[string]any{"id": p.ID, "approve": true, "credential_id": p.Allow[0].ID,
		"client_data": b64.EncodeToString(cd), "authenticator_data": b64.EncodeToString(ad), "signature": b64.EncodeToString(sig),
		"prf": b64.EncodeToString(auth.PRF(dec(p.Allow[0].Salt)))}, nil); code != 403 {
		t.Fatalf("forged assertion: %d", code)
	}

	cd, ad, sig = auth.Assert(dec(p.Challenge), pc.origin, rpID)
	if code := pc.do("POST", "/api/decide", map[string]any{"id": p.ID, "approve": true, "credential_id": p.Allow[0].ID,
		"client_data": b64.EncodeToString(cd), "authenticator_data": b64.EncodeToString(ad), "signature": b64.EncodeToString(sig),
		"prf": b64.EncodeToString(auth.PRF(dec(p.Allow[0].Salt)))}, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	v, _ := e.d.WaitGrant(context.Background(), s, g.ID, 10*time.Second)
	if v.State != grants.Active || v.Delivery == nil {
		t.Fatalf("grant after phone approval = %+v", v)
	}
	if r := e.proxyDo("GET", "/github/api/repos/tillknuesting/vogt", map[string]string{"Authorization": "Bearer " + v.Delivery.Token}, nil); r.StatusCode != 200 {
		t.Fatalf("proxy after phone approval: %s", r.Status)
	}
}
