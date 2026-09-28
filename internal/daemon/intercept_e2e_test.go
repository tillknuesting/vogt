package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"vogt/internal/grants"
	"vogt/internal/proxy"
)

func TestTLSInterception(t *testing.T) {
	e := newEnv(t)
	// Upstream "api.openai.com" is the fake static server.
	fake := e.static.Listener.Addr().String()
	e.d.proxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, fake)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test only: the fake has no api.openai.com certificate
	}
	var p map[string]any
	raw, _ := e.d.PolicyRaw()
	json.Unmarshal(raw, &p)
	p["version"] = 2
	p["capabilities"].(map[string]any)["intercept.api"] = map[string]any{
		"provider": "static", "secret": "openai", "route": "icpt", "upstream": "https://api.openai.com",
		"display": "CALL OpenAI through interception", "hosts": []string{"api.openai.com"},
		"scope": map[string]any{"header": "Authorization", "format": "Bearer {key}"},
		"allow": []map[string]any{{"methods": []string{"POST"}, "path": "/v1/**"}},
	}
	b, _ := json.Marshal(p)
	if err := e.d.LoadPolicy(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	caPEM, err := e.d.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	_, s := e.d.CreateSession("claude")
	v := e.grant(s, GrantRequest{Capability: "intercept.api"})
	if v.State != grants.Active {
		t.Fatalf("grant = %+v", v)
	}
	proxyURL, _ := url.Parse(e.d.ProxyBase())
	proxyURL.User = url.UserPassword("vogt", v.Delivery.Token)
	agent := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	defer agent.CloseIdleConnections()

	resp, err := agent.Post("https://api.openai.com/v1/chat/completions", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("intercepted call: %s %s", resp.Status, body)
	}
	if h := <-e.staticIn; h.Get("Authorization") != "Bearer sk-real-openai-key" {
		t.Fatalf("upstream auth = %q", h.Get("Authorization"))
	}

	// Paths outside the grant are refused inside the tunnel too.
	resp, err = agent.Get("https://api.openai.com/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("GET outside allow rules: %s", resp.Status)
	}

	// Other hosts get no tunnel.
	if _, err := agent.Get("https://evil.example.com/"); err == nil {
		t.Fatal("CONNECT to a host outside the grant succeeded")
	}

	// Even with the CA key, a certificate for another host does not verify.
	ca, _ := proxy.ParseCA(caPEM, mustKeyPEM(t, e))
	leaf, err := ca.Leaf("evil.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(leaf.Certificate[0])
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "evil.example.com"}); err == nil {
		t.Fatal("name constraints did not stop a certificate for another host")
	}
}

func mustKeyPEM(t *testing.T, e *env) []byte {
	_, k, err := e.d.currentCA().PEM()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
