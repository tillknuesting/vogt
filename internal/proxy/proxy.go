// Package proxy is Vogt's egress proxy. An agent sends requests to
// http://127.0.0.1:<port>/<route>/... with its broker token where the
// provider's key would normally go. The proxy finds the grant, checks the
// request against it, swaps in the real credential and forwards upstream.
package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"vogt/internal/grants"
	"vogt/internal/policy"
	"vogt/internal/provider"
	"vogt/internal/token"
)

// Backend is what the proxy needs from the daemon.
type Backend interface {
	GrantByToken(hash [32]byte) (*grants.Grant, bool)
	GrantByID(id string) (*grants.Grant, bool)
	Audit(event string, fields map[string]string)
}

// Proxy serves proxied requests.
type Proxy struct {
	Backend   Backend
	Transport http.RoundTripper
	// SigV4 authenticates AWS-signed requests. It returns the grant whose ID
	// is the access key and whose broker token signed the request.
	SigV4 func(r *http.Request) (*grants.Grant, error)
	// Intercept handles CONNECT for the TLS-interception fallback. Nil
	// disables it.
	Intercept http.Handler
	Now       func() time.Time
}

// DefaultTransport is the upstream transport: TLS 1.2 or later, with Go's
// default hybrid post-quantum key exchanges, no proxy from the environment.
func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func fail(code int, format string, args ...any) error {
	return &httpError{code, fmt.Sprintf(format, args...)}
}

func (p *Proxy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if p.Intercept == nil {
			http.Error(w, "vogt: CONNECT is disabled", http.StatusMethodNotAllowed)
			return
		}
		p.Intercept.ServeHTTP(w, r)
		return
	}
	g, rest, err := p.Authorize(r)
	if err != nil {
		var he *httpError
		code := http.StatusForbidden
		if errors.As(err, &he) {
			code = he.code
		}
		if code == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="vogt"`)
		}
		p.Backend.Audit("proxy.refused", map[string]string{"method": r.Method, "path": r.URL.Path, "reason": err.Error()})
		http.Error(w, "vogt: "+err.Error(), code)
		return
	}
	p.Forward(w, r, g, rest)
}

// Authorize finds and checks the grant for a request. It returns the grant
// and the request path after the route prefix.
func (p *Proxy) Authorize(r *http.Request) (*grants.Grant, string, error) {
	// A browser page must never drive the proxy.
	if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		return nil, "", fail(http.StatusForbidden, "browser requests are refused")
	}
	if !safePath(r) {
		return nil, "", fail(http.StatusBadRequest, "path is not canonical")
	}
	route, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !ok || route == "" {
		return nil, "", fail(http.StatusNotFound, "no route")
	}
	rest = "/" + rest

	g, err := p.grantFor(r)
	if err != nil {
		return nil, "", err
	}
	if g.Route != route {
		return nil, "", fail(http.StatusForbidden, "grant is for route %q", g.Route)
	}
	if g.Mode != policy.ModeProxy {
		return nil, "", fail(http.StatusForbidden, "grant is not a proxy grant")
	}
	if !p.now().Before(g.NotAfter) {
		return nil, "", fail(http.StatusUnauthorized, "grant expired")
	}
	if !g.Cap.Permits(r.Method, rest, g.Target) {
		return nil, "", fail(http.StatusForbidden, "%s %s is outside the grant", r.Method, rest)
	}
	if r.Method == http.MethodPost && strings.HasSuffix(rest, "/git-receive-pack") {
		if err := filterPush(r, g.DenyRefs); err != nil {
			return nil, "", fail(http.StatusForbidden, "%v", err)
		}
	}
	return g, rest, nil
}

func (p *Proxy) grantFor(r *http.Request) (*grants.Grant, error) {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		if p.SigV4 == nil {
			return nil, fail(http.StatusForbidden, "AWS signing is not enabled")
		}
		g, err := p.SigV4(r)
		if err != nil {
			return nil, fail(http.StatusForbidden, "%v", err)
		}
		return g, nil
	}
	tok := extractToken(r)
	if tok == "" {
		return nil, fail(http.StatusUnauthorized, "no broker token")
	}
	if k, ok := token.Parse(tok); !ok || k != token.Proxy {
		return nil, fail(http.StatusUnauthorized, "malformed broker token")
	}
	g, ok := p.Backend.GrantByToken(token.Hash(tok))
	if !ok {
		return nil, fail(http.StatusUnauthorized, "unknown or ended grant")
	}
	return g, nil
}

// extractToken looks for a broker token wherever clients put API keys.
func extractToken(r *http.Request) string {
	for _, h := range []string{"Authorization", "Proxy-Authorization"} {
		v := r.Header.Get(h)
		scheme, val, _ := strings.Cut(v, " ")
		switch strings.ToLower(scheme) {
		case "bearer", "token":
			return strings.TrimSpace(val)
		case "basic":
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(val))
			if err == nil {
				if _, pass, ok := strings.Cut(string(raw), ":"); ok {
					return pass
				}
			}
		}
	}
	for _, h := range []string{"X-Api-Key", "Api-Key"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

// safePath refuses dot segments, doubled slashes and encoded slashes, so the
// path that is checked is the path that is forwarded.
func safePath(r *http.Request) bool {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, "\\") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	raw := strings.ToLower(r.URL.RawPath)
	return !strings.Contains(raw, "%2f") && !strings.Contains(raw, "%5c") && !strings.Contains(raw, "%2e")
}

// Forward sends an authorized request upstream with the grant's credential.
func (p *Proxy) Forward(w http.ResponseWriter, r *http.Request, g *grants.Grant, rest string) {
	var target, status string
	rp := &httputil.ReverseProxy{
		Transport: p.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			for _, h := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key", "Cookie", "Forwarded"} {
				out.Header.Del(h)
			}
			for k := range out.Header {
				if strings.HasPrefix(strings.ToLower(k), "x-forwarded-") {
					out.Header.Del(k)
				}
			}
			for k := range out.Header {
				if strings.HasPrefix(strings.ToLower(k), "x-vogt-") {
					out.Header.Del(k)
				}
			}
			if g.Provider == "aws" {
				if h, err := provider.ParseSigV4(pr.In.Header.Get("Authorization")); err == nil {
					out.Header.Set("X-Vogt-Aws-Scope", h.Region+"/"+h.Service)
				}
			}
			if err := g.Cred.Inject(out, rest); err != nil {
				out.URL.Host = "invalid.invalid" // fails the round trip
				out.Header.Set("X-Vogt-Error", err.Error())
			}
			target = out.URL.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			for k := range resp.Header {
				if strings.HasPrefix(strings.ToLower(k), "access-control-") {
					resp.Header.Del(k)
				}
			}
			status = resp.Status
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status = "502"
			http.Error(w, "vogt: upstream request failed", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
	p.Backend.Audit("proxy.call", map[string]string{
		"grant": g.ID, "method": r.Method, "host": target, "path": rest, "status": status,
	})
}
