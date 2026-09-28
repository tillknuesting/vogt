package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"vogt/internal/grants"
	"vogt/internal/policy"
	"vogt/internal/token"
)

// CA is the local certificate authority for the TLS-interception fallback.
// Its name constraints limit it to the hosts in the policy, so even if its
// key leaks it cannot impersonate any other site to a client that honours
// name constraints (Go, BoringSSL, OpenSSL and Apple's TLS all do).
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA makes a CA constrained to hosts, valid for a year.
func NewCA(hosts []string) (*CA, error) {
	if len(hosts) == 0 {
		return nil, errors.New("proxy: a CA needs at least one host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "Vogt local interception CA"},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().AddDate(1, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// PEM returns the certificate and the PKCS#8 private key, PEM-encoded.
func (c *CA) PEM() (certPEM, keyPEM []byte, err error) {
	k, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), nil
}

// ParseCA reads a CA written by PEM.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("proxy: bad CA PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("proxy: CA key is not ECDSA")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Hosts returns the CA's permitted hosts.
func (c *CA) Hosts() []string { return c.Cert.PermittedDNSDomains }

// Leaf issues a 24-hour certificate for host.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: key}, nil
}

// Interceptor serves CONNECT requests by terminating TLS for approved hosts.
type Interceptor struct {
	Proxy *Proxy
	CA    func() *CA // current CA; it changes when the policy's hosts do

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func (ic *Interceptor) leaf(ca *CA, host string) (*tls.Certificate, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.leaves == nil {
		ic.leaves = map[string]*tls.Certificate{}
	}
	key := string(ca.Cert.Raw[:16]) + host
	if l := ic.leaves[key]; l != nil && time.Until(l.Leaf.NotAfter) > time.Hour {
		return l, nil
	}
	l, err := ca.Leaf(host)
	if err != nil {
		return nil, err
	}
	l.Leaf, _ = x509.ParseCertificate(l.Certificate[0])
	ic.leaves[key] = l
	return l, nil
}

// interceptRest maps a request to host+path onto the route path the grant's
// credential and allow rules expect.
func interceptRest(g *grants.Grant, host, path string) (string, error) {
	switch g.Provider {
	case "github":
		switch host {
		case "api.github.com":
			return "/api" + path, nil
		case "github.com":
			return "/git" + path, nil
		}
		return "", fmt.Errorf("github grants cover api.github.com and github.com, not %s", host)
	case "static", "oauth":
		if !strings.HasSuffix(g.Cap.Upstream, "://"+host) && !strings.Contains(g.Cap.Upstream, "://"+host+"/") {
			return "", fmt.Errorf("grant's upstream is not %s", host)
		}
		return path, nil
	}
	return "", fmt.Errorf("%s grants cannot use TLS interception", g.Provider)
}

func (ic *Interceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca := ic.CA()
	if ca == nil {
		http.Error(w, "vogt: no interception CA", http.StatusServiceUnavailable)
		return
	}
	tok := extractToken(r)
	if k, ok := token.Parse(tok); !ok || k != token.Proxy {
		w.Header().Set("Proxy-Authenticate", `Basic realm="vogt"`)
		http.Error(w, "vogt: broker token required", http.StatusProxyAuthRequired)
		return
	}
	hash := token.Hash(tok)
	g, ok := ic.Proxy.Backend.GrantByToken(hash)
	host, port, err := net.SplitHostPort(r.Host)
	switch {
	case !ok:
		http.Error(w, "vogt: unknown or ended grant", http.StatusProxyAuthRequired)
		return
	case err != nil || port != "443":
		http.Error(w, "vogt: only port 443 is intercepted", http.StatusForbidden)
		return
	case g.Mode != policy.ModeProxy || !slices.Contains(g.Cap.Hosts, host) || !slices.Contains(ca.Hosts(), host):
		ic.Proxy.Backend.Audit("proxy.refused", map[string]string{"grant": g.ID, "connect": host})
		http.Error(w, "vogt: host is not covered by the grant", http.StatusForbidden)
		return
	}
	cert, err := ic.leaf(ca, host)
	if err != nil {
		http.Error(w, "vogt: cannot issue certificate", http.StatusInternalServerError)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "vogt: cannot hijack", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || brw.Flush() != nil {
		return
	}
	tc := tls.Server(&bufConn{Conn: conn, r: brw.Reader}, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hi.ServerName != "" && hi.ServerName != host {
				return nil, errors.New("SNI does not match the CONNECT host")
			}
			return cert, nil
		},
		NextProtos: []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		return
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g, ok := ic.Proxy.Backend.GrantByToken(hash)
		if !ok || !ic.Proxy.now().Before(g.NotAfter) {
			http.Error(w, "vogt: grant ended", http.StatusUnauthorized)
			return
		}
		if !safePath(r) {
			http.Error(w, "vogt: path is not canonical", http.StatusBadRequest)
			return
		}
		rest, err := interceptRest(g, host, r.URL.Path)
		if err != nil || !g.Cap.Permits(r.Method, rest, g.Target) {
			ic.Proxy.Backend.Audit("proxy.refused", map[string]string{"grant": g.ID, "method": r.Method, "host": host, "path": r.URL.Path})
			http.Error(w, "vogt: request is outside the grant", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(rest, "/git-receive-pack") {
			if err := filterPush(r, g.DenyRefs); err != nil {
				http.Error(w, "vogt: "+err.Error(), http.StatusForbidden)
				return
			}
		}
		ic.Proxy.Forward(w, r, g, rest)
	})
	srv := &http.Server{Handler: inner, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
	srv.Serve(&oneConn{c: tc})
}

// bufConn replays bytes the HTTP server had already buffered.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// oneConn is a listener that yields one connection, then blocks until it
// closes.
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
	mu   sync.Mutex
}

func (o *oneConn) Accept() (net.Conn, error) {
	o.mu.Lock()
	if o.done == nil {
		o.done = make(chan struct{})
	}
	done := o.done
	o.mu.Unlock()
	var c net.Conn
	o.once.Do(func() { c = &closeNotify{Conn: o.c, done: done} })
	if c != nil {
		return c, nil
	}
	<-done
	return nil, net.ErrClosed
}

func (o *oneConn) Close() error   { return nil }
func (o *oneConn) Addr() net.Addr { return o.c.LocalAddr() }

type closeNotify struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
