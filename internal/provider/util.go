package provider

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// SignJWTRS256 builds a compact JWT signed with an RSA key.
func SignJWTRS256(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	digest := sha256.Sum256([]byte(unsigned))
	s, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + enc.EncodeToString(s), nil
}

// ParseRSAKey reads a PEM RSA private key in PKCS#1 or PKCS#8 form.
func ParseRSAKey(pemText []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemText)
	if block == nil {
		return nil, errors.New("no PEM block in private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

// PointAt rewrites r to go to base + rest, keeping the query string.
func PointAt(r *http.Request, base, rest string) error {
	u, err := url.Parse(base)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && !strings.HasPrefix(u.Host, "127.0.0.1") && !strings.HasPrefix(u.Host, "localhost") {
		return fmt.Errorf("upstream %s is not HTTPS", base)
	}
	r.URL.Scheme = u.Scheme
	r.URL.Host = u.Host
	r.URL.Path = strings.TrimSuffix(u.Path, "/") + rest
	r.URL.RawPath = ""
	r.Host = u.Host
	return nil
}

// ReadJSON decodes a JSON response body, failing on non-2xx status.
func ReadJSON(resp *http.Response, v any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("upstream returned %s: %s", resp.Status, truncate(body, 200))
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(body, v)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
