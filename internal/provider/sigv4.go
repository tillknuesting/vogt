package provider

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, as used by every AWS SDK.

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	amzDateFormat  = "20060102T150405Z"
	// UnsignedPayload is the payload hash S3 clients may send instead of a digest.
	UnsignedPayload = "UNSIGNED-PAYLOAD"
	maxHashedBody   = 16 << 20
)

// AWSCreds are credentials to sign with.
type AWSCreds struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

// SignV4 signs r in place for the given region and service. payloadHash is
// the hex SHA-256 of the body, or UnsignedPayload.
func SignV4(r *http.Request, c AWSCreds, region, service, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format(amzDateFormat)
	r.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	if service == "s3" || r.Header.Get("X-Amz-Content-Sha256") != "" {
		r.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	signed := []string{"host"}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-type" || lk == "content-md5" {
			signed = append(signed, lk)
		}
	}
	sort.Strings(signed)
	scope := strings.Join([]string{amzDate[:8], region, service, "aws4_request"}, "/")
	sigHex := sigV4Signature(r, c.SecretAccessKey, amzDate, scope, service, signed, payloadHash)
	r.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, c.AccessKeyID, scope, strings.Join(signed, ";"), sigHex))
}

func sigV4Signature(r *http.Request, secret, amzDate, scope, service string, signed []string, payloadHash string) string {
	canon := canonicalRequest(r, service, signed, payloadHash)
	h := sha256.Sum256([]byte(canon))
	sts := strings.Join([]string{sigV4Algorithm, amzDate, scope, hex.EncodeToString(h[:])}, "\n")
	parts := strings.Split(scope, "/")
	k := hmacSHA256([]byte("AWS4"+secret), parts[0])
	k = hmacSHA256(k, parts[1])
	k = hmacSHA256(k, parts[2])
	k = hmacSHA256(k, "aws4_request")
	return hex.EncodeToString(hmacSHA256(k, sts))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func canonicalRequest(r *http.Request, service string, signed []string, payloadHash string) string {
	var hdrs strings.Builder
	for _, name := range signed {
		var v string
		if name == "host" {
			v = r.Host
			if v == "" {
				v = r.URL.Host
			}
		} else {
			v = strings.Join(r.Header.Values(name), ",")
		}
		hdrs.WriteString(name + ":" + strings.Join(strings.Fields(v), " ") + "\n")
	}
	return strings.Join([]string{
		r.Method,
		canonicalURI(r.URL, service),
		canonicalQuery(r.URL),
		hdrs.String(),
		strings.Join(signed, ";"),
		payloadHash,
	}, "\n")
}

func canonicalURI(u *url.URL, service string) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	if service == "s3" {
		return p
	}
	// Every other service encodes each segment twice.
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = awsEscape(s)
	}
	return strings.Join(segs, "/")
}

func canonicalQuery(u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsEscape(k)+"="+awsEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// awsEscape percent-encodes everything except RFC 3986 unreserved characters.
func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// SigV4Header is a parsed Authorization header.
type SigV4Header struct {
	AccessKey, Date, Region, Service string
	Signed                           []string
	Signature                        string
}

// ParseSigV4 parses an AWS4-HMAC-SHA256 Authorization header.
func ParseSigV4(auth string) (SigV4Header, error) {
	var h SigV4Header
	rest, ok := strings.CutPrefix(auth, sigV4Algorithm+" ")
	if !ok {
		return h, errors.New("not a SigV4 header")
	}
	for _, part := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			f := strings.Split(v, "/")
			if len(f) != 5 || f[4] != "aws4_request" {
				return h, errors.New("malformed SigV4 credential")
			}
			h.AccessKey, h.Date, h.Region, h.Service = f[0], f[1], f[2], f[3]
		case "SignedHeaders":
			h.Signed = strings.Split(v, ";")
		case "Signature":
			h.Signature = v
		}
	}
	if h.AccessKey == "" || h.Signature == "" || len(h.Signed) == 0 || !sort.StringsAreSorted(h.Signed) {
		return h, errors.New("incomplete SigV4 header")
	}
	return h, nil
}

// PayloadHash returns the request's declared payload hash, computing and
// setting it from the body if the client did not send one.
func PayloadHash(r *http.Request) (string, error) {
	if v := r.Header.Get("X-Amz-Content-Sha256"); v != "" {
		if strings.HasPrefix(v, "STREAMING-AWS4-HMAC-SHA256") {
			return "", errors.New("chunk-signed uploads cannot pass the proxy; use direct mode")
		}
		return v, nil
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxHashedBody+1))
		r.Body.Close()
		if err != nil {
			return "", err
		}
		if len(body) > maxHashedBody {
			return "", errors.New("request body too large to hash")
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	r.Header.Set("X-Amz-Content-Sha256", h)
	return h, nil
}

// VerifySigV4Request checks a request an agent's AWS SDK signed with the
// grant ID as access key and the broker token as secret key. lookup returns
// the grant and its broker token for an access key.
func VerifySigV4Request[G any](r *http.Request, lookup func(id string) (G, []byte, bool)) (G, error) {
	var zero G
	h, err := ParseSigV4(r.Header.Get("Authorization"))
	if err != nil {
		return zero, err
	}
	g, secret, ok := lookup(h.AccessKey)
	if !ok {
		return zero, errors.New("unknown or ended grant")
	}
	amzDate := r.Header.Get("X-Amz-Date")
	t, err := time.Parse(amzDateFormat, amzDate)
	if err != nil || amzDate[:8] != h.Date {
		return zero, errors.New("bad X-Amz-Date")
	}
	if d := time.Since(t); d > 5*time.Minute || d < -5*time.Minute {
		return zero, errors.New("request time is more than 5 minutes off")
	}
	payload, err := PayloadHash(r)
	if err != nil {
		return zero, err
	}
	// If the client did not sign the content hash, the one PayloadHash
	// added must not join the signed set.
	scope := strings.Join([]string{h.Date, h.Region, h.Service, "aws4_request"}, "/")
	want := sigV4Signature(r, string(secret), amzDate, scope, h.Service, h.Signed, payload)
	if !hmac.Equal([]byte(want), []byte(h.Signature)) {
		return zero, errors.New("SigV4 signature does not match")
	}
	return g, nil
}
