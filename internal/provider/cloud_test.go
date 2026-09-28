package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testRSAPEM(t *testing.T) (*rsa.PrivateKey, string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func verifyJWT(t *testing.T, jwt string, pub *rsa.PublicKey) map[string]any {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, 5, digest[:], sig); err != nil {
		t.Fatal("JWT signature:", err)
	}
	var claims map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(raw, &claims)
	return claims
}

func TestGCPMint(t *testing.T) {
	key, pemKey := testRSAPEM(t)
	var sawLifetime string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			r.ParseForm()
			claims := verifyJWT(t, r.Form.Get("assertion"), &key.PublicKey)
			if claims["iss"] != "broker@p.iam.gserviceaccount.com" {
				t.Errorf("iss = %v", claims["iss"])
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "broker-token"})
		case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			if r.Header.Get("Authorization") != "Bearer broker-token" {
				http.Error(w, "no", 401)
				return
			}
			var body struct {
				Lifetime string   `json:"lifetime"`
				Scope    []string `json:"scope"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			sawLifetime = body.Lifetime
			json.NewEncoder(w).Encode(map[string]any{"accessToken": "ya29.short", "expireTime": time.Now().Add(10 * time.Minute)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	master, _ := json.Marshal(map[string]string{"client_email": "broker@p.iam.gserviceaccount.com", "private_key": pemKey, "token_uri": srv.URL + "/token"})
	g := &GCP{Client: srv.Client(), CredsEndpoint: srv.URL}
	cred, err := g.Mint(context.Background(), Request{TTL: 10 * time.Minute, Scope: json.RawMessage(`{"service_account":"agent@p.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/devstorage.read_only"]}`)}, master)
	if err != nil {
		t.Fatal(err)
	}
	defer cred.Wipe()
	if sawLifetime != "600s" {
		t.Fatalf("lifetime = %q", sawLifetime)
	}
	r, _ := http.NewRequest("GET", "http://proxy/gcp/storage.googleapis.com/storage/v1/b/x/o", nil)
	if err := cred.Inject(r, "/storage.googleapis.com/storage/v1/b/x/o"); err != nil {
		t.Fatal(err)
	}
	if r.URL.String() != "https://storage.googleapis.com/storage/v1/b/x/o" || r.Header.Get("Authorization") != "Bearer ya29.short" {
		t.Fatalf("injected %s %s", r.URL, r.Header.Get("Authorization"))
	}
	if err := cred.Inject(r, "/evil.example.com/x"); err == nil {
		t.Fatal("non-Google host accepted")
	}
}

func TestOAuthRotatesRefreshToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("refresh_token") != "rt-1" {
			http.Error(w, "bad", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "expires_in": 3600, "refresh_token": "rt-2"})
	}))
	defer srv.Close()
	master, _ := json.Marshal(map[string]string{"token_url": srv.URL, "client_id": "c", "refresh_token": "rt-1"})
	o := &OAuth{Client: srv.Client()}
	cred, err := o.Mint(context.Background(), Request{Upstream: "https://graph.microsoft.com"}, master)
	if err != nil {
		t.Fatal(err)
	}
	nm := cred.(RotatedMaster).NewMaster()
	if !strings.Contains(string(nm), "rt-2") {
		t.Fatalf("new master = %s", nm)
	}
	if _, err := o.Mint(context.Background(), Request{Direct: true}, master); err == nil {
		t.Fatal("direct mode allowed for OAuth")
	}
}

func TestStaticInjects(t *testing.T) {
	cred, err := Static{}.Mint(context.Background(), Request{Upstream: "https://api.anthropic.com", Scope: json.RawMessage(`{"header":"x-api-key","format":"{key}"}`)}, []byte("sk-ant"))
	if err != nil {
		t.Fatal(err)
	}
	defer cred.Wipe()
	r, _ := http.NewRequest("POST", "http://proxy/anthropic/v1/messages", nil)
	cred.Inject(r, "/v1/messages")
	if r.URL.String() != "https://api.anthropic.com/v1/messages" || r.Header.Get("x-api-key") != "sk-ant" {
		t.Fatalf("%s %v", r.URL, r.Header)
	}
}

func TestPointAtRefusesPlainHTTP(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	if err := PointAt(r, "http://example.com", "/"); err == nil {
		t.Fatal("plain HTTP upstream accepted")
	}
}
