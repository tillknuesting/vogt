package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
