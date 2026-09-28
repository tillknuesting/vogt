package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const zero = "0000000000000000000000000000000000000000"
const one = "1111111111111111111111111111111111111111"

func pushReq(t *testing.T, body string, gz bool) *http.Request {
	var b io.Reader = strings.NewReader(body)
	r, _ := http.NewRequest("POST", "http://x/github/git/o/r.git/git-receive-pack", nil)
	if gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write([]byte(body))
		w.Close()
		b = &buf
		r.Header.Set("Content-Encoding", "gzip")
	}
	r.Body = io.NopCloser(b)
	return r
}

func TestFilterPush(t *testing.T) {
	deny := []string{"refs/heads/main", "refs/tags/*"}
	feature := pkt(zero+" "+one+" refs/heads/feature\x00report-status\n") + "0000" + "PACKDATA"
	for _, gz := range []bool{false, true} {
		r := pushReq(t, feature, gz)
		if err := filterPush(r, deny); err != nil {
			t.Fatalf("gzip=%v: %v", gz, err)
		}
		got, _ := io.ReadAll(r.Body)
		if string(got) != feature {
			t.Fatalf("gzip=%v: body changed:\n%q\n%q", gz, got, feature)
		}
		if r.Header.Get("Content-Encoding") != "" {
			t.Fatal("gzip header kept after decompressing")
		}
	}
	bad := []string{
		pkt(zero+" "+one+" refs/heads/main\n") + "0000",
		pkt(zero+" "+one+" refs/heads/ok\x00caps\n") + pkt(zero+" "+one+" refs/tags/v1\n") + "0000",
		"zzzz",
		pkt("garbage\n") + "0000",
		pkt(zero + " " + one + " refs/heads/ok\n"), // no flush
	}
	for _, b := range bad {
		if err := filterPush(pushReq(t, b, false), deny); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func FuzzFilterPush(f *testing.F) {
	f.Add(pkt(zero+" "+one+" refs/heads/feature\x00caps\n") + "0000PACK")
	f.Fuzz(func(t *testing.T, body string) {
		r := pushReq(t, body, false)
		if filterPush(r, []string{"refs/heads/main"}) == nil {
			got, _ := io.ReadAll(r.Body)
			if string(got) != body {
				t.Fatal("accepted push changed the body")
			}
			if strings.Contains(body, "refs/heads/main") && strings.Index(body, "0000") > strings.Index(body, "refs/heads/main") {
				// main appeared in the command section and was still let through
				t.Fatalf("main push accepted: %q", body)
			}
		}
	})
}

func TestSafePath(t *testing.T) {
	cases := map[string]bool{
		"/openai/v1/chat":         true,
		"/openai/v1/../admin":     false,
		"/openai/./v1":            false,
		"/openai//v1":             false,
		"/openai/v1%2f..%2fx":     false,
		"/github/api/repos/o/r":   true,
		"/openai/v1/a%2Eb":        false,
		"/openai/v1/with%20space": true,
	}
	for p, want := range cases {
		r, err := http.NewRequest("GET", "http://x"+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := safePath(r); got != want {
			t.Errorf("safePath(%q) = %v", p, got)
		}
	}
}

func TestExtractToken(t *testing.T) {
	cases := []struct {
		h, v, want string
	}{
		{"Authorization", "Bearer vogt_p_a", "vogt_p_a"},
		{"Authorization", "token vogt_p_b", "vogt_p_b"},
		{"Authorization", "Basic dm9ndDp2b2d0X3BfYw==", "vogt_p_c"}, // vogt:vogt_p_c
		{"X-Api-Key", "vogt_p_d", "vogt_p_d"},
		{"Proxy-Authorization", "Basic dm9ndDp2b2d0X3BfZQ==", "vogt_p_e"},
	}
	for _, c := range cases {
		r, _ := http.NewRequest("GET", "http://x/", nil)
		r.Header.Set(c.h, c.v)
		if got := extractToken(r); got != c.want {
			t.Errorf("%s: %q, want %q", c.v, got, c.want)
		}
	}
}
