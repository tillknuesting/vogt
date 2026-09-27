package token

import (
	"strings"
	"testing"
)

func TestNewParses(t *testing.T) {
	for _, k := range []Kind{Session, Proxy} {
		tok, h := New(k)
		if !strings.HasPrefix(tok, string(k)) {
			t.Fatalf("token %q lacks prefix %q", tok, k)
		}
		got, ok := Parse(tok)
		if !ok || got != k {
			t.Fatalf("Parse(%q) = %q, %v", tok, got, ok)
		}
		if !Equal(h, Hash(tok)) {
			t.Fatal("hash mismatch")
		}
	}
}

func TestParseRejects(t *testing.T) {
	tok, _ := New(Proxy)
	flipped := []byte(tok)
	if flipped[10] == 'a' {
		flipped[10] = 'b'
	} else {
		flipped[10] = 'a'
	}
	for _, bad := range []string{"", "vogt_p_", "vogt_x_" + tok[7:], string(flipped), tok + "a", tok[:len(tok)-1]} {
		if _, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestUnique(t *testing.T) {
	a, _ := New(Session)
	b, _ := New(Session)
	if a == b {
		t.Fatal("two tokens are equal")
	}
}
