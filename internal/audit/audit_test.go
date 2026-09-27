package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"vogt/internal/sig"
)

func setup(t *testing.T) (string, *sig.PrivateKey) {
	t.Helper()
	k, err := sig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(t.TempDir(), "audit.log"), k
}

func TestChainVerifies(t *testing.T) {
	path, k := setup(t)
	l, err := Open(path, k)
	if err != nil {
		t.Fatal(err)
	}
	for i := range CheckpointEvery + 10 {
		if err := l.Append("grant.issued", map[string]string{"grant": "g", "n": string(rune('a' + i%26))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path, k.Public())
	if err != nil {
		t.Fatal(err)
	}
	if res.Checkpoints != 2 || res.Unsigned != 0 || res.Entries != CheckpointEvery+12 {
		t.Fatalf("result = %+v", res)
	}

	// Reopening continues the chain.
	l, err = Open(path, k)
	if err != nil {
		t.Fatal(err)
	}
	l.Append("session.ended", nil)
	l.Close()
	if _, err := Verify(path, k.Public()); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetected(t *testing.T) {
	path, k := setup(t)
	l, _ := Open(path, k)
	l.Append("a", map[string]string{"x": "1"})
	l.Append("b", map[string]string{"x": "2"})
	l.Close()
	orig, _ := os.ReadFile(path)

	cases := map[string][]byte{
		"edited field":   bytes.Replace(orig, []byte(`"x":"1"`), []byte(`"x":"9"`), 1),
		"removed line":   orig[bytes.IndexByte(orig, '\n')+1:],
		"flipped a byte": flip(orig, 30),
	}
	for name, b := range cases {
		os.WriteFile(path, b, 0o600)
		if _, err := Verify(path, k.Public()); err == nil {
			t.Errorf("%s: verified", name)
		}
		if _, err := Open(path, k); err == nil {
			t.Errorf("%s: Open appended to a broken log", name)
		}
	}
}

func TestWrongKey(t *testing.T) {
	path, k := setup(t)
	l, _ := Open(path, k)
	l.Append("a", nil)
	l.Close()
	other, _ := sig.GenerateKey()
	if _, err := Verify(path, other.Public()); err == nil {
		t.Fatal("verified with the wrong key")
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 1
	return c
}
