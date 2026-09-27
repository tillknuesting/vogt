package vault

import (
	"crypto/hpke"
	"errors"
	"testing"

	"vogt/internal/envelope"
)

func newStore(t *testing.T) (*Store, hpke.PrivateKey, hpke.PrivateKey) {
	t.Helper()
	high, _ := envelope.SuiteVault.GenerateKey()
	low, _ := envelope.SuiteVault.GenerateKey()
	s, err := Open(t.TempDir(), TierKeys{High: high.PublicKey(), Low: low.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return s, high, low
}

func unwrap(t *testing.T, sk hpke.PrivateKey, e *Entry) []byte {
	t.Helper()
	dek, err := envelope.Unwrap(sk, WrapPurpose, WrapAAD(e.ID, e.KeyVersion), e.Wraps[WrapSE])
	if err != nil {
		t.Fatal(err)
	}
	return dek
}

func TestPutGetDecrypt(t *testing.T) {
	s, high, low := newStore(t)
	secret := []byte("ghs_app_private_key")
	if _, err := s.Put("github-write", "github", envelope.TierHigh, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret) != string(make([]byte, len(secret))) {
		t.Error("Put did not wipe the plaintext")
	}
	e, err := s.Get("github-write")
	if err != nil {
		t.Fatal(err)
	}
	buf, err := Decrypt(e, unwrap(t, high, e))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != "ghs_app_private_key" {
		t.Fatalf("got %q", buf.Bytes())
	}
	// The low-tier key cannot open a high-tier wrap.
	if _, err := envelope.Unwrap(low, WrapPurpose, WrapAAD(e.ID, e.KeyVersion), e.Wraps[WrapSE]); err == nil {
		t.Fatal("low-tier key opened a high-tier wrap")
	}
}

func TestReplaceBumpsVersion(t *testing.T) {
	s, high, _ := newStore(t)
	s.Put("k", "static", envelope.TierHigh, []byte("one"))
	old, _ := s.Get("k")
	oldDEK := unwrap(t, high, old)
	s.Put("k", "static", envelope.TierHigh, []byte("two"))
	e, _ := s.Get("k")
	if e.KeyVersion != 2 || !e.Created.Equal(old.Created) {
		t.Fatalf("meta = %+v", e.Meta)
	}
	// The old DEK does not open the new record.
	if _, err := Decrypt(e, oldDEK); err == nil {
		t.Fatal("old DEK opened the new record")
	}
	// An old wrap cannot be replayed onto the new version.
	e.Wraps[WrapSE] = old.Wraps[WrapSE]
	if _, err := envelope.Unwrap(high, WrapPurpose, WrapAAD(e.ID, e.KeyVersion), e.Wraps[WrapSE]); err == nil {
		t.Fatal("old wrap opened under the new version's AAD")
	}
}

func TestListDelete(t *testing.T) {
	s, _, _ := newStore(t)
	s.Put("b", "static", envelope.TierLow, []byte("x"))
	s.Put("a", "static", envelope.TierHigh, []byte("y"))
	l, err := s.List()
	if err != nil || len(l) != 2 || l[0].ID != "a" {
		t.Fatalf("List = %+v, %v", l, err)
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestRejectsBadNames(t *testing.T) {
	s, _, _ := newStore(t)
	for _, id := range []string{"", "../x", "A", ".hidden", "a/b"} {
		if _, err := s.Put(id, "static", envelope.TierHigh, []byte("x")); err == nil {
			t.Errorf("accepted %q", id)
		}
	}
}
