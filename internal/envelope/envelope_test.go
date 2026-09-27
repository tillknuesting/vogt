package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"vogt/internal/wire"
)

func newDEK() []byte {
	k := make([]byte, DEKSize)
	rand.Read(k)
	return k
}

var hdr = Header{ID: "github-write", Tier: TierHigh, KeyVersion: 3}

func TestRecordRoundTrip(t *testing.T) {
	dek := newDEK()
	rec, err := SealRecord(dek, hdr, []byte("-----BEGIN RSA PRIVATE KEY-----"))
	if err != nil {
		t.Fatal(err)
	}
	h, pt, err := OpenRecord(dek, rec, "github-write")
	if err != nil {
		t.Fatal(err)
	}
	if h != hdr || string(pt) != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Fatalf("got %+v %q", h, pt)
	}
}

func TestRecordNoncesDiffer(t *testing.T) {
	dek := newDEK()
	a, _ := SealRecord(dek, hdr, []byte("same"))
	b, _ := SealRecord(dek, hdr, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical")
	}
}

func TestRecordRejects(t *testing.T) {
	dek := newDEK()
	rec, _ := SealRecord(dek, hdr, []byte("secret"))

	if _, _, err := OpenRecord(newDEK(), rec, hdr.ID); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong key: %v", err)
	}
	if _, _, err := OpenRecord(dek, rec, "other-id"); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong ID: %v", err)
	}
	if _, _, err := OpenRecord(dek, rec[:len(rec)-1], hdr.ID); !errors.Is(err, ErrOpen) {
		t.Errorf("truncated: %v", err)
	}

	// Re-label the ciphertext with a different tier: the header is
	// authenticated, so decryption must fail.
	d := wire.NewDecoder(rec, labelRecord)
	_, ct := d.ReadBytes(), d.ReadBytes()
	moved := wire.NewEncoder(labelRecord).
		PutBytes(Header{ID: hdr.ID, Tier: TierLow, KeyVersion: 3}.encode()).
		PutBytes(ct).Finish()
	if _, _, err := OpenRecord(dek, moved, hdr.ID); !errors.Is(err, ErrOpen) {
		t.Errorf("swapped header: %v", err)
	}
}

func TestRecordNeedsFullKey(t *testing.T) {
	if _, err := SealRecord(make([]byte, 16), hdr, nil); err == nil {
		t.Fatal("accepted a 16-byte DEK")
	}
}

func TestWrapBothSuites(t *testing.T) {
	for _, s := range []Suite{SuiteVault, SuiteReply} {
		sk, err := s.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		dek := newDEK()
		w, err := Wrap(sk.PublicKey(), "dek", []byte("record-7"), dek)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unwrap(sk, "dek", []byte("record-7"), w)
		if err != nil {
			t.Fatalf("suite %d: %v", s, err)
		}
		if !bytes.Equal(got, dek) {
			t.Fatalf("suite %d: wrong plaintext", s)
		}
	}
}

func TestWrapRejects(t *testing.T) {
	sk, _ := SuiteVault.GenerateKey()
	w, _ := Wrap(sk.PublicKey(), "dek", []byte("a"), newDEK())

	if _, err := Unwrap(sk, "other", []byte("a"), w); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong purpose: %v", err)
	}
	if _, err := Unwrap(sk, "dek", []byte("b"), w); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong aad: %v", err)
	}
	other, _ := SuiteVault.GenerateKey()
	if _, err := Unwrap(other, "dek", []byte("a"), w); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong key: %v", err)
	}
	reply, _ := SuiteReply.GenerateKey()
	if _, err := Unwrap(reply, "dek", []byte("a"), w); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong suite: %v", err)
	}
}

func FuzzOpenRecord(f *testing.F) {
	dek := newDEK()
	rec, _ := SealRecord(dek, hdr, []byte("x"))
	f.Add(rec)
	f.Fuzz(func(t *testing.T, b []byte) {
		OpenRecord(dek, b, hdr.ID) // must not panic
	})
}

func FuzzUnwrap(f *testing.F) {
	sk, _ := SuiteReply.GenerateKey()
	w, _ := Wrap(sk.PublicKey(), "dek", nil, []byte("k"))
	f.Add(w)
	f.Fuzz(func(t *testing.T, b []byte) {
		Unwrap(sk, "dek", nil, b) // must not panic
	})
}
