package sig

import (
	"bytes"
	"errors"
	"testing"

	"vogt/internal/wire"
)

func mustKey(t testing.TB) *PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerify(t *testing.T) {
	k := mustKey(t)
	s, err := k.Sign("approval", []byte("grant 42"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Public().Verify("approval", []byte("grant 42"), s); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	k := mustKey(t)
	pub := k.Public()
	msg := []byte("grant 42")
	s, _ := k.Sign("approval", msg)

	if err := pub.Verify("policy", msg, s); !errors.Is(err, ErrInvalid) {
		t.Errorf("other purpose: %v", err)
	}
	if err := pub.Verify("approval", []byte("grant 43"), s); !errors.Is(err, ErrInvalid) {
		t.Errorf("other message: %v", err)
	}
	if err := mustKey(t).Public().Verify("approval", msg, s); !errors.Is(err, ErrInvalid) {
		t.Errorf("other key: %v", err)
	}
	flipped := append([]byte{}, s...)
	flipped[len(flipped)-5] ^= 1
	if err := pub.Verify("approval", msg, flipped); !errors.Is(err, ErrInvalid) {
		t.Errorf("flipped bit: %v", err)
	}
}

// TestBothHalvesRequired swaps in one half from another key's signature over
// the same message. Either half alone must not be enough.
func TestBothHalvesRequired(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	msg := []byte("m")
	sa, _ := a.Sign("x", msg)
	sb, _ := b.Sign("x", msg)
	halves := func(s []byte) (pq, ec []byte) {
		d := wire.NewDecoder(s, labelValue)
		return d.ReadBytes(), d.ReadBytes()
	}
	pqA, ecA := halves(sa)
	pqB, ecB := halves(sb)
	mixed := [][]byte{
		wire.NewEncoder(labelValue).PutBytes(pqA).PutBytes(ecB).Finish(),
		wire.NewEncoder(labelValue).PutBytes(pqB).PutBytes(ecA).Finish(),
	}
	for i, s := range mixed {
		if err := a.Public().Verify("x", msg, s); !errors.Is(err, ErrInvalid) {
			t.Errorf("mix %d verified", i)
		}
	}
}

func TestKeyEncoding(t *testing.T) {
	k := mustKey(t)
	raw, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(k.Public().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub.Bytes(), k2.Public().Bytes()) {
		t.Fatal("public key changed across encode and decode")
	}
	s, _ := k2.Sign("p", []byte("m"))
	if err := pub.Verify("p", []byte("m"), s); err != nil {
		t.Fatal(err)
	}
}

func TestPurposeRules(t *testing.T) {
	k := mustKey(t)
	for _, p := range []string{"", "Approval", "a b", "ü", string(make([]byte, 65))} {
		if _, err := k.Sign(p, nil); err == nil {
			t.Errorf("purpose %q accepted", p)
		}
	}
}

func FuzzVerify(f *testing.F) {
	k := mustKey(f)
	pub := k.Public()
	s, _ := k.Sign("f", []byte("m"))
	f.Add(s)
	f.Fuzz(func(t *testing.T, s []byte) {
		pub.Verify("f", []byte("m"), s) // must not panic
	})
}

func FuzzParsePublicKey(f *testing.F) {
	f.Add(mustKey(f).Public().Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := ParsePublicKey(b); err == nil && !bytes.Equal(p.Bytes(), b) {
			t.Fatal("accepted a non-canonical encoding")
		}
	})
}
