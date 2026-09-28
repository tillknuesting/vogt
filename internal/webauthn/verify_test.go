package webauthn

import (
	"bytes"
	"testing"
)

const (
	origin = "http://localhost:7854"
	rp     = "localhost"
)

func TestRegisterAndAssert(t *testing.T) {
	a := NewSoftAuthenticator()
	cd, ad, spki := a.Register([]byte("reg-challenge"), origin, rp)
	c, err := VerifyRegistration(cd, ad, spki, AlgES256, []byte("reg-challenge"), origin, rp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.ID, a.CredID) {
		t.Fatal("credential ID not taken from authenticator data")
	}
	cd, ad, sig := a.Assert([]byte("approve-1"), origin, rp)
	n, err := VerifyAssertion(c, cd, ad, sig, []byte("approve-1"), origin, rp)
	if err != nil {
		t.Fatal(err)
	}
	c.SignCount = n

	// Replaying the same assertion fails on the counter.
	if _, err := VerifyAssertion(c, cd, ad, sig, []byte("approve-1"), origin, rp); err == nil {
		t.Fatal("replayed assertion accepted")
	}
}

func TestAssertionRejects(t *testing.T) {
	a := NewSoftAuthenticator()
	cd, ad, spki := a.Register([]byte("c"), origin, rp)
	c, _ := VerifyRegistration(cd, ad, spki, AlgES256, []byte("c"), origin, rp)

	cases := map[string]func() error{
		"wrong challenge": func() error {
			cd, ad, sig := a.Assert([]byte("x"), origin, rp)
			_, err := VerifyAssertion(c, cd, ad, sig, []byte("y"), origin, rp)
			return err
		},
		"wrong origin": func() error {
			cd, ad, sig := a.Assert([]byte("x"), "http://evil.localhost:7854", rp)
			_, err := VerifyAssertion(c, cd, ad, sig, []byte("x"), origin, rp)
			return err
		},
		"wrong rp": func() error {
			cd, ad, sig := a.Assert([]byte("x"), origin, "example.com")
			_, err := VerifyAssertion(c, cd, ad, sig, []byte("x"), origin, rp)
			return err
		},
		"other key": func() error {
			b := NewSoftAuthenticator()
			b.Count = 100
			cd, ad, sig := b.Assert([]byte("x"), origin, rp)
			_, err := VerifyAssertion(c, cd, ad, sig, []byte("x"), origin, rp)
			return err
		},
		"no user verification": func() error {
			cd, ad, sig := a.Assert([]byte("x"), origin, rp)
			ad[32] &^= flagUV
			_, err := VerifyAssertion(c, cd, ad, sig, []byte("x"), origin, rp)
			return err
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPRFWrap(t *testing.T) {
	a := NewSoftAuthenticator()
	salt := []byte("salt-for-this-credential-32bytes")
	kek, err := KEK(a.PRF(salt))
	if err != nil {
		t.Fatal(err)
	}
	w, err := WrapDEK(kek, []byte("0123456789abcdef0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	again, _ := KEK(a.PRF(salt))
	dek, err := UnwrapDEK(again, w, []byte("aad"))
	if err != nil || string(dek) != "0123456789abcdef0123456789abcdef" {
		t.Fatal("PRF-derived key did not unwrap")
	}
	other, _ := KEK(NewSoftAuthenticator().PRF(salt))
	if _, err := UnwrapDEK(other, w, []byte("aad")); err == nil {
		t.Fatal("another authenticator unwrapped the DEK")
	}
}
