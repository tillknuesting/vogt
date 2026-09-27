// Package interop checks that Vogt's Go formats match the Swift helper's,
// using test vectors in testdata/vectors.
//
//	go test ./internal/interop -update   rewrites go-to-swift.json
//	swift spikes/cryptokit/interop.swift reads it and writes swift-to-go.json
//
// Signatures and HPKE are randomized, so vectors are generated once and
// committed; the tests check that they still verify and open.
package interop

import (
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"vogt/internal/envelope"
	"vogt/internal/sig"
	"vogt/internal/wire"
)

var update = flag.Bool("update", false, "rewrite go-to-swift.json")

var dir = filepath.Join("..", "..", "testdata", "vectors")

// hexBytes marshals as a hex string.
type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }
func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := hex.DecodeString(s)
	*h = v
	return err
}

type goVectors struct {
	Wire struct {
		Label   string   `json:"label"`
		Uint    uint64   `json:"uint"`
		Bytes   hexBytes `json:"bytes"`
		String  string   `json:"string"`
		Encoded hexBytes `json:"encoded"`
	} `json:"wire"`
	Sig struct {
		Purpose   string   `json:"purpose"`
		Message   hexBytes `json:"message"`
		Signed    hexBytes `json:"signed"` // wire("vogt/v1/sig", purpose, message)
		Context   string   `json:"context"`
		PublicKey hexBytes `json:"public_key"` // sig.PublicKey.Bytes()
		MLDSAPub  hexBytes `json:"mldsa_public"`
		ECDSAPub  hexBytes `json:"ecdsa_public_x963"`
		Signature hexBytes `json:"signature"` // sig value, wire-encoded
		MLDSASig  hexBytes `json:"mldsa_signature"`
		ECDSASig  hexBytes `json:"ecdsa_signature_der"`
	} `json:"sig"`
	XWing struct {
		PrivateSeed hexBytes `json:"private_seed"` // test key only
		PublicKey   hexBytes `json:"public_key"`
		Info        string   `json:"info"`
		AAD         hexBytes `json:"aad"`
		Enc         hexBytes `json:"enc"`
		Ciphertext  hexBytes `json:"ciphertext"`
		Plaintext   hexBytes `json:"plaintext"`
		Wrapped     hexBytes `json:"wrapped"` // envelope.Wrap output
	} `json:"xwing"`
}

type swiftVectors struct {
	Sig struct {
		Purpose  string   `json:"purpose"`
		Message  hexBytes `json:"message"`
		MLDSAPub hexBytes `json:"mldsa_public"`
		ECDSAPub hexBytes `json:"ecdsa_public_x963"`
		MLDSASig hexBytes `json:"mldsa_signature"`
		ECDSASig hexBytes `json:"ecdsa_signature_der"`
		Enclave  bool     `json:"secure_enclave"`
	} `json:"sig"`
	XWing struct {
		AAD        hexBytes `json:"aad"`
		Enc        hexBytes `json:"enc"`
		Ciphertext hexBytes `json:"ciphertext"`
		Plaintext  hexBytes `json:"plaintext"`
	} `json:"xwing"`
}

func load(t *testing.T, name string, v any) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
	return true
}

func split(t *testing.T, msg []byte, label string) (a, b []byte) {
	t.Helper()
	d := wire.NewDecoder(msg, label)
	a, b = d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func generate(t *testing.T) {
	var v goVectors

	v.Wire.Label, v.Wire.Uint, v.Wire.Bytes, v.Wire.String = "vogt/v1/test", 1<<40+7, hexBytes{0, 1, 0xfe}, "grüße"
	v.Wire.Encoded = wire.NewEncoder(v.Wire.Label).PutUint(v.Wire.Uint).PutBytes(v.Wire.Bytes).PutString(v.Wire.String).Finish()

	k, err := sig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v.Sig.Purpose, v.Sig.Message = "approval", hexBytes("grant 7f3a: push tillknuesting/vogt")
	v.Sig.Signed = wire.NewEncoder("vogt/v1/sig").PutString(v.Sig.Purpose).PutBytes(v.Sig.Message).Finish()
	v.Sig.Context = "vogt/v1/" + v.Sig.Purpose
	v.Sig.PublicKey = k.Public().Bytes()
	v.Sig.MLDSAPub, v.Sig.ECDSAPub = split(t, v.Sig.PublicKey, "vogt/v1/sig-public")
	if v.Sig.Signature, err = k.Sign(v.Sig.Purpose, v.Sig.Message); err != nil {
		t.Fatal(err)
	}
	v.Sig.MLDSASig, v.Sig.ECDSASig = split(t, v.Sig.Signature, "vogt/v1/sig-value")

	sk, err := envelope.SuiteReply.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if v.XWing.PrivateSeed, err = sk.Bytes(); err != nil {
		t.Fatal(err)
	}
	v.XWing.PublicKey = sk.PublicKey().Bytes()
	v.XWing.Info, v.XWing.AAD, v.XWing.Plaintext = "vogt/v1/dek", hexBytes("record github-write"), hexBytes("0123456789abcdef0123456789abcdef")
	if v.XWing.Wrapped, err = envelope.Wrap(sk.PublicKey(), "dek", v.XWing.AAD, v.XWing.Plaintext); err != nil {
		t.Fatal(err)
	}
	d := wire.NewDecoder(v.XWing.Wrapped, "vogt/v1/wrap")
	d.ReadUint()
	d.ReadUint()
	d.ReadString()
	v.XWing.Enc, v.XWing.Ciphertext = d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}

	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go-to-swift.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestGoVectors checks that the committed Go vectors still verify and open,
// so a format change cannot slip in without regenerating them.
func TestGoVectors(t *testing.T) {
	if *update {
		generate(t)
	}
	var v goVectors
	if !load(t, "go-to-swift.json", &v) {
		t.Fatal("missing go-to-swift.json; run with -update")
	}
	enc := wire.NewEncoder(v.Wire.Label).PutUint(v.Wire.Uint).PutBytes(v.Wire.Bytes).PutString(v.Wire.String).Finish()
	if hex.EncodeToString(enc) != hex.EncodeToString(v.Wire.Encoded) {
		t.Error("wire encoding changed")
	}
	pub, err := sig.ParsePublicKey(v.Sig.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(v.Sig.Purpose, v.Sig.Message, v.Sig.Signature); err != nil {
		t.Errorf("signature: %v", err)
	}
	sk, err := hpke.MLKEM768X25519().NewPrivateKey(v.XWing.PrivateSeed)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := envelope.Unwrap(sk, "dek", v.XWing.AAD, v.XWing.Wrapped)
	if err != nil || string(pt) != string(v.XWing.Plaintext) {
		t.Errorf("unwrap: %v", err)
	}
}

// TestSwiftVectors checks what CryptoKit produced: a composite signature
// and an X-Wing HPKE ciphertext sealed to the Go test key.
func TestSwiftVectors(t *testing.T) {
	var g goVectors
	var s swiftVectors
	if !load(t, "go-to-swift.json", &g) {
		t.Fatal("missing go-to-swift.json")
	}
	if !load(t, "swift-to-go.json", &s) {
		t.Skip("no swift-to-go.json; run spikes/cryptokit/interop.swift")
	}

	pub, err := sig.ParsePublicKey(wire.NewEncoder("vogt/v1/sig-public").PutBytes(s.Sig.MLDSAPub).PutBytes(s.Sig.ECDSAPub).Finish())
	if err != nil {
		t.Fatal(err)
	}
	value := wire.NewEncoder("vogt/v1/sig-value").PutBytes(s.Sig.MLDSASig).PutBytes(s.Sig.ECDSASig).Finish()
	if err := pub.Verify(s.Sig.Purpose, s.Sig.Message, value); err != nil {
		t.Errorf("CryptoKit signature (secure enclave: %v): %v", s.Sig.Enclave, err)
	}

	sk, err := hpke.MLKEM768X25519().NewPrivateKey(g.XWing.PrivateSeed)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wire.NewEncoder("vogt/v1/wrap").PutUint(1).PutUint(uint64(envelope.SuiteReply)).
		PutString("dek").PutBytes(s.XWing.Enc).PutBytes(s.XWing.Ciphertext).Finish()
	pt, err := envelope.Unwrap(sk, "dek", s.XWing.AAD, wrapped)
	if err != nil || string(pt) != string(s.XWing.Plaintext) {
		t.Errorf("CryptoKit X-Wing seal: %v", err)
	}
}
