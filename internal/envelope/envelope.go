// Package envelope defines Vogt's two encrypted formats.
//
// A record holds one secret at rest, encrypted with AES-256-GCM under that
// secret's own data key (DEK). The record header is the associated data, so a
// ciphertext cannot be moved to another record ID, tier or key version.
//
// A wrap carries a key to a recipient with HPKE (RFC 9180), always with
// HKDF-SHA256 and AES-256-GCM and one of two hybrid post-quantum KEMs:
//
//	SuiteVault  MLKEM768-P256: DEKs sealed to the helper's Secure Enclave keys
//	SuiteReply  MLKEM768-X25519 (X-Wing): DEKs sent back to the daemon
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"errors"
	"fmt"

	"vogt/internal/wire"
)

const (
	version = 1

	labelRecord = "vogt/v1/record"
	labelHeader = "vogt/v1/record-header"
	labelWrap   = "vogt/v1/wrap"

	algAES256GCM = 1

	// DEKSize is the size of every data key.
	DEKSize = 32
)

// ErrOpen is returned for any record or wrap that fails to decrypt or parse.
// Callers get no detail about which check failed.
var ErrOpen = errors.New("envelope: cannot open")

// Tier says which Secure Enclave key protects a record's DEK.
type Tier uint8

const (
	TierHigh Tier = 1 // Touch ID for every unwrap
	TierLow  Tier = 2 // unwrapped once per login
)

// Header describes a record. It is authenticated but not encrypted.
type Header struct {
	ID         string
	Tier       Tier
	KeyVersion uint64
}

func (h Header) encode() []byte {
	return wire.NewEncoder(labelHeader).
		PutUint(version).
		PutString(h.ID).
		PutUint(uint64(h.Tier)).
		PutUint(h.KeyVersion).
		PutUint(algAES256GCM).
		Finish()
}

func decodeHeader(b []byte) (Header, error) {
	d := wire.NewDecoder(b, labelHeader)
	v := d.ReadUint()
	h := Header{ID: d.ReadString(), Tier: Tier(d.ReadUint()), KeyVersion: d.ReadUint()}
	alg := d.ReadUint()
	if err := d.Finish(); err != nil {
		return Header{}, err
	}
	if v != version || alg != algAES256GCM || (h.Tier != TierHigh && h.Tier != TierLow) || h.ID == "" {
		return Header{}, errors.New("envelope: unsupported header")
	}
	return h, nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("envelope: DEK must be %d bytes", DEKSize)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// SealRecord encrypts plaintext under dek. The nonce is random and stored in
// the ciphertext.
func SealRecord(dek []byte, h Header, plaintext []byte) ([]byte, error) {
	if h.ID == "" || (h.Tier != TierHigh && h.Tier != TierLow) {
		return nil, errors.New("envelope: header needs an ID and a valid tier")
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	hb := h.encode()
	ct := aead.Seal(nil, nil, plaintext, hb)
	return wire.NewEncoder(labelRecord).PutBytes(hb).PutBytes(ct).Finish(), nil
}

// OpenRecord decrypts a record and checks that it belongs to wantID.
func OpenRecord(dek []byte, record []byte, wantID string) (Header, []byte, error) {
	aead, err := newGCM(dek)
	if err != nil {
		return Header{}, nil, err
	}
	d := wire.NewDecoder(record, labelRecord)
	hb, ct := d.ReadBytes(), d.ReadBytes()
	if d.Finish() != nil {
		return Header{}, nil, ErrOpen
	}
	h, err := decodeHeader(hb)
	if err != nil || h.ID != wantID {
		return Header{}, nil, ErrOpen
	}
	pt, err := aead.Open(nil, nil, ct, hb)
	if err != nil {
		return Header{}, nil, ErrOpen
	}
	return h, pt, nil
}

// Suite names an HPKE ciphersuite.
type Suite uint16

const (
	SuiteVault Suite = 1 // MLKEM768-P256, HKDF-SHA256, AES-256-GCM
	SuiteReply Suite = 2 // MLKEM768-X25519, HKDF-SHA256, AES-256-GCM
)

// KEM returns the suite's key encapsulation mechanism.
func (s Suite) KEM() (hpke.KEM, error) {
	switch s {
	case SuiteVault:
		return hpke.MLKEM768P256(), nil
	case SuiteReply:
		return hpke.MLKEM768X25519(), nil
	}
	return nil, fmt.Errorf("envelope: unknown suite %d", s)
}

// GenerateKey returns a new HPKE key pair for the suite.
func (s Suite) GenerateKey() (hpke.PrivateKey, error) {
	kem, err := s.KEM()
	if err != nil {
		return nil, err
	}
	return kem.GenerateKey()
}

func suiteOf(kem hpke.KEM) (Suite, error) {
	for _, s := range []Suite{SuiteVault, SuiteReply} {
		k, _ := s.KEM()
		if k.ID() == kem.ID() {
			return s, nil
		}
	}
	return 0, fmt.Errorf("envelope: KEM 0x%04x is not allowed", kem.ID())
}

// Wrap seals plaintext to pk. The purpose goes into the HPKE info and aad is
// authenticated, so a wrap made for one purpose or record cannot be opened as
// another.
func Wrap(pk hpke.PublicKey, purpose string, aad, plaintext []byte) ([]byte, error) {
	s, err := suiteOf(pk.KEM())
	if err != nil {
		return nil, err
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info(purpose))
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, err
	}
	return wire.NewEncoder(labelWrap).
		PutUint(version).
		PutUint(uint64(s)).
		PutString(purpose).
		PutBytes(enc).
		PutBytes(ct).
		Finish(), nil
}

// Unwrap opens a wrap made by Wrap. It fails unless the suite matches sk's
// KEM and the purpose and aad match what the caller expects.
func Unwrap(sk hpke.PrivateKey, purpose string, aad, wrapped []byte) ([]byte, error) {
	want, err := suiteOf(sk.KEM())
	if err != nil {
		return nil, err
	}
	d := wire.NewDecoder(wrapped, labelWrap)
	v, s, p := d.ReadUint(), Suite(d.ReadUint()), d.ReadString()
	enc, ct := d.ReadBytes(), d.ReadBytes()
	if d.Finish() != nil || v != version || s != want || p != purpose {
		return nil, ErrOpen
	}
	r, err := hpke.NewRecipient(enc, sk, hpke.HKDFSHA256(), hpke.AES256GCM(), info(purpose))
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := r.Open(aad, ct)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func info(purpose string) []byte {
	return []byte("vogt/v1/" + purpose)
}
