// Package sig implements Vogt's composite signature: ML-DSA-65 and ECDSA
// P-256 over the same message. A signature verifies only if both halves do,
// so it holds as long as either algorithm is unbroken.
//
// Both halves sign a message that binds a purpose label:
//
//	m = wire("vogt/v1/sig", purpose, message)
//
// ML-DSA signs m with the context string "vogt/v1/" + purpose. ECDSA signs
// SHA-256(m), which is what CryptoKit's P256.Signing produces for m, so the
// Secure Enclave can produce the ECDSA half directly.
package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"vogt/internal/wire"
)

const (
	labelMessage = "vogt/v1/sig"
	labelValue   = "vogt/v1/sig-value"
	labelPublic  = "vogt/v1/sig-public"
	labelPrivate = "vogt/v1/sig-private"
	maxPurpose   = 64
)

// ErrInvalid is returned for any signature that does not verify.
var ErrInvalid = errors.New("sig: invalid signature")

// PrivateKey is a composite signing key.
type PrivateKey struct {
	pq *mldsa.PrivateKey
	ec *ecdsa.PrivateKey
}

// PublicKey is a composite verification key.
type PublicKey struct {
	pq *mldsa.PublicKey
	ec *ecdsa.PublicKey
}

// GenerateKey returns a new random key pair.
func GenerateKey() (*PrivateKey, error) {
	pq, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{pq: pq, ec: ec}, nil
}

// Public returns the verification key.
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{pq: k.pq.PublicKey(), ec: &k.ec.PublicKey}
}

// MarshalBinary encodes the private key: the 32-byte ML-DSA seed and the raw
// P-256 scalar. The result is secret; move it into secmem or wipe it.
func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	ec, err := k.ec.Bytes()
	if err != nil {
		return nil, err
	}
	out := wire.NewEncoder(labelPrivate).PutBytes(k.pq.Bytes()).PutBytes(ec).Finish()
	clear(ec)
	return out, nil
}

// ParsePrivateKey decodes a key produced by MarshalBinary.
func ParsePrivateKey(b []byte) (*PrivateKey, error) {
	d := wire.NewDecoder(b, labelPrivate)
	seed, raw := d.ReadBytes(), d.ReadBytes()
	defer clear(seed)
	defer clear(raw)
	if err := d.Finish(); err != nil {
		return nil, err
	}
	pq, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, err
	}
	ec, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{pq: pq, ec: ec}, nil
}

// Bytes encodes the public key.
func (p *PublicKey) Bytes() []byte {
	ec, err := p.ec.Bytes()
	if err != nil {
		panic("sig: invalid P-256 public key: " + err.Error())
	}
	return wire.NewEncoder(labelPublic).PutBytes(p.pq.Bytes()).PutBytes(ec).Finish()
}

// Fingerprint is the SHA-256 of the encoded public key, used for pinning.
func (p *PublicKey) Fingerprint() [32]byte {
	return sha256.Sum256(p.Bytes())
}

// ParsePublicKey decodes a public key produced by Bytes.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	d := wire.NewDecoder(b, labelPublic)
	pqb, ecb := d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		return nil, err
	}
	pq, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pqb)
	if err != nil {
		return nil, err
	}
	ec, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ecb)
	if err != nil {
		return nil, err
	}
	return &PublicKey{pq: pq, ec: ec}, nil
}

// Sign signs msg for the given purpose, such as "approval" or "policy".
func (k *PrivateKey) Sign(purpose string, msg []byte) ([]byte, error) {
	m, err := message(purpose, msg)
	if err != nil {
		return nil, err
	}
	pqSig, err := k.pq.Sign(nil, m, &mldsa.Options{Context: context(purpose)})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(m)
	ecSig, err := ecdsa.SignASN1(rand.Reader, k.ec, digest[:])
	if err != nil {
		return nil, err
	}
	return wire.NewEncoder(labelValue).PutBytes(pqSig).PutBytes(ecSig).Finish(), nil
}

// Verify checks a composite signature. Both halves must be valid.
func (p *PublicKey) Verify(purpose string, msg, signature []byte) error {
	m, err := message(purpose, msg)
	if err != nil {
		return err
	}
	d := wire.NewDecoder(signature, labelValue)
	pqSig, ecSig := d.ReadBytes(), d.ReadBytes()
	if d.Finish() != nil {
		return ErrInvalid
	}
	pqErr := mldsa.Verify(p.pq, m, pqSig, &mldsa.Options{Context: context(purpose)})
	digest := sha256.Sum256(m)
	ecOK := ecdsa.VerifyASN1(p.ec, digest[:], ecSig)
	if pqErr != nil || !ecOK {
		return ErrInvalid
	}
	return nil
}

func message(purpose string, msg []byte) ([]byte, error) {
	if err := checkPurpose(purpose); err != nil {
		return nil, err
	}
	return wire.NewEncoder(labelMessage).PutString(purpose).PutBytes(msg).Finish(), nil
}

func context(purpose string) string {
	return "vogt/v1/" + purpose
}

// checkPurpose allows lowercase letters, digits and . _ - /, up to 64 bytes.
func checkPurpose(p string) error {
	if len(p) == 0 || len(p) > maxPurpose {
		return fmt.Errorf("sig: purpose must be 1 to %d bytes", maxPurpose)
	}
	for _, c := range []byte(p) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '/':
		default:
			return fmt.Errorf("sig: invalid character %q in purpose", c)
		}
	}
	return nil
}
