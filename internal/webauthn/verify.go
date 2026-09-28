// Package webauthn verifies passkey and security-key approvals for Vogt's
// localhost approval page, with no CBOR parser: registration reads the
// public key from the browser's getPublicKey(), which returns DER
// SubjectPublicKeyInfo, and assertions need only the fixed authenticator
// data layout.
//
// The PRF extension gives each credential a secret only the authenticator
// can reproduce. Vogt derives a key-encryption key from it, so a phone
// approval can unwrap a secret's DEK the way a Touch ID tap does.
package webauthn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// COSE algorithm identifiers.
const (
	AlgES256 = -7
	AlgEdDSA = -8
)

const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified (PIN or biometric)
	flagAT = 0x40 // attested credential data included
)

// Credential is an enrolled authenticator.
type Credential struct {
	ID        []byte `json:"id"`
	PublicKey []byte `json:"public_key"` // DER SubjectPublicKeyInfo
	Alg       int    `json:"alg"`
	SignCount uint32 `json:"sign_count"`
	PRFSalt   []byte `json:"prf_salt"`
	Name      string `json:"name"`
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func checkClientData(raw []byte, typ string, challenge []byte, origin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("webauthn: bad clientDataJSON")
	}
	if cd.Type != typ {
		return fmt.Errorf("webauthn: type %q, want %q", cd.Type, typ)
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return errors.New("webauthn: challenge does not match")
	}
	if cd.Origin != origin {
		return fmt.Errorf("webauthn: origin %q is not %q", cd.Origin, origin)
	}
	return nil
}

type authData struct {
	flags     byte
	signCount uint32
	credID    []byte
}

func parseAuthData(b []byte, rpID string) (authData, error) {
	var a authData
	if len(b) < 37 {
		return a, errors.New("webauthn: authenticator data too short")
	}
	h := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(b[:32], h[:]) != 1 {
		return a, errors.New("webauthn: relying party does not match")
	}
	a.flags = b[32]
	a.signCount = binary.BigEndian.Uint32(b[33:37])
	if a.flags&flagUP == 0 || a.flags&flagUV == 0 {
		return a, errors.New("webauthn: user presence and verification are required")
	}
	if a.flags&flagAT != 0 {
		if len(b) < 55 {
			return a, errors.New("webauthn: attested data too short")
		}
		n := int(binary.BigEndian.Uint16(b[53:55]))
		if len(b) < 55+n {
			return a, errors.New("webauthn: credential ID truncated")
		}
		a.credID = b[55 : 55+n]
	}
	return a, nil
}

// VerifyRegistration checks a new credential and returns it.
func VerifyRegistration(clientDataJSON, authenticatorData, spki []byte, alg int, challenge []byte, origin, rpID string) (*Credential, error) {
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, origin); err != nil {
		return nil, err
	}
	a, err := parseAuthData(authenticatorData, rpID)
	if err != nil {
		return nil, err
	}
	if a.credID == nil {
		return nil, errors.New("webauthn: no credential in registration")
	}
	if _, err := parsePublicKey(spki, alg); err != nil {
		return nil, err
	}
	return &Credential{ID: append([]byte(nil), a.credID...), PublicKey: spki, Alg: alg, SignCount: a.signCount}, nil
}

func parsePublicKey(spki []byte, alg int) (any, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("webauthn: public key: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg != AlgES256 || k.Curve != elliptic.P256() {
			return nil, errors.New("webauthn: only ES256 on P-256 is accepted for EC keys")
		}
	case ed25519.PublicKey:
		if alg != AlgEdDSA {
			return nil, errors.New("webauthn: algorithm does not match the Ed25519 key")
		}
	default:
		return nil, errors.New("webauthn: unsupported key type")
	}
	return pub, nil
}

// VerifyAssertion checks an approval and returns the new signature counter.
func VerifyAssertion(c *Credential, clientDataJSON, authenticatorData, signature, challenge []byte, origin, rpID string) (uint32, error) {
	if err := checkClientData(clientDataJSON, "webauthn.get", challenge, origin); err != nil {
		return 0, err
	}
	a, err := parseAuthData(authenticatorData, rpID)
	if err != nil {
		return 0, err
	}
	pub, err := parsePublicKey(c.PublicKey, c.Alg)
	if err != nil {
		return 0, err
	}
	cdh := sha256.Sum256(clientDataJSON)
	msg := append(append([]byte(nil), authenticatorData...), cdh[:]...)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		ok = ecdsa.VerifyASN1(k, d[:], signature)
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, msg, signature)
	}
	if !ok {
		return 0, errors.New("webauthn: signature does not verify")
	}
	// A counter that goes backwards means a cloned authenticator. Passkeys
	// that sync across devices always report 0.
	if (a.signCount != 0 || c.SignCount != 0) && a.signCount <= c.SignCount {
		return 0, errors.New("webauthn: signature counter went backwards")
	}
	return a.signCount, nil
}

// KEK derives the key-encryption key from a PRF output.
func KEK(prfOutput []byte) ([]byte, error) {
	if len(prfOutput) != 32 {
		return nil, errors.New("webauthn: PRF output must be 32 bytes")
	}
	return hkdf.Key(sha256.New, prfOutput, nil, "vogt/v1/prf-kek", 32)
}

// WrapDEK seals a DEK under a PRF-derived key. aad binds it to one secret
// version and one credential.
func WrapDEK(kek, dek, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, dek, aad), nil
}

// UnwrapDEK opens a WrapDEK result.
func UnwrapDEK(kek, wrapped, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, wrapped, aad)
}
