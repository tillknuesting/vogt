package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

// SoftAuthenticator is a software authenticator for tests. It behaves like
// a platform authenticator with user verification and the PRF extension.
type SoftAuthenticator struct {
	Key     *ecdsa.PrivateKey
	CredID  []byte
	prfSeed []byte
	Count   uint32
}

// NewSoftAuthenticator makes one.
func NewSoftAuthenticator() *SoftAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	seed := make([]byte, 32)
	rand.Read(seed)
	return &SoftAuthenticator{Key: k, CredID: id, prfSeed: seed}
}

func (s *SoftAuthenticator) clientData(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(clientData{Type: typ, Challenge: base64.RawURLEncoding.EncodeToString(challenge), Origin: origin})
	return b
}

func (s *SoftAuthenticator) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte(nil), h[:]...)
	flags := byte(flagUP | flagUV)
	if attested {
		flags |= flagAT
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, s.Count)
	if attested {
		b = append(b, make([]byte, 16)...) // AAGUID
		b = binary.BigEndian.AppendUint16(b, uint16(len(s.CredID)))
		b = append(b, s.CredID...)
		b = append(b, 0xa0) // an empty CBOR map where the key would be; unused
	}
	return b
}

// Register returns what the browser would post for navigator.credentials.create.
func (s *SoftAuthenticator) Register(challenge []byte, origin, rpID string) (clientDataJSON, authenticatorData, spki []byte) {
	spki, _ = x509.MarshalPKIXPublicKey(&s.Key.PublicKey)
	return s.clientData("webauthn.create", challenge, origin), s.authData(rpID, true), spki
}

// Assert returns what the browser would post for navigator.credentials.get.
func (s *SoftAuthenticator) Assert(challenge []byte, origin, rpID string) (clientDataJSON, authenticatorData, signature []byte) {
	s.Count++
	cd := s.clientData("webauthn.get", challenge, origin)
	ad := s.authData(rpID, false)
	cdh := sha256.Sum256(cd)
	d := sha256.Sum256(append(append([]byte(nil), ad...), cdh[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, s.Key, d[:])
	return cd, ad, sig
}

// PRF evaluates the credential's pseudo-random function on salt.
func (s *SoftAuthenticator) PRF(salt []byte) []byte {
	m := hmac.New(sha256.New, s.prfSeed)
	m.Write(salt)
	return m.Sum(nil)
}
