// Package token makes and checks Vogt's bearer tokens.
//
// A token is a typed prefix followed by lowercase base32 (no padding) of 32
// random bytes and their CRC32. The prefix and checksum let secret scanners
// recognise a leaked token with few false positives. The daemon stores only
// SHA-256 hashes of tokens.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"hash/crc32"
	"strings"
)

// Kind is a token's type, carried in its prefix.
type Kind string

const (
	Session Kind = "vogt_s_" // identifies an agent session
	Proxy   Kind = "vogt_p_" // authorizes proxied calls for one grant
)

var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// New returns a fresh token of the given kind and its hash.
func New(k Kind) (string, [32]byte) {
	var body [36]byte
	rand.Read(body[:32])
	binary.BigEndian.PutUint32(body[32:], crc32.ChecksumIEEE(body[:32]))
	tok := string(k) + enc.EncodeToString(body[:])
	return tok, Hash(tok)
}

// Hash returns the value the daemon stores for tok.
func Hash(tok string) [32]byte {
	return sha256.Sum256([]byte(tok))
}

// Parse reports the kind of a well-formed token. It checks the prefix,
// length and checksum, not whether the token was ever issued.
func Parse(tok string) (Kind, bool) {
	for _, k := range []Kind{Session, Proxy} {
		rest, ok := strings.CutPrefix(tok, string(k))
		if !ok {
			continue
		}
		body, err := enc.DecodeString(rest)
		if err != nil || len(body) != 36 {
			return "", false
		}
		sum := crc32.ChecksumIEEE(body[:32])
		if subtle.ConstantTimeEq(int32(sum), int32(binary.BigEndian.Uint32(body[32:]))) != 1 {
			return "", false
		}
		return k, true
	}
	return "", false
}

// Equal compares two hashes in constant time.
func Equal(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
