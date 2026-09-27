// Package helperlink is the protocol between the Vogt daemon and the approval
// helper, the process in the user's login session that holds the Secure
// Enclave keys and shows Touch ID prompts.
//
// The helper connects to the daemon's helper socket. Both sides are pinned to
// each other at pairing time: the daemon knows the helper's channel and
// approval keys and its two tier KEM keys, and the helper knows the daemon's
// identity key.
//
// Messages are wire-encoded and framed with a 4-byte big-endian length.
//
//	daemon → helper  hello        daemon public key, random nonce
//	helper → daemon  hello-reply  channel key signs (nonce, daemon fingerprint)
//	daemon → helper  challenge    signed by the daemon identity key
//	helper → daemon  response     signed by the channel key; approvals also
//	                              by the approval key; DEKs sealed with X-Wing
//	helper → daemon  revoke-all   the menu-bar kill switch, channel-signed
//
// A challenge of kind "grant" or "admin" needs a Touch ID tap. Kind "unwrap"
// only releases low-tier DEKs and needs no tap while the helper is unlocked.
package helperlink

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"vogt/internal/envelope"
	"vogt/internal/wire"
)

// Version is the protocol version both sides must speak.
const Version = 1

const maxFrame = 4 << 20

// Challenge kinds.
const (
	KindGrant  = "grant"
	KindAdmin  = "admin"
	KindUnwrap = "unwrap"
)

// Decisions.
const (
	Deny    uint64 = 0
	Approve uint64 = 1
)

// Message labels.
const (
	labelHello      = "vogt/v1/hl-hello"
	labelHelloReply = "vogt/v1/hl-hello-reply"
	labelChallenge  = "vogt/v1/hl-challenge"
	labelSigned     = "vogt/v1/hl-signed-challenge"
	labelResponse   = "vogt/v1/hl-response"
	labelRespBody   = "vogt/v1/hl-response-body"
	labelApproval   = "vogt/v1/hl-approval"
	labelDEKRequest = "vogt/v1/hl-dek-request"
	labelRevokeAll  = "vogt/v1/hl-revoke-all"
	labelHelperKeys = "vogt/v1/helper-keys"
)

// Signature purposes.
const (
	PurposeHello     = "hello"
	PurposeChallenge = "challenge"
	PurposeResponse  = "response"
	PurposeApproval  = "approval"
	PurposeRevokeAll = "revoke-all"
	purposeDEKReply  = "dek-reply"
)

// DEKRequest is one wrapped DEK the daemon needs back.
type DEKRequest struct {
	Tier    envelope.Tier
	Wrapped []byte // envelope.Wrap output, SuiteVault
	AAD     []byte // vault.WrapAAD for the secret
}

// Challenge asks the helper for a decision.
type Challenge struct {
	ID        string
	Kind      string
	Display   string   // rendered by the daemon; the helper shows it verbatim
	Digest    [32]byte // what is being approved, e.g. the grant or policy hash
	DEKs      []DEKRequest
	ReplyKey  []byte // X-Wing public key for the DEKs coming back
	Nonce     [32]byte
	NotAfter  int64  // Unix seconds
	MaxBundle uint64 // minutes the human may extend this approval to; 0 = none
}

func (c *Challenge) encode() []byte {
	deks := make([][]byte, len(c.DEKs))
	for i, d := range c.DEKs {
		deks[i] = wire.NewEncoder(labelDEKRequest).PutUint(uint64(d.Tier)).PutBytes(d.Wrapped).PutBytes(d.AAD).Finish()
	}
	return wire.NewEncoder(labelChallenge).
		PutUint(Version).
		PutString(c.ID).
		PutString(c.Kind).
		PutString(c.Display).
		PutBytes(c.Digest[:]).
		PutList(deks).
		PutBytes(c.ReplyKey).
		PutBytes(c.Nonce[:]).
		PutUint(uint64(c.NotAfter)).
		PutUint(c.MaxBundle).
		Finish()
}

// DecodeChallenge parses a challenge body.
func DecodeChallenge(b []byte) (*Challenge, error) {
	d := wire.NewDecoder(b, labelChallenge)
	v := d.ReadUint()
	c := &Challenge{ID: d.ReadString(), Kind: d.ReadString(), Display: d.ReadString()}
	digest := d.ReadBytes()
	deks := d.ReadList()
	c.ReplyKey = d.ReadBytes()
	nonce := d.ReadBytes()
	c.NotAfter = int64(d.ReadUint())
	c.MaxBundle = d.ReadUint()
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if v != Version || len(digest) != 32 || len(nonce) != 32 {
		return nil, errors.New("helperlink: malformed challenge")
	}
	copy(c.Digest[:], digest)
	copy(c.Nonce[:], nonce)
	for _, raw := range deks {
		dd := wire.NewDecoder(raw, labelDEKRequest)
		r := DEKRequest{Tier: envelope.Tier(dd.ReadUint()), Wrapped: dd.ReadBytes(), AAD: dd.ReadBytes()}
		if err := dd.Finish(); err != nil {
			return nil, err
		}
		c.DEKs = append(c.DEKs, r)
	}
	switch c.Kind {
	case KindGrant, KindAdmin, KindUnwrap:
	default:
		return nil, fmt.Errorf("helperlink: unknown challenge kind %q", c.Kind)
	}
	return c, nil
}

// ApprovalMessage is what the approval key signs. The daemon keeps it with
// the signature as evidence of exactly what the human approved.
func ApprovalMessage(id string, digest, nonce [32]byte, decision, bundle uint64) []byte {
	return wire.NewEncoder(labelApproval).
		PutString(id).PutBytes(digest[:]).PutBytes(nonce[:]).PutUint(decision).PutUint(bundle).Finish()
}

// Response answers a challenge.
type Response struct {
	ID            string
	Decision      uint64
	BundleMinutes uint64
	ApprovalSig   []byte   // empty for denials and unwrap challenges
	DEKs          [][]byte // envelope.Wrap to the reply key, in request order
	ChannelSig    []byte
}

func (r *Response) body() []byte {
	return wire.NewEncoder(labelRespBody).
		PutString(r.ID).PutUint(r.Decision).PutUint(r.BundleMinutes).
		PutBytes(r.ApprovalSig).PutList(r.DEKs).Finish()
}

func (r *Response) encode() []byte {
	return wire.NewEncoder(labelResponse).PutBytes(r.body()).PutBytes(r.ChannelSig).Finish()
}

func decodeResponse(b []byte) (*Response, error) {
	d := wire.NewDecoder(b, labelResponse)
	body, s := d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		return nil, err
	}
	bd := wire.NewDecoder(body, labelRespBody)
	r := &Response{ID: bd.ReadString(), Decision: bd.ReadUint(), BundleMinutes: bd.ReadUint(), ApprovalSig: bd.ReadBytes(), DEKs: bd.ReadList(), ChannelSig: s}
	if err := bd.Finish(); err != nil {
		return nil, err
	}
	return r, nil
}

// DEKReplyAAD binds a returned DEK to its challenge and position.
func DEKReplyAAD(challengeID string, i int) []byte {
	return wire.NewEncoder("vogt/v1/hl-dek-reply").PutString(challengeID).PutUint(uint64(i)).Finish()
}

// DEKReplyPurpose is the HPKE purpose for DEKs sent back to the daemon.
const DEKReplyPurpose = purposeDEKReply

func helloMessage(nonce []byte, daemonFP [32]byte) []byte {
	return wire.NewEncoder("vogt/v1/hl-hello-msg").PutBytes(nonce).PutBytes(daemonFP[:]).Finish()
}

func revokeAllMessage(nonce []byte) []byte {
	return wire.NewEncoder("vogt/v1/hl-revoke-all-msg").PutBytes(nonce).Finish()
}

// Fingerprint is the SHA-256 of an encoded public key.
func Fingerprint(pub []byte) [32]byte { return sha256.Sum256(pub) }

// label returns the domain label of a wire message, for dispatch.
func label(msg []byte) string {
	if len(msg) < 5 || msg[0] != 0x03 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(msg[1:5]))
	if n > len(msg)-5 {
		return ""
	}
	return string(msg[5 : 5+n])
}

func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > maxFrame {
		return errors.New("helperlink: frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	if _, err := w.Write(append(hdr[:], msg...)); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, errors.New("helperlink: frame too large")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
