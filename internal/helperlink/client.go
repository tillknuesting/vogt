package helperlink

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"vogt/internal/envelope"
	"vogt/internal/sig"
	"vogt/internal/wire"
)

// Keyring holds the helper's private keys. On macOS the Swift helper keeps
// them in the Secure Enclave; the Go implementation here backs the software
// helper used for tests and development.
type Keyring interface {
	ChannelPublic() *sig.PublicKey
	ChannelSign(purpose string, msg []byte) ([]byte, error)
	// ApprovalSign must only be called after the human approved.
	ApprovalSign(purpose string, msg []byte) ([]byte, error)
	UnwrapDEK(tier envelope.Tier, wrapped, aad []byte) ([]byte, error)
	// LowUnlocked reports whether the low tier was unlocked this login.
	LowUnlocked() bool
}

// Approver asks the human. It returns the decision and, if the challenge
// offers one, the bundle length in minutes the human chose.
type Approver interface {
	Approve(ch *Challenge) (approved bool, bundleMinutes uint64)
}

// Client is the helper side of the link.
type Client struct {
	Keyring  Keyring
	Approver Approver

	// DaemonPin is the pinned daemon fingerprint. If nil, TrustFirst is asked
	// to accept the daemon's key, and OnPin records the answer.
	DaemonPin  *[32]byte
	TrustFirst func(fp [32]byte) bool
	OnPin      func(fp [32]byte)

	mu     sync.Mutex
	conn   net.Conn
	nonces map[[32]byte]bool
}

var ErrWrongDaemon = errors.New("helperlink: daemon key does not match the pinned fingerprint")

// Serve runs the protocol on an established connection until it closes.
func (c *Client) Serve(conn net.Conn) error {
	defer conn.Close()
	msg, err := readFrame(conn)
	if err != nil {
		return err
	}
	d := wire.NewDecoder(msg, labelHello)
	v, daemonPub, nonce := d.ReadUint(), d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		return err
	}
	if v != Version {
		return fmt.Errorf("helperlink: daemon speaks version %d", v)
	}
	fp := Fingerprint(daemonPub)
	if c.DaemonPin == nil {
		if c.TrustFirst == nil || !c.TrustFirst(fp) {
			return ErrWrongDaemon
		}
		c.DaemonPin = &fp
		if c.OnPin != nil {
			c.OnPin(fp)
		}
	} else if *c.DaemonPin != fp {
		return ErrWrongDaemon
	}
	daemonKey, err := sig.ParsePublicKey(daemonPub)
	if err != nil {
		return err
	}
	s, err := c.Keyring.ChannelSign(PurposeHello, helloMessage(nonce, fp))
	if err != nil {
		return err
	}
	reply := wire.NewEncoder(labelHelloReply).PutUint(Version).PutBytes(c.Keyring.ChannelPublic().Bytes()).PutBytes(s).Finish()
	if err := writeFrame(conn, reply); err != nil {
		return err
	}

	c.mu.Lock()
	c.conn = conn
	if c.nonces == nil {
		c.nonces = map[[32]byte]bool{}
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	for {
		msg, err := readFrame(conn)
		if err != nil {
			return err
		}
		if label(msg) != labelSigned {
			continue
		}
		d := wire.NewDecoder(msg, labelSigned)
		body, bs := d.ReadBytes(), d.ReadBytes()
		if d.Finish() != nil || daemonKey.Verify(PurposeChallenge, body, bs) != nil {
			continue
		}
		ch, err := DecodeChallenge(body)
		if err != nil {
			continue
		}
		go c.answer(conn, ch)
	}
}

func (c *Client) answer(conn net.Conn, ch *Challenge) {
	r := c.decide(ch)
	body := r.body()
	s, err := c.Keyring.ChannelSign(PurposeResponse, body)
	if err != nil {
		return
	}
	r.ChannelSig = s
	c.mu.Lock()
	defer c.mu.Unlock()
	writeFrame(conn, r.encode())
}

func (c *Client) decide(ch *Challenge) *Response {
	deny := &Response{ID: ch.ID, Decision: Deny}
	if time.Now().Unix() > ch.NotAfter {
		return deny
	}
	c.mu.Lock()
	replay := c.nonces[ch.Nonce]
	c.nonces[ch.Nonce] = true
	c.mu.Unlock()
	if replay {
		return deny
	}
	kem, _ := envelope.SuiteReply.KEM()
	pk, err := kem.NewPublicKey(ch.ReplyKey)
	if err != nil {
		return deny
	}

	r := &Response{ID: ch.ID, Decision: Approve}
	if ch.Kind == KindUnwrap {
		if !c.Keyring.LowUnlocked() {
			return deny
		}
		for _, d := range ch.DEKs {
			if d.Tier != envelope.TierLow {
				return deny
			}
		}
	} else {
		ok, bundle := c.Approver.Approve(ch)
		if !ok {
			return deny
		}
		if bundle > ch.MaxBundle {
			bundle = ch.MaxBundle
		}
		r.BundleMinutes = bundle
		sg, err := c.Keyring.ApprovalSign(PurposeApproval, ApprovalMessage(ch.ID, ch.Digest, ch.Nonce, Approve, bundle))
		if err != nil {
			return deny
		}
		r.ApprovalSig = sg
	}

	for i, d := range ch.DEKs {
		dek, err := c.Keyring.UnwrapDEK(d.Tier, d.Wrapped, d.AAD)
		if err != nil {
			return deny
		}
		w, err := envelope.Wrap(pk, DEKReplyPurpose, DEKReplyAAD(ch.ID, i), dek)
		clear(dek)
		if err != nil {
			return deny
		}
		r.DEKs = append(r.DEKs, w)
	}
	return r
}

// RevokeAll sends the kill switch to the daemon.
func (c *Client) RevokeAll(nonce [32]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return ErrNoHelper
	}
	s, err := c.Keyring.ChannelSign(PurposeRevokeAll, revokeAllMessage(nonce[:]))
	if err != nil {
		return err
	}
	return writeFrame(c.conn, wire.NewEncoder(labelRevokeAll).PutBytes(nonce[:]).PutBytes(s).Finish())
}
