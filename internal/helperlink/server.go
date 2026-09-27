package helperlink

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"uuid"

	"vogt/internal/envelope"
	"vogt/internal/secmem"
	"vogt/internal/sig"
	"vogt/internal/wire"
)

var (
	ErrNoHelper = errors.New("helperlink: no approval helper is connected")
	ErrUnpaired = errors.New("helperlink: no helper is paired; run `vogt pair`")
	ErrTimeout  = errors.New("helperlink: no decision before the deadline")
)

// Result is a verified answer to a challenge.
type Result struct {
	Approved        bool
	Bundle          time.Duration
	DEKs            []*secmem.Buffer // in request order; caller destroys
	ApprovalSig     []byte
	ApprovalMessage []byte
}

// Destroy wipes the DEKs.
func (r *Result) Destroy() {
	for _, d := range r.DEKs {
		d.Destroy()
	}
}

// Server is the daemon side of the link.
type Server struct {
	identity *sig.PrivateKey

	mu      sync.Mutex
	keys    *HelperKeys
	conn    net.Conn
	writeMu *sync.Mutex
	waiters map[string]chan *Response

	// OnRevokeAll is called when the helper's kill switch is used.
	OnRevokeAll func()
	// OnConnect is called with true when a helper authenticates and false
	// when it disconnects.
	OnConnect func(bool)
}

// NewServer returns a server for the daemon identity. keys may be nil
// until a helper is paired.
func NewServer(identity *sig.PrivateKey, keys *HelperKeys) *Server {
	return &Server{identity: identity, keys: keys, waiters: map[string]chan *Response{}}
}

// SetKeys replaces the paired helper keys and drops any connected helper.
func (s *Server) SetKeys(k *HelperKeys) {
	s.mu.Lock()
	s.keys = k
	c := s.conn
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// Connected reports whether an authenticated helper is connected.
func (s *Server) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil
}

// Serve accepts helper connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	s.mu.Lock()
	keys := s.keys
	s.mu.Unlock()
	if keys == nil {
		return
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var nonce [32]byte
	rand.Read(nonce[:])
	pub := s.identity.Public().Bytes()
	hello := wire.NewEncoder(labelHello).PutUint(Version).PutBytes(pub).PutBytes(nonce[:]).Finish()
	if writeFrame(c, hello) != nil {
		return
	}
	msg, err := readFrame(c)
	if err != nil {
		return
	}
	d := wire.NewDecoder(msg, labelHelloReply)
	v, chPub, sg := d.ReadUint(), d.ReadBytes(), d.ReadBytes()
	if d.Finish() != nil || v != Version || !bytes.Equal(chPub, keys.Channel.Bytes()) {
		return
	}
	if keys.Channel.Verify(PurposeHello, helloMessage(nonce[:], Fingerprint(pub)), sg) != nil {
		return
	}
	c.SetDeadline(time.Time{})

	wmu := &sync.Mutex{}
	s.mu.Lock()
	old := s.conn
	s.conn, s.writeMu = c, wmu
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if s.OnConnect != nil {
		s.OnConnect(true)
	}
	defer func() {
		s.mu.Lock()
		if s.conn == c {
			s.conn = nil
		}
		s.mu.Unlock()
		if s.OnConnect != nil {
			s.OnConnect(false)
		}
	}()

	for {
		msg, err := readFrame(c)
		if err != nil {
			return
		}
		switch label(msg) {
		case labelResponse:
			r, err := decodeResponse(msg)
			if err != nil || keys.Channel.Verify(PurposeResponse, r.body(), r.ChannelSig) != nil {
				continue
			}
			s.mu.Lock()
			ch := s.waiters[r.ID]
			delete(s.waiters, r.ID)
			s.mu.Unlock()
			if ch != nil {
				ch <- r
			}
		case labelRevokeAll:
			d := wire.NewDecoder(msg, labelRevokeAll)
			n, sg := d.ReadBytes(), d.ReadBytes()
			if d.Finish() == nil && keys.Channel.Verify(PurposeRevokeAll, revokeAllMessage(n), sg) == nil && s.OnRevokeAll != nil {
				s.OnRevokeAll()
			}
		}
	}
}

// Ask sends a challenge and waits for a verified decision. It fills in the
// ID, nonce, deadline and reply key. A denial, a timeout and a helper that
// disconnects all end with Approved false or an error; never with DEKs.
func (s *Server) Ask(ctx context.Context, ch Challenge, timeout time.Duration) (*Result, error) {
	s.mu.Lock()
	keys, c, wmu := s.keys, s.conn, s.writeMu
	s.mu.Unlock()
	if keys == nil {
		return nil, ErrUnpaired
	}
	if c == nil {
		return nil, ErrNoHelper
	}
	if ch.Kind == KindUnwrap {
		for _, d := range ch.DEKs {
			if d.Tier != envelope.TierLow {
				return nil, errors.New("helperlink: unwrap challenges carry low-tier DEKs only")
			}
		}
	}
	if ch.ID == "" {
		ch.ID = uuid.New().String()
	}
	rand.Read(ch.Nonce[:])
	ch.NotAfter = time.Now().Add(timeout).Unix()
	replyKey, err := envelope.SuiteReply.GenerateKey()
	if err != nil {
		return nil, err
	}
	ch.ReplyKey = replyKey.PublicKey().Bytes()

	body := ch.encode()
	sg, err := s.identity.Sign(PurposeChallenge, body)
	if err != nil {
		return nil, err
	}
	wait := make(chan *Response, 1)
	s.mu.Lock()
	s.waiters[ch.ID] = wait
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.waiters, ch.ID)
		s.mu.Unlock()
	}()

	wmu.Lock()
	err = writeFrame(c, wire.NewEncoder(labelSigned).PutBytes(body).PutBytes(sg).Finish())
	wmu.Unlock()
	if err != nil {
		return nil, ErrNoHelper
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case r := <-wait:
		return s.verify(keys, &ch, replyKey, r)
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrTimeout
		}
		return nil, ctx.Err()
	}
}

func (s *Server) verify(keys *HelperKeys, ch *Challenge, replyKey hpke.PrivateKey, r *Response) (*Result, error) {
	if r.Decision != Approve {
		return &Result{}, nil
	}
	if time.Now().Unix() > ch.NotAfter {
		return nil, ErrTimeout
	}
	if r.BundleMinutes > ch.MaxBundle {
		return nil, errors.New("helperlink: bundle longer than offered")
	}
	res := &Result{Approved: true, Bundle: time.Duration(r.BundleMinutes) * time.Minute}
	if ch.Kind != KindUnwrap {
		m := ApprovalMessage(ch.ID, ch.Digest, ch.Nonce, Approve, r.BundleMinutes)
		if keys.Approval.Verify(PurposeApproval, m, r.ApprovalSig) != nil {
			return nil, errors.New("helperlink: approval signature is invalid")
		}
		res.ApprovalSig, res.ApprovalMessage = r.ApprovalSig, m
	}
	if len(r.DEKs) != len(ch.DEKs) {
		return nil, fmt.Errorf("helperlink: got %d DEKs, want %d", len(r.DEKs), len(ch.DEKs))
	}
	for i, w := range r.DEKs {
		dek, err := envelope.Unwrap(replyKey, DEKReplyPurpose, DEKReplyAAD(ch.ID, i), w)
		if err != nil {
			res.Destroy()
			return nil, errors.New("helperlink: returned DEK does not open")
		}
		buf, err := secmem.FromBytes(dek)
		if err != nil {
			res.Destroy()
			return nil, err
		}
		res.DEKs = append(res.DEKs, buf)
	}
	return res, nil
}
