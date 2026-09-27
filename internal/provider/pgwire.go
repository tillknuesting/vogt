package provider

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"time"
)

// A minimal PostgreSQL client: protocol 3.0 startup, TLS, SCRAM-SHA-256 and
// SCRAM-SHA-256-PLUS authentication, and simple queries. Cleartext and MD5
// password authentication are refused.

type pgConn struct {
	c  net.Conn
	br *bufio.Reader
}

// PGConfig says how to reach a server.
type PGConfig struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
	// SSLMode is "verify-full" (default) or "disable", which is only allowed
	// for loopback addresses.
	SSLMode string
	RootCAs *x509.CertPool
}

func pgConnect(ctx context.Context, cfg PGConfig) (*pgConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "verify-full"
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	} else {
		raw.SetDeadline(time.Now().Add(30 * time.Second))
	}
	conn := raw
	var tlsConn *tls.Conn
	switch cfg.SSLMode {
	case "disable":
		if ip := net.ParseIP(cfg.Host); cfg.Host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			raw.Close()
			return nil, errors.New("postgres: sslmode=disable is only allowed for loopback hosts")
		}
	case "verify-full":
		var req [8]byte
		binary.BigEndian.PutUint32(req[0:], 8)
		binary.BigEndian.PutUint32(req[4:], 80877103)
		if _, err := raw.Write(req[:]); err != nil {
			raw.Close()
			return nil, err
		}
		var resp [1]byte
		if _, err := io.ReadFull(raw, resp[:]); err != nil {
			raw.Close()
			return nil, err
		}
		if resp[0] != 'S' {
			raw.Close()
			return nil, errors.New("postgres: server does not support TLS")
		}
		tlsConn = tls.Client(raw, &tls.Config{ServerName: cfg.Host, RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("postgres: TLS: %w", err)
		}
		conn = tlsConn
	default:
		raw.Close()
		return nil, fmt.Errorf("postgres: sslmode %q is not supported; use verify-full", cfg.SSLMode)
	}

	pc := &pgConn{c: conn, br: bufio.NewReader(conn)}
	var startup []byte
	startup = binary.BigEndian.AppendUint32(startup, 0)
	startup = binary.BigEndian.AppendUint32(startup, 196608)
	for _, kv := range [][2]string{{"user", cfg.User}, {"database", cfg.Database}, {"application_name", "vogt"}} {
		startup = append(append(append(append(startup, kv[0]...), 0), kv[1]...), 0)
	}
	startup = append(startup, 0)
	binary.BigEndian.PutUint32(startup, uint32(len(startup)))
	if _, err := conn.Write(startup); err != nil {
		conn.Close()
		return nil, err
	}
	if err := pc.authenticate(cfg.Password, tlsConn); err != nil {
		conn.Close()
		return nil, err
	}
	return pc, nil
}

func (pc *pgConn) send(typ byte, body []byte) error {
	msg := make([]byte, 0, 5+len(body))
	msg = append(msg, typ)
	msg = binary.BigEndian.AppendUint32(msg, uint32(4+len(body)))
	msg = append(msg, body...)
	_, err := pc.c.Write(msg)
	return err
}

func (pc *pgConn) recv() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(pc.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n < 4 || n > 1<<24 {
		return 0, nil, errors.New("postgres: bad message length")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(pc.br, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

func pgError(body []byte) error {
	var msg, code string
	for len(body) > 1 {
		f := body[0]
		end := strings.IndexByte(string(body[1:]), 0)
		if end < 0 {
			break
		}
		v := string(body[1 : 1+end])
		switch f {
		case 'M':
			msg = v
		case 'C':
			code = v
		}
		body = body[2+end:]
	}
	return fmt.Errorf("postgres: %s (%s)", msg, code)
}

func (pc *pgConn) authenticate(password string, tlsConn *tls.Conn) error {
	var scram *scramClient
	for {
		typ, body, err := pc.recv()
		if err != nil {
			return err
		}
		switch typ {
		case 'E':
			return pgError(body)
		case 'R':
			if len(body) < 4 {
				return errors.New("postgres: short auth message")
			}
			kind, data := binary.BigEndian.Uint32(body), body[4:]
			switch kind {
			case 0: // AuthenticationOk
			case 10: // SASL
				mechs := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
				scram, err = newScram(password, mechs, tlsConn)
				if err != nil {
					return err
				}
				first := scram.clientFirst()
				msg := append([]byte(scram.mechanism), 0)
				msg = binary.BigEndian.AppendUint32(msg, uint32(len(first)))
				msg = append(msg, first...)
				if err := pc.send('p', msg); err != nil {
					return err
				}
			case 11: // SASLContinue
				if scram == nil {
					return errors.New("postgres: unexpected SASL continue")
				}
				final, err := scram.clientFinal(string(data))
				if err != nil {
					return err
				}
				if err := pc.send('p', []byte(final)); err != nil {
					return err
				}
			case 12: // SASLFinal
				if scram == nil || !scram.verifyServer(string(data)) {
					return errors.New("postgres: server SCRAM signature is invalid")
				}
				scram.done = true
			default:
				return fmt.Errorf("postgres: authentication method %d is refused; only SCRAM is allowed", kind)
			}
		case 'Z':
			if scram == nil || !scram.done {
				return errors.New("postgres: server skipped authentication")
			}
			return nil
		case 'S', 'K', 'N':
			// parameter status, backend key, notice
		default:
			return fmt.Errorf("postgres: unexpected message %q during startup", typ)
		}
	}
}

// Exec runs one simple query and returns an error from the server, if any.
func (pc *pgConn) Exec(sql string) error {
	if err := pc.send('Q', append([]byte(sql), 0)); err != nil {
		return err
	}
	var firstErr error
	for {
		typ, body, err := pc.recv()
		if err != nil {
			return err
		}
		switch typ {
		case 'E':
			if firstErr == nil {
				firstErr = pgError(body)
			}
		case 'Z':
			return firstErr
		}
	}
}

func (pc *pgConn) Close() error {
	pc.send('X', nil)
	return pc.c.Close()
}

// --- SCRAM-SHA-256 (RFC 5802, RFC 7677) ------------------------------------

type scramClient struct {
	password    string
	mechanism   string
	gs2         string
	cbind       []byte
	nonce       string
	clientBare  string
	authMessage string
	salted      []byte
	done        bool
}

func newScram(password string, mechs []string, tlsConn *tls.Conn) (*scramClient, error) {
	has := func(m string) bool {
		for _, x := range mechs {
			if x == m {
				return true
			}
		}
		return false
	}
	s := &scramClient{password: password}
	switch {
	case tlsConn != nil && has("SCRAM-SHA-256-PLUS"):
		cb, err := tlsServerEndPoint(tlsConn)
		if err != nil {
			return nil, err
		}
		s.mechanism, s.gs2, s.cbind = "SCRAM-SHA-256-PLUS", "p=tls-server-end-point,,", cb
	case has("SCRAM-SHA-256"):
		s.mechanism, s.gs2 = "SCRAM-SHA-256", "n,,"
		if tlsConn != nil {
			// We support channel binding but the server did not offer it.
			s.gs2 = "y,,"
		}
	default:
		return nil, fmt.Errorf("postgres: server offers %v; SCRAM-SHA-256 is required", mechs)
	}
	n := make([]byte, 24)
	rand.Read(n)
	s.nonce = base64.RawStdEncoding.EncodeToString(n)
	return s, nil
}

// tlsServerEndPoint is the RFC 5929 channel binding: the hash of the server
// certificate, with SHA-256 unless the certificate uses a stronger hash.
func tlsServerEndPoint(c *tls.Conn) ([]byte, error) {
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("postgres: no server certificate for channel binding")
	}
	cert := certs[0]
	var h hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write(cert.Raw)
	return h.Sum(nil), nil
}

func (s *scramClient) clientFirst() string {
	s.clientBare = "n=,r=" + s.nonce
	return s.gs2 + s.clientBare
}

func (s *scramClient) clientFinal(serverFirst string) (string, error) {
	var nonce, salt64 string
	iter := 0
	for _, part := range strings.Split(serverFirst, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "r":
			nonce = v
		case "s":
			salt64 = v
		case "i":
			fmt.Sscan(v, &iter)
		}
	}
	if !strings.HasPrefix(nonce, s.nonce) || len(nonce) == len(s.nonce) {
		return "", errors.New("postgres: server nonce does not extend ours")
	}
	if iter < 4096 {
		return "", errors.New("postgres: SCRAM iteration count below 4096")
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil {
		return "", errors.New("postgres: bad SCRAM salt")
	}
	s.salted, err = pbkdf2.Key(sha256.New, s.password, salt, iter, 32)
	if err != nil {
		return "", err
	}
	cbind := base64.StdEncoding.EncodeToString(append([]byte(s.gs2), s.cbind...))
	withoutProof := "c=" + cbind + ",r=" + nonce
	s.authMessage = s.clientBare + "," + serverFirst + "," + withoutProof
	clientKey := hmacSum(s.salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	sig := hmacSum(stored[:], s.authMessage)
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ sig[i]
	}
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

func (s *scramClient) verifyServer(serverFinal string) bool {
	v, ok := strings.CutPrefix(serverFinal, "v=")
	if !ok || s.salted == nil {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return false
	}
	want := hmacSum(hmacSum(s.salted, "Server Key"), s.authMessage)
	return hmac.Equal(got, want)
}

func hmacSum(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// ScramVerifier returns the stored form of a password, so the password
// itself never travels to the server in a CREATE ROLE statement.
func ScramVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	const iter = 4096
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return "", err
	}
	stored := sha256.Sum256(hmacSum(salted, "Client Key"))
	server := hmacSum(salted, "Server Key")
	b := base64.StdEncoding
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, b.EncodeToString(salt), b.EncodeToString(stored[:]), b.EncodeToString(server)), nil
}
