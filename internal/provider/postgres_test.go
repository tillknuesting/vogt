package provider

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePG is a PostgreSQL server that speaks just enough of the protocol:
// TLS, SCRAM-SHA-256-PLUS with channel binding, and simple queries.
type fakePG struct {
	l        net.Listener
	cert     tls.Certificate
	certPEM  []byte
	password string
	offerMD5 bool
	mu       sync.Mutex
	queries  []string
	sawMech  string
}

func newFakePG(t *testing.T) *fakePG {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	f := &fakePG{password: "admin-pw", cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
	f.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var err error
	if f.l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.l.Close() })
	go func() {
		for {
			c, err := f.l.Accept()
			if err != nil {
				return
			}
			go f.handle(c, der)
		}
	}()
	return f
}

func (f *fakePG) master() []byte {
	b, _ := json.Marshal(map[string]any{"host": "localhost", "port": f.l.Addr().(*net.TCPAddr).Port, "database": "orders", "user": "admin", "password": f.password, "ca_pem": string(f.certPEM)})
	return b
}

func pgMsg(typ byte, body []byte) []byte {
	m := []byte{typ}
	m = binary.BigEndian.AppendUint32(m, uint32(4+len(body)))
	return append(m, body...)
}

func authMsg(kind uint32, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, kind)
	return pgMsg('R', append(b, data...))
}

func (f *fakePG) handle(raw net.Conn, der []byte) {
	defer raw.Close()
	var hdr [8]byte
	io.ReadFull(raw, hdr[:])
	raw.Write([]byte{'S'})
	c := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	br := bufio.NewReader(c)
	var lenb [4]byte
	io.ReadFull(br, lenb[:])
	startup := make([]byte, binary.BigEndian.Uint32(lenb[:])-4)
	io.ReadFull(br, startup)

	if f.offerMD5 {
		c.Write(authMsg(5, []byte{1, 2, 3, 4}))
		return
	}
	c.Write(authMsg(10, []byte("SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00")))
	read := func() (byte, []byte) {
		var h [5]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			return 0, nil
		}
		b := make([]byte, binary.BigEndian.Uint32(h[1:])-4)
		io.ReadFull(br, b)
		return h[0], b
	}
	_, init := read()
	mech := string(init[:strings.IndexByte(string(init), 0)])
	f.mu.Lock()
	f.sawMech = mech
	f.mu.Unlock()
	clientFirst := string(init[len(mech)+5:])
	gs2End := strings.Index(clientFirst, ",,") + 2
	gs2, bare := clientFirst[:gs2End], clientFirst[gs2End:]
	cnonce := strings.TrimPrefix(bare[strings.Index(bare, "r="):], "r=")
	salt := []byte("0123456789abcdef")
	serverFirst := "r=" + cnonce + "srv,s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"
	c.Write(authMsg(11, []byte(serverFirst)))
	_, final := read()
	fs := string(final)
	withoutProof := fs[:strings.LastIndex(fs, ",p=")]
	proof, _ := base64.StdEncoding.DecodeString(fs[strings.LastIndex(fs, ",p=")+3:])
	// Channel binding must be the hash of our certificate.
	cbWant := sha256.Sum256(der)
	cWant := base64.StdEncoding.EncodeToString(append([]byte(gs2), cbWant[:]...))
	if !strings.HasPrefix(withoutProof, "c="+cWant+",") {
		c.Write(pgMsg('E', []byte("Mbad channel binding\x00\x00")))
		return
	}
	salted, _ := pbkdf2.Key(sha256.New, f.password, salt, 4096, 32)
	clientKey := hmacSum(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	auth := bare + "," + serverFirst + "," + withoutProof
	sig := hmacSum(stored[:], auth)
	got := make([]byte, len(proof))
	for i := range proof {
		got[i] = proof[i] ^ sig[i]
	}
	if gs := sha256.Sum256(got); !hmac.Equal(gs[:], stored[:]) {
		c.Write(pgMsg('E', []byte("Mpassword authentication failed\x00\x00")))
		return
	}
	c.Write(authMsg(12, []byte("v="+base64.StdEncoding.EncodeToString(hmacSum(hmacSum(salted, "Server Key"), auth)))))
	c.Write(authMsg(0, nil))
	c.Write(pgMsg('Z', []byte{'I'}))
	for {
		typ, body := read()
		switch typ {
		case 'Q':
			f.mu.Lock()
			f.queries = append(f.queries, strings.TrimRight(string(body), "\x00"))
			f.mu.Unlock()
			c.Write(pgMsg('C', []byte("OK\x00")))
			c.Write(pgMsg('Z', []byte{'I'}))
		default:
			return
		}
	}
}

func TestPostgresMintAndRevoke(t *testing.T) {
	f := newFakePG(t)
	p := Postgres{}
	req := Request{Direct: true, TTL: 10 * time.Minute, Scope: json.RawMessage(`{"grants":["USAGE ON SCHEMA orders","SELECT ON ALL TABLES IN SCHEMA orders"]}`)}
	cred, err := p.Mint(context.Background(), req, f.master())
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	mech, q := f.sawMech, append([]string(nil), f.queries...)
	f.mu.Unlock()
	if mech != "SCRAM-SHA-256-PLUS" {
		t.Fatalf("mechanism = %s", mech)
	}
	if len(q) != 3 || !strings.HasPrefix(q[0], `CREATE ROLE "vogt_`) || !strings.Contains(q[0], "SCRAM-SHA-256$4096:") || !strings.Contains(q[0], "VALID UNTIL") {
		t.Fatalf("queries = %q", q)
	}
	env := strings.Join(cred.Env(), "\n")
	if strings.Contains(q[0], pgPassword(env)) {
		t.Fatal("the role's password travelled to the server in clear")
	}
	if err := cred.(Revoker).Revoke(context.Background()); err != nil {
		t.Fatal(err)
	}
	cred.Wipe()
	f.mu.Lock()
	last := f.queries[len(f.queries)-1]
	f.mu.Unlock()
	if !strings.HasPrefix(last, `DROP ROLE "vogt_`) {
		t.Fatalf("last query = %s", last)
	}
}

func pgPassword(env string) string {
	for l := range strings.SplitSeq(env, "\n") {
		if v, ok := strings.CutPrefix(l, "PGPASSWORD="); ok {
			return v
		}
	}
	return "missing"
}

func TestPostgresRefusesMD5(t *testing.T) {
	f := newFakePG(t)
	f.offerMD5 = true
	_, err := Postgres{}.Mint(context.Background(), Request{Direct: true, TTL: time.Minute, Scope: json.RawMessage(`{"grants":["SELECT ON t"]}`)}, f.master())
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err = %v", err)
	}
}

func TestPostgresScopeRejectsInjection(t *testing.T) {
	for _, g := range []string{"SELECT ON t; DROP TABLE x", "ALL ON t TO public", "SELECT ON t --"} {
		if _, err := (Postgres{}).Permissions(Request{Scope: json.RawMessage(`{"grants":[` + strconvQuote(g) + `]}`)}); err == nil {
			t.Errorf("accepted %q", g)
		}
	}
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
