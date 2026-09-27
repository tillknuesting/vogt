package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"vogt/internal/secmem"
)

// Postgres creates a login role per grant with only the capability's
// grants, and drops it when the grant ends. Direct mode only in v1.
//
// The master secret is JSON: {"host": "...", "port": 5432, "database":
// "...", "user": "...", "password": "...", "sslmode": "verify-full",
// "ca_pem": "optional PEM bundle"}. The user needs CREATEROLE and the
// privileges it hands out.
type Postgres struct{}

type pgScope struct {
	Grants []string `json:"grants"`
}

type pgMaster struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSLMode  string `json:"sslmode"`
	CAPEM    string `json:"ca_pem"`
}

// grantText allows privilege lists and object names, and nothing that could
// end the statement or add another.
var grantText = regexp.MustCompile(`^[A-Za-z0-9_ ,."*()]+$`)

func (Postgres) Name() string { return "postgres" }

func (Postgres) Guarantees() Guarantees {
	return Guarantees{Revoke: RevokeImmediate}
}

func (Postgres) scope(req Request) (pgScope, error) {
	var s pgScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return s, err
	}
	if len(s.Grants) == 0 {
		return s, errors.New("postgres scope needs grants")
	}
	for _, g := range s.Grants {
		if !grantText.MatchString(g) || strings.Contains(strings.ToUpper(g), " TO ") {
			return s, fmt.Errorf("postgres grant %q is not allowed", g)
		}
	}
	return s, nil
}

func (p Postgres) Permissions(req Request) ([]string, error) {
	s, err := p.scope(req)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(s.Grants))
	for i, g := range s.Grants {
		out[i] = "postgres:" + g
	}
	return out, nil
}

func (m pgMaster) config() (PGConfig, error) {
	cfg := PGConfig{Host: m.Host, Port: m.Port, Database: m.Database, User: m.User, Password: m.Password, SSLMode: m.SSLMode}
	if m.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(m.CAPEM)) {
			return cfg, errors.New("postgres: ca_pem holds no certificates")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func quoteLit(s string) string   { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

func (p Postgres) Mint(ctx context.Context, req Request, master []byte) (Credential, error) {
	if !req.Direct {
		return nil, errors.New("postgres grants are direct mode only")
	}
	s, err := p.scope(req)
	if err != nil {
		return nil, err
	}
	var m pgMaster
	if err := json.Unmarshal(master, &m); err != nil || m.Host == "" || m.User == "" {
		return nil, errors.New("postgres master secret needs host, user and password")
	}
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	rb := make([]byte, 8)
	rand.Read(rb)
	role := "vogt_" + hex.EncodeToString(rb)
	pw := make([]byte, 32)
	rand.Read(pw)
	password := base64.RawURLEncoding.EncodeToString(pw)
	verifier, err := ScramVerifier(password)
	if err != nil {
		return nil, err
	}
	until := time.Now().Add(req.TTL).UTC().Format("2006-01-02 15:04:05+00")

	conn, err := pgConnect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stmts := []string{fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s VALID UNTIL %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 5",
		quoteIdent(role), quoteLit(verifier), quoteLit(until))}
	for _, g := range s.Grants {
		stmts = append(stmts, fmt.Sprintf("GRANT %s TO %s", g, quoteIdent(role)))
	}
	for _, st := range stmts {
		if err := conn.Exec(st); err != nil {
			conn.Exec("DROP OWNED BY " + quoteIdent(role))
			conn.Exec("DROP ROLE IF EXISTS " + quoteIdent(role))
			return nil, err
		}
	}
	mb, err := secmem.FromBytes(append([]byte(nil), master...))
	if err != nil {
		return nil, err
	}
	pwb, err := secmem.FromBytes([]byte(password))
	if err != nil {
		mb.Destroy()
		return nil, err
	}
	return &pgCred{role: role, password: pwb, master: mb, host: m.Host, port: m.Port, db: m.Database}, nil
}

// Revoke by handle is not possible: dropping the role needs the admin
// connection. Live grants revoke through the credential; after a crash the
// role's password expires at VALID UNTIL, but open sessions stay until an
// admin ends them.
func (Postgres) Revoke(context.Context, []byte) error { return nil }

func (Postgres) ProxyEnv(Request, string, string) []string { return nil }

type pgCred struct {
	role     string
	password *secmem.Buffer
	master   *secmem.Buffer
	host     string
	port     int
	db       string
}

func (c *pgCred) Inject(*http.Request, string) error {
	return errors.New("postgres grants are direct mode only")
}

func (c *pgCred) Env() []string {
	port := c.port
	if port == 0 {
		port = 5432
	}
	pw := string(c.password.Bytes())
	u := url.URL{Scheme: "postgres", User: url.UserPassword(c.role, pw), Host: c.host + ":" + strconv.Itoa(port), Path: "/" + c.db, RawQuery: "sslmode=verify-full"}
	return []string{
		"PGHOST=" + c.host, "PGPORT=" + strconv.Itoa(port), "PGDATABASE=" + c.db,
		"PGUSER=" + c.role, "PGPASSWORD=" + pw, "PGSSLMODE=verify-full",
		"DATABASE_URL=" + u.String(),
	}
}

func (c *pgCred) Handle() []byte     { return []byte(c.role) }
func (c *pgCred) Expires() time.Time { return time.Time{} }

// Revoke ends the role's sessions and drops it.
func (c *pgCred) Revoke(ctx context.Context) error {
	var m pgMaster
	if err := json.Unmarshal(c.master.Bytes(), &m); err != nil {
		return err
	}
	cfg, err := m.config()
	if err != nil {
		return err
	}
	conn, err := pgConnect(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	r := quoteIdent(c.role)
	for _, st := range []string{
		"ALTER ROLE " + r + " NOLOGIN",
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = " + quoteLit(c.role),
		"DROP OWNED BY " + r,
		"DROP ROLE " + r,
	} {
		if err := conn.Exec(st); err != nil {
			return err
		}
	}
	return nil
}

func (c *pgCred) Wipe() {
	c.password.Destroy()
	c.master.Destroy()
}
