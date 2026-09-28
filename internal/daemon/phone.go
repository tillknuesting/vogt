package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"vogt/internal/helperlink"
	"vogt/internal/secmem"
	"vogt/internal/vault"
	"vogt/internal/webauthn"
	"vogt/internal/wire"
)

// Phone and security-key approvals over WebAuthn. The daemon serves a page
// on http://localhost:<port>. A passkey enrolled there can approve grants
// while the Touch ID helper is not connected, and its PRF output unwraps
// the secret the grant needs.

const (
	fileWebAuthn = "webauthn.json"
	rpID         = "localhost"
	enrollTTL    = 5 * time.Minute
)

var b64 = base64.RawURLEncoding

type phone struct {
	mu      sync.Mutex
	origin  string
	creds   []webauthn.Credential
	pending map[string]*phoneReq
	enrolls map[string]*enrollSession
}

type phoneReq struct {
	id, display string
	challenge   []byte
	secretID    string
	keyVersion  uint64
	expires     time.Time
	done        chan phoneResult
}

type phoneResult struct {
	approved bool
	dek      *secmem.Buffer
	evidence string
}

type enrollSession struct {
	challenge, userID, prfSalt []byte
	deks                       map[string]enrollDEK
	expires                    time.Time
}

type enrollDEK struct {
	version uint64
	dek     *secmem.Buffer
}

func (s *enrollSession) destroy() {
	for _, d := range s.deks {
		d.dek.Destroy()
	}
}

func (d *Daemon) loadPhone() error {
	d.ph = &phone{pending: map[string]*phoneReq{}, enrolls: map[string]*enrollSession{}}
	b, err := os.ReadFile(d.state(fileWebAuthn))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &d.ph.creds)
}

func (d *Daemon) savePhoneLocked() error {
	b, err := json.MarshalIndent(d.ph.creds, "", "  ")
	if err != nil {
		return err
	}
	return vault.WriteFileAtomic(d.state(fileWebAuthn), b, 0o600)
}

func prfWrapName(credID []byte) string { return "prf:" + b64.EncodeToString(credID) }

func prfAAD(id string, version uint64, credID []byte) []byte {
	return append(vault.WrapAAD(id, version), credID...)
}

// phoneReady reports whether a passkey can approve a grant for this secret.
func (d *Daemon) phoneReady(e *vault.Entry) bool {
	d.ph.mu.Lock()
	defer d.ph.mu.Unlock()
	if d.ph.origin == "" {
		return false
	}
	for _, c := range d.ph.creds {
		if _, ok := e.Wraps[prfWrapName(c.ID)]; ok {
			return true
		}
	}
	return false
}

// askPhone waits for a passkey approval on the localhost page.
func (d *Daemon) askPhone(ctx context.Context, id, display string, digest [32]byte, e *vault.Entry) (*secmem.Buffer, string, error) {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ch := sha256.Sum256(wire.NewEncoder("vogt/v1/phone-challenge").PutBytes(nonce).PutBytes(digest[:]).Finish())
	req := &phoneReq{id: id, display: display, challenge: ch[:], secretID: e.ID, keyVersion: e.KeyVersion,
		expires: time.Now().Add(d.approvalTimeout()), done: make(chan phoneResult, 1)}
	d.ph.mu.Lock()
	d.ph.pending[id] = req
	origin := d.ph.origin
	d.ph.mu.Unlock()
	defer func() {
		d.ph.mu.Lock()
		delete(d.ph.pending, id)
		d.ph.mu.Unlock()
	}()
	d.Audit("phone.waiting", map[string]string{"request": id, "page": origin})
	select {
	case r := <-req.done:
		if !r.approved {
			return nil, "", errors.New("the human denied the request")
		}
		master, err := vault.Decrypt(e, r.dek.Bytes())
		r.dek.Destroy()
		if err != nil {
			return nil, "", errors.New("secret did not decrypt")
		}
		return master, r.evidence, nil
	case <-time.After(time.Until(req.expires)):
		return nil, "", helperlink.ErrTimeout
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

// StartEnroll asks the human, through the helper, to let a new passkey
// approve grants. The tap unwraps every secret once so each can also be
// wrapped under the passkey's PRF key. It returns the page to open.
func (d *Daemon) StartEnroll(ctx context.Context) (string, error) {
	d.ph.mu.Lock()
	origin := d.ph.origin
	d.ph.mu.Unlock()
	if origin == "" {
		return "", errors.New("the approval page is off; start the daemon with --webauthn 127.0.0.1:7854")
	}
	list, err := d.vault.List()
	if err != nil {
		return "", err
	}
	var reqs []helperlink.DEKRequest
	var entries []*vault.Entry
	for _, m := range list {
		e, err := d.vault.Get(m.ID)
		if err != nil {
			return "", err
		}
		entries = append(entries, e)
		reqs = append(reqs, helperlink.DEKRequest{Tier: e.Tier, Wrapped: e.Wraps[vault.WrapSE], AAD: vault.WrapAAD(e.ID, e.KeyVersion)})
	}
	display := fmt.Sprintf("ADD A PASSKEY that can approve grants when this helper is away.\n  It will be able to unlock all %d secrets.\n  Only approve if you just ran `vogt webauthn enroll`.", len(entries))
	res, err := d.askAdmin(ctx, display, sha256.Sum256([]byte("vogt/v1/webauthn-enroll")), reqs...)
	if err != nil {
		return "", err
	}
	if !res.Approved {
		return "", errors.New("the human denied the enrollment")
	}
	s := &enrollSession{challenge: randBytes(32), userID: randBytes(16), prfSalt: randBytes(32), deks: map[string]enrollDEK{}, expires: time.Now().Add(enrollTTL)}
	for i, e := range entries {
		s.deks[e.ID] = enrollDEK{version: e.KeyVersion, dek: res.DEKs[i]}
	}
	token := b64.EncodeToString(randBytes(24))
	d.ph.mu.Lock()
	d.ph.enrolls[token] = s
	d.ph.mu.Unlock()
	d.Audit("webauthn.enroll_started", nil)
	return origin + "/#t=" + token, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// WebAuthnCredential is an enrolled passkey as listed to the human.
type WebAuthnCredential struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// WebAuthnCredentials lists enrolled passkeys.
func (d *Daemon) WebAuthnCredentials() []WebAuthnCredential {
	d.ph.mu.Lock()
	defer d.ph.mu.Unlock()
	out := []WebAuthnCredential{}
	for _, c := range d.ph.creds {
		out = append(out, WebAuthnCredential{ID: b64.EncodeToString(c.ID), Name: c.Name})
	}
	return out
}

// RemoveWebAuthn forgets a passkey and deletes its wraps.
func (d *Daemon) RemoveWebAuthn(id string) error {
	raw, err := b64.DecodeString(id)
	if err != nil {
		return err
	}
	d.ph.mu.Lock()
	i := slices.IndexFunc(d.ph.creds, func(c webauthn.Credential) bool { return string(c.ID) == string(raw) })
	if i < 0 {
		d.ph.mu.Unlock()
		return errors.New("no such passkey")
	}
	d.ph.creds = slices.Delete(d.ph.creds, i, i+1)
	err = d.savePhoneLocked()
	d.ph.mu.Unlock()
	if err != nil {
		return err
	}
	list, _ := d.vault.List()
	for _, m := range list {
		d.vault.DeleteWrap(m.ID, prfWrapName(raw))
	}
	d.Audit("webauthn.removed", map[string]string{"credential": id})
	return nil
}

func (d *Daemon) expireEnrollments() {
	d.ph.mu.Lock()
	defer d.ph.mu.Unlock()
	for t, s := range d.ph.enrolls {
		if time.Now().After(s.expires) {
			s.destroy()
			delete(d.ph.enrolls, t)
		}
	}
}

// startPhone listens for the approval page.
func (d *Daemon) startPhone(addr string) (net.Listener, *http.Server, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	d.ph.mu.Lock()
	d.ph.origin = "http://localhost:" + port
	d.ph.mu.Unlock()
	srv := &http.Server{Handler: d.phoneHandler(), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 32 << 10}
	return l, srv, nil
}

func (d *Daemon) phoneHandler() http.Handler {
	static, _ := fs.Sub(webauthn.Static, "static")
	files := http.FileServerFS(static)
	m := http.NewServeMux()
	m.Handle("GET /", files)
	m.HandleFunc("GET /api/pending", d.phonePending)
	m.HandleFunc("POST /api/decide", d.phoneDecide)
	m.HandleFunc("GET /api/enroll", d.phoneEnrollOptions)
	m.HandleFunc("POST /api/enroll", d.phoneEnroll)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.ph.mu.Lock()
		origin := d.ph.origin
		d.ph.mu.Unlock()
		// Only the exact localhost origin: this also defeats DNS rebinding.
		if "http://"+r.Host != origin {
			http.Error(w, "use "+origin, http.StatusMisdirectedRequest)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != origin {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		m.ServeHTTP(w, r)
	})
}

func phoneJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func phoneErr(w http.ResponseWriter, code int, err error) {
	phoneJSON(w, code, map[string]string{"error": err.Error()})
}

func (d *Daemon) phonePending(w http.ResponseWriter, r *http.Request) {
	type allow struct {
		ID   string `json:"id"`
		Salt string `json:"salt"`
	}
	type view struct {
		ID        string  `json:"id"`
		Display   string  `json:"display"`
		Challenge string  `json:"challenge"`
		Allow     []allow `json:"allow"`
	}
	d.ph.mu.Lock()
	defer d.ph.mu.Unlock()
	out := []view{}
	for _, p := range d.ph.pending {
		e, err := d.vault.Get(p.secretID)
		if err != nil {
			continue
		}
		v := view{ID: p.id, Display: p.display, Challenge: b64.EncodeToString(p.challenge)}
		for _, c := range d.ph.creds {
			if _, ok := e.Wraps[prfWrapName(c.ID)]; ok {
				v.Allow = append(v.Allow, allow{b64.EncodeToString(c.ID), b64.EncodeToString(c.PRFSalt)})
			}
		}
		out = append(out, v)
	}
	phoneJSON(w, http.StatusOK, out)
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (d *Daemon) phoneDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string `json:"id"`
		Approve           bool   `json:"approve"`
		CredentialID      string `json:"credential_id"`
		ClientData        string `json:"client_data"`
		AuthenticatorData string `json:"authenticator_data"`
		Signature         string `json:"signature"`
		PRF               string `json:"prf"`
	}
	if err := decodeBody(r, &req); err != nil {
		phoneErr(w, http.StatusBadRequest, err)
		return
	}
	d.ph.mu.Lock()
	p := d.ph.pending[req.ID]
	d.ph.mu.Unlock()
	if p == nil {
		phoneErr(w, http.StatusNotFound, errors.New("no such request"))
		return
	}
	if !req.Approve {
		select {
		case p.done <- phoneResult{}:
		default:
		}
		phoneJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	dec := func(s string) []byte { b, _ := b64.DecodeString(s); return b }
	credID := dec(req.CredentialID)
	d.ph.mu.Lock()
	i := slices.IndexFunc(d.ph.creds, func(c webauthn.Credential) bool { return string(c.ID) == string(credID) })
	if i < 0 {
		d.ph.mu.Unlock()
		phoneErr(w, http.StatusForbidden, errors.New("unknown passkey"))
		return
	}
	c := d.ph.creds[i]
	count, err := webauthn.VerifyAssertion(&c, dec(req.ClientData), dec(req.AuthenticatorData), dec(req.Signature), p.challenge, d.ph.origin, rpID)
	if err == nil {
		d.ph.creds[i].SignCount = count
		err = d.savePhoneLocked()
	}
	d.ph.mu.Unlock()
	if err != nil {
		d.Audit("phone.rejected", map[string]string{"request": p.id, "reason": err.Error()})
		phoneErr(w, http.StatusForbidden, err)
		return
	}
	var buf *secmem.Buffer
	secmem.Do(func() {
		var kek, dek []byte
		e, gerr := d.vault.Get(p.secretID)
		if gerr != nil || e.KeyVersion != p.keyVersion {
			err = errors.New("the secret changed; ask again")
			return
		}
		if kek, err = webauthn.KEK(dec(req.PRF)); err != nil {
			return
		}
		dek, err = webauthn.UnwrapDEK(kek, e.Wraps[prfWrapName(credID)], prfAAD(e.ID, e.KeyVersion, credID))
		clear(kek)
		if err != nil {
			err = errors.New("the passkey's PRF output does not unlock the secret")
			return
		}
		buf, err = secmem.FromBytes(dek)
	})
	if err != nil {
		phoneErr(w, http.StatusForbidden, err)
		return
	}
	h := sha256.Sum256(dec(req.Signature))
	select {
	case p.done <- phoneResult{approved: true, dek: buf, evidence: "passkey:" + hex.EncodeToString(h[:8])}:
		phoneJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		buf.Destroy()
		phoneErr(w, http.StatusConflict, errors.New("already decided"))
	}
}

func (d *Daemon) enrollSession(token string) *enrollSession {
	d.ph.mu.Lock()
	defer d.ph.mu.Unlock()
	s := d.ph.enrolls[token]
	if s == nil || time.Now().After(s.expires) {
		return nil
	}
	return s
}

func (d *Daemon) phoneEnrollOptions(w http.ResponseWriter, r *http.Request) {
	s := d.enrollSession(r.URL.Query().Get("t"))
	if s == nil {
		phoneErr(w, http.StatusNotFound, errors.New("enrollment link expired; run `vogt webauthn enroll` again"))
		return
	}
	phoneJSON(w, http.StatusOK, map[string]string{
		"challenge": b64.EncodeToString(s.challenge), "user_id": b64.EncodeToString(s.userID), "prf_salt": b64.EncodeToString(s.prfSalt),
	})
}

func (d *Daemon) phoneEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		T                 string `json:"t"`
		Name              string `json:"name"`
		ClientData        string `json:"client_data"`
		AuthenticatorData string `json:"authenticator_data"`
		PublicKey         string `json:"public_key"`
		Alg               int    `json:"alg"`
		PRF               string `json:"prf"`
	}
	if err := decodeBody(r, &req); err != nil {
		phoneErr(w, http.StatusBadRequest, err)
		return
	}
	d.ph.mu.Lock()
	s := d.ph.enrolls[req.T]
	delete(d.ph.enrolls, req.T) // one attempt per link
	origin := d.ph.origin
	d.ph.mu.Unlock()
	if s == nil || time.Now().After(s.expires) {
		phoneErr(w, http.StatusNotFound, errors.New("enrollment link expired"))
		return
	}
	defer s.destroy()
	dec := func(v string) []byte { b, _ := b64.DecodeString(v); return b }
	c, err := webauthn.VerifyRegistration(dec(req.ClientData), dec(req.AuthenticatorData), dec(req.PublicKey), req.Alg, s.challenge, origin, rpID)
	if err != nil {
		phoneErr(w, http.StatusBadRequest, err)
		return
	}
	c.PRFSalt, c.Name = s.prfSalt, sanitize(req.Name, 40)
	kek, err := webauthn.KEK(dec(req.PRF))
	if err != nil {
		phoneErr(w, http.StatusBadRequest, err)
		return
	}
	defer clear(kek)
	for id, ed := range s.deks {
		wrapped, err := webauthn.WrapDEK(kek, ed.dek.Bytes(), prfAAD(id, ed.version, c.ID))
		if err == nil {
			err = d.vault.SetWrap(id, prfWrapName(c.ID), wrapped)
		}
		if err != nil {
			phoneErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	d.ph.mu.Lock()
	d.ph.creds = append(d.ph.creds, *c)
	err = d.savePhoneLocked()
	d.ph.mu.Unlock()
	if err != nil {
		phoneErr(w, http.StatusInternalServerError, err)
		return
	}
	d.Audit("webauthn.enrolled", map[string]string{"credential": b64.EncodeToString(c.ID), "name": c.Name, "secrets": fmt.Sprint(len(s.deks))})
	phoneJSON(w, http.StatusOK, map[string]string{"id": b64.EncodeToString(c.ID)})
}
