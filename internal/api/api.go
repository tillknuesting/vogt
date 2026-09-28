// Package api serves Vogt's JSON API on the daemon's Unix socket.
//
// Agent endpoints need the session secret as a bearer token. Admin
// endpoints that grant or change anything ask the human through the helper;
// the rest only read state or remove access.
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"vogt/internal/daemon"
	"vogt/internal/peercred"
	"vogt/internal/session"
)

const maxBody = 1 << 20

// Handler returns the API handler for d.
func Handler(d *daemon.Daemon) http.Handler {
	h := &handler{d: d}
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/sessions", h.createSession)
	m.HandleFunc("DELETE /v1/sessions/self", h.withSession(h.endSession))
	m.HandleFunc("GET /v1/capabilities", h.capabilities)
	m.HandleFunc("POST /v1/grants", h.withSession(h.requestGrant))
	m.HandleFunc("GET /v1/grants", h.withSession(h.listGrants))
	m.HandleFunc("GET /v1/grants/{id}", h.withSession(h.getGrant))
	m.HandleFunc("DELETE /v1/grants/{id}", h.withSession(h.surrender))

	m.HandleFunc("GET /v1/admin/status", h.status)
	m.HandleFunc("GET /v1/admin/identity", h.identity)
	m.HandleFunc("POST /v1/admin/revoke-all", h.revokeAll)
	m.HandleFunc("GET /v1/admin/grants", h.allGrants)
	m.HandleFunc("POST /v1/admin/grants/{id}/revoke", h.revokeGrant)
	m.HandleFunc("GET /v1/admin/sessions", h.sessions)
	m.HandleFunc("POST /v1/admin/sessions/{id}/unlock", h.unlock)
	m.HandleFunc("GET /v1/admin/secrets", h.secrets)
	m.HandleFunc("POST /v1/admin/secrets", h.addSecret)
	m.HandleFunc("DELETE /v1/admin/secrets/{id}", h.deleteSecret)
	m.HandleFunc("POST /v1/admin/secrets/{id}/rotate", h.rotateSecret)
	m.HandleFunc("GET /v1/admin/policy", h.getPolicy)
	m.HandleFunc("POST /v1/admin/policy", h.loadPolicy)
	m.HandleFunc("POST /v1/admin/reload", h.reload)
	m.HandleFunc("GET /v1/admin/audit/verify", h.verifyAudit)
	m.HandleFunc("GET /v1/admin/ca", h.caCert)
	m.HandleFunc("POST /v1/admin/webauthn/enroll", h.webauthnEnroll)
	m.HandleFunc("GET /v1/admin/webauthn", h.webauthnList)
	m.HandleFunc("DELETE /v1/admin/webauthn/{id}", h.webauthnRemove)
	return m
}

type handler struct{ d *daemon.Daemon }

type sessionHandler func(w http.ResponseWriter, r *http.Request, s *session.Session)

func (h *handler) withSession(next sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeErr(w, http.StatusUnauthorized, errors.New("missing session secret; run the agent under `vogt run`"))
			return
		}
		s, err := h.d.LookupSession(secret)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err)
			return
		}
		next(w, r, s)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (h *handler) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	secret, s := h.d.CreateSessionFor(req.Name, peercred.FromContext(r.Context()))
	writeJSON(w, http.StatusCreated, map[string]string{"id": s.ID, "secret": secret})
}

func (h *handler) endSession(w http.ResponseWriter, r *http.Request, s *session.Session) {
	h.d.EndSession(s.ID)
	w.WriteHeader(http.StatusNoContent)
}

// Capability is a catalogue entry as agents see it.
type Capability struct {
	Name     string   `json:"name"`
	Display  string   `json:"display"`
	Provider string   `json:"provider"`
	Target   string   `json:"target,omitempty"`
	Modes    []string `json:"modes"`
}

func (h *handler) capabilities(w http.ResponseWriter, r *http.Request) {
	p := h.d.Policy()
	if p == nil {
		writeErr(w, http.StatusServiceUnavailable, daemon.ErrNoPolicy)
		return
	}
	out := []Capability{}
	for name, c := range p.Capabilities {
		modes := []string{"proxy"}
		if len(c.Modes) > 0 {
			modes = modes[:0]
			for _, m := range c.Modes {
				modes = append(modes, string(m))
			}
		}
		out = append(out, Capability{Name: name, Display: c.Display, Provider: c.Provider, Target: c.Target, Modes: modes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) requestGrant(w http.ResponseWriter, r *http.Request, s *session.Session) {
	var req daemon.GrantRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	g, err := h.d.RequestGrant(s, req)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, daemon.ErrDenied) {
			code = http.StatusForbidden
		}
		writeErr(w, code, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": g.ID, "state": string(g.State), "display": g.Display})
}

func (h *handler) getGrant(w http.ResponseWriter, r *http.Request, s *session.Session) {
	wait := time.Duration(0)
	if v := r.URL.Query().Get("wait"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			writeErr(w, http.StatusBadRequest, errors.New("bad wait"))
			return
		}
		wait = min(d, 2*time.Minute)
	}
	v, err := h.d.WaitGrant(r.Context(), s, r.PathValue("id"), wait)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *handler) listGrants(w http.ResponseWriter, r *http.Request, s *session.Session) {
	writeJSON(w, http.StatusOK, h.d.Grants(s.ID))
}

func (h *handler) surrender(w http.ResponseWriter, r *http.Request, s *session.Session) {
	if err := h.d.SurrenderGrant(s, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.d.Status())
}

func (h *handler) identity(w http.ResponseWriter, r *http.Request) {
	pub := h.d.IdentityPublic().Bytes()
	fp := h.d.IdentityPublic().Fingerprint()
	writeJSON(w, http.StatusOK, map[string]string{
		"public_key":  base64.StdEncoding.EncodeToString(pub),
		"fingerprint": base64.RawURLEncoding.EncodeToString(fp[:]),
	})
}

func (h *handler) revokeAll(w http.ResponseWriter, r *http.Request) {
	n := h.d.RevokeAll("vogt revoke --all")
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (h *handler) allGrants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.d.Grants(""))
}

func (h *handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := h.d.RevokeGrant(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) sessions(w http.ResponseWriter, r *http.Request) {
	type view struct {
		ID      string    `json:"id"`
		Name    string    `json:"name"`
		Created time.Time `json:"created"`
	}
	out := []view{}
	for _, s := range h.d.Sessions() {
		out = append(out, view{s.ID, s.Name, s.Created})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) unlock(w http.ResponseWriter, r *http.Request) {
	if err := h.d.UnlockSession(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) secrets(w http.ResponseWriter, r *http.Request) {
	l, err := h.d.Secrets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (h *handler) addSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		Tier     string `json:"tier"`
		Secret   []byte `json:"secret"` // base64 in JSON
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	defer clear(req.Secret)
	tier := map[string]uint8{"high": 1, "low": 2}[req.Tier]
	m, err := h.d.AddSecret(r.Context(), req.ID, req.Provider, tier, req.Secret)
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (h *handler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if err := h.d.DeleteSecret(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	raw, err := h.d.PolicyRaw()
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func (h *handler) loadPolicy(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := h.d.LoadPolicy(r.Context(), raw); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]uint64{"version": h.d.Policy().Version})
}

func (h *handler) reload(w http.ResponseWriter, r *http.Request) {
	if err := h.d.Reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, h.d.Status())
}

func (h *handler) verifyAudit(w http.ResponseWriter, r *http.Request) {
	res, err := h.d.VerifyAudit()
	out := map[string]any{"entries": res.Entries, "checkpoints": res.Checkpoints, "unsigned_tail": res.Unsigned, "ok": err == nil}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) caCert(w http.ResponseWriter, r *http.Request) {
	c, err := h.d.CACertPEM()
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(c)
}

func (h *handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	m, err := h.d.RotateSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (h *handler) webauthnEnroll(w http.ResponseWriter, r *http.Request) {
	u, err := h.d.StartEnroll(r.Context())
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": u})
}

func (h *handler) webauthnList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.d.WebAuthnCredentials())
}

func (h *handler) webauthnRemove(w http.ResponseWriter, r *http.Request) {
	if err := h.d.RemoveWebAuthn(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
