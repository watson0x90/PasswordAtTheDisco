// Package httpapi wires the HTTP routes, middleware, and handlers for the API.
package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/secretsdump"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

const sessionCookie = "patd_session"

// Server holds the API's dependencies.
type Server struct {
	Store        *store.Store
	StaticFS     fs.FS  // embedded SPA; if nil, served from StaticDir on disk
	StaticDir    string // disk fallback for the SPA (e.g. web/dist)
	IngestToken  string // bearer token the analysis engine uses to push data
	Users        auth.Users
	Sessions     *auth.SessionStore
	Audit        *audit.Logger
	LoginLimiter *auth.Limiter  // per-IP failed-login throttle
	Engine       *engine.Engine // optional: enables lead web uploads (POST /api/audit)
	Policies     *policy.Set    // shared with Engine; exposed/edited via /api/policies
	PolicyPath   string         // where to persist policy edits (empty = in-memory only)
}

// staticFS resolves the SPA filesystem: the embedded FS if present, else the
// on-disk StaticDir, else nil.
func (s *Server) staticFS() fs.FS {
	if s.StaticFS != nil {
		return s.StaticFS
	}
	if s.StaticDir != "" {
		return os.DirFS(s.StaticDir)
	}
	return nil
}

type ctxKey int

const sessionKey ctxKey = 0

func sessionFrom(ctx context.Context) (auth.Session, bool) {
	s, ok := ctx.Value(sessionKey).(auth.Session)
	return s, ok
}

// Routes returns the fully-wrapped handler (routes + middleware).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	// Public
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/version", s.handleVersion)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	// Engine ingestion (separate token, not a user session) -- creates an audit
	mux.Handle("POST /api/ingest", s.requireIngestToken(s.requireUnlocked(http.HandlerFunc(s.handleIngest))))
	// Authenticated operators (any role) -- redacted data only
	mux.Handle("POST /api/logout", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogout))))
	mux.Handle("GET /api/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
	// Unlock / first-run passphrase for the encrypted store (lead)
	mux.Handle("POST /api/unlock", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleUnlock))))
	// Audit (engagement) management + selection -- needs an unlocked store
	mux.Handle("GET /api/audits", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleListAudits))))
	mux.Handle("POST /api/audits", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleCreateAudit)))))
	mux.Handle("DELETE /api/audits/{id}", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleDeleteAudit)))))
	mux.Handle("POST /api/audits/{id}/open", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleOpenAudit)))))
	// Views scoped to the session's active audit
	mux.Handle("GET /api/summary", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleSummary))))
	mux.Handle("GET /api/accounts", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAccounts))))
	// Cleartext reveal -- requires lead role, always audit-logged
	mux.Handle("GET /api/accounts/{username}/secret", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleReveal))))
	// Web upload of dump files into the active audit (lead)
	mux.Handle("POST /api/upload", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleAudit)))))
	// Per-domain password policies: any operator may read; lead may edit
	mux.Handle("GET /api/policies", s.requireAuth(http.HandlerFunc(s.handleGetPolicies)))
	mux.Handle("PUT /api/policies", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleSetPolicies))))
	// SPA
	mux.Handle("/", spaHandler(s.staticFS()))
	return securityHeaders(logRequests(mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"name": "passwordatthedisco-api", "version": "0.1.0-dev"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ip := clientIP(r)
	if ok, retry := s.LoginLimiter.Allowed(ip); !ok {
		s.Audit.Log(audit.Event{Action: "login", Source: r.RemoteAddr, Result: "rate_limited"})
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&creds); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	user, ok := s.Users.Authenticate(creds.Username, creds.Password)
	if !ok {
		s.LoginLimiter.RecordFailure(ip)
		s.Audit.Log(audit.Event{Actor: creds.Username, Action: "login", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	s.LoginLimiter.Reset(ip)
	id, csrf, err := s.Sessions.Create(user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	s.Audit.Log(audit.Event{Actor: user.Username, Role: string(user.Role), Action: "login", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"username": user.Username, "role": string(user.Role), "csrf_token": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	if sess, ok := sessionFrom(r.Context()); ok {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "logout", Source: r.RemoteAddr, Result: "ok"})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	active := sess.ActiveAudit
	if active != "" && (!s.Store.Unlocked() || !s.Store.Has(active)) {
		active = "" // store locked, or the selected audit was deleted
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":          sess.Username,
		"role":              string(sess.Role),
		"csrf_token":        sess.CSRF,
		"active_audit":      active,
		"store_initialized": s.Store.Initialized(),
		"store_unlocked":    s.Store.Unlocked(),
	})
}

// handleUnlock unlocks the encrypted store (or, on first run, sets the store
// passphrase). Lead only; audit-logged. The passphrase is never persisted.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_unlock", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	defer r.Body.Close()
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&body); err != nil || body.Passphrase == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passphrase required"})
		return
	}
	if s.Store.Unlocked() {
		writeJSON(w, http.StatusOK, map[string]bool{"unlocked": true, "initialized": true})
		return
	}
	first := !s.Store.Initialized()
	action := "store_unlock"
	var err error
	if first {
		if len(body.Passphrase) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "store passphrase must be at least 8 characters"})
			return
		}
		action = "store_initialize"
		err = s.Store.Initialize(body.Passphrase)
	} else {
		err = s.Store.Unlock(body.Passphrase)
	}
	if err != nil {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: action, Source: r.RemoteAddr, Result: "failed"})
		if errors.Is(err, vault.ErrBadPassphrase) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "incorrect passphrase"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: action, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]bool{"unlocked": true, "initialized": true})
}

// requireUnlocked rejects requests when the encrypted store is locked (423).
func (s *Server) requireUnlocked(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Store.Unlocked() {
			writeJSON(w, http.StatusLocked, map[string]string{"error": "data store is locked"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// activeAudit resolves the session's selected audit, writing a 409 if none is
// selected (or it has been deleted).
func (s *Server) activeAudit(w http.ResponseWriter, sess auth.Session) (string, bool) {
	if sess.ActiveAudit == "" || !s.Store.Has(sess.ActiveAudit) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return "", false
	}
	return sess.ActiveAudit, true
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<20)) // 256 MiB cap
	dec.DisallowUnknownFields()
	var ds model.Dataset
	if err := dec.Decode(&ds); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid dataset: " + err.Error()})
		return
	}
	if ds.GeneratedAt.IsZero() {
		ds.GeneratedAt = time.Now().UTC()
	}
	name := strings.TrimSpace(ds.Name)
	if name == "" {
		name = "CLI import"
	}
	meta, err := s.Store.CreateAudit(name, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create audit: " + err.Error()})
		return
	}
	if err := s.Store.Replace(meta.ID, ds); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store dataset: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_id": meta.ID, "ingested": len(ds.Accounts)})
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return
	}
	writeJSON(w, http.StatusOK, accts)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	sum, err := s.Store.Summary(id)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// handleReveal returns a single account's cleartext password. Requires the lead
// role; every attempt (allowed or denied) is audit-logged. The password is
// never written to the audit log.
func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	username := r.PathValue("username")
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: username, Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	acct, ok := s.Store.Find(id, username)
	if !ok {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: username, Source: r.RemoteAddr, Result: "not_found"})
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: username, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"username": acct.Username, "password": acct.Password})
}

// handleAudit accepts uploaded credential dumps (multipart: domain + a required
// "cracked" file and an optional "uncracked" file), runs the engine, and upserts
// the domain's results into the store. Lead role only; audit-logged. Cleartext
// is parsed and scored in memory and never written to disk.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_upload", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit engine not configured on this server"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 128<<20) // 128 MiB cap
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload: " + err.Error()})
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}

	cf, _, err := r.FormFile("cracked")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a cracked-passwords file is required"})
		return
	}
	defer cf.Close()
	cracked, err := secretsdump.ParseCracked(cf, domain)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parse cracked: " + err.Error()})
		return
	}
	uncracked, err := optionalUpload(r, "uncracked", domain, secretsdump.ParseUncracked)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	accts := s.Engine.ProcessDomain(domain, cracked, uncracked)
	if err := s.Store.ReplaceDomain(auditID, domain, accts); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_upload", Target: domain, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]int{"accounts": len(accts), "cracked": len(cracked), "uncracked": len(uncracked)})
}

// optionalUpload parses an optional multipart file part; returns nil if absent.
func optionalUpload(r *http.Request, field, domain string, fn func(io.Reader, string) ([]secretsdump.ParsedAccount, error)) ([]secretsdump.ParsedAccount, error) {
	f, _, err := r.FormFile(field)
	if err == http.ErrMissingFile {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s file: %v", field, err)
	}
	defer f.Close()
	return fn(f, domain)
}

// handleListAudits returns all audits' metadata + headline counts.
func (s *Server) handleListAudits(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.List())
}

// handleCreateAudit creates a new (empty) audit and opens it for the creator.
func (s *Server) handleCreateAudit(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	defer r.Body.Close()
	var body struct {
		Name  string `json:"name"`
		Notes string `json:"notes"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "audit name is required"})
		return
	}
	meta, err := s.Store.CreateAudit(name, strings.TrimSpace(body.Notes))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save audit: " + err.Error()})
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Sessions.SetActiveAudit(c.Value, meta.ID) // auto-open for the creator
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_create", Target: name, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, meta)
}

// handleDeleteAudit removes an audit (lead only).
func (s *Server) handleDeleteAudit(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	id := r.PathValue("id")
	if !s.Store.Delete(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "audit not found"})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_delete", Target: id, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleOpenAudit sets the session's active audit.
func (s *Server) handleOpenAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.Store.Has(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "audit not found"})
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || !s.Sessions.SetActiveAudit(c.Value, id) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"active_audit": id})
}

// policiesPayload is the wire shape for GET/PUT /api/policies.
type policiesPayload struct {
	Default policy.Policy            `json:"default"`
	Domains map[string]policy.Policy `json:"domains"`
}

// handleGetPolicies returns the current default + per-domain policies.
func (s *Server) handleGetPolicies(w http.ResponseWriter, _ *http.Request) {
	if s.Policies == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policies not configured"})
		return
	}
	def, domains := s.Policies.Snapshot()
	writeJSON(w, http.StatusOK, policiesPayload{Default: def, Domains: domains})
}

// handleSetPolicies replaces the policy set (lead only), persists it to disk if a
// path is configured, and -- because the Set is shared with the engine -- takes
// effect for the next upload immediately. Audit-logged.
func (s *Server) handleSetPolicies(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "policy_update", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Policies == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policies not configured"})
		return
	}
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	var p policiesPayload
	if err := dec.Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policies: " + err.Error()})
		return
	}
	if err := validatePolicy("default", p.Default); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for name, pol := range p.Domains {
		if strings.TrimSpace(name) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain name cannot be empty"})
			return
		}
		if err := validatePolicy(name, pol); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	s.Policies.Replace(p.Default, p.Domains)
	saved := "memory"
	if s.PolicyPath != "" {
		if err := s.Policies.Save(s.PolicyPath); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saved in memory but failed to persist: " + err.Error()})
			return
		}
		saved = s.PolicyPath
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "policy_update", Target: strconv.Itoa(len(p.Domains)) + " domain(s)", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"domains": len(p.Domains), "persisted": saved})
}

func validatePolicy(name string, p policy.Policy) error {
	if p.MinLength < 1 || p.MinLength > 256 {
		return fmt.Errorf("%s: min_length must be between 1 and 256", name)
	}
	if p.MaxPasswordAgeDays < 0 || p.MaxPasswordAgeDays > 100000 {
		return fmt.Errorf("%s: max_password_age_days out of range", name)
	}
	return nil
}

// requireAuth ensures a valid session and puts it in the request context.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		sess, ok := s.Sessions.Get(c.Value)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

// requireCSRF enforces the per-session CSRF token (synchronizer pattern) on
// state-changing requests. Defense-in-depth atop the SameSite=Strict cookie.
// Must be wrapped inside requireAuth (it reads the session from context).
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := sessionFrom(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		got := r.Header.Get("X-CSRF-Token")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the request's source IP (without port) for rate-limiting.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requireIngestToken enforces a bearer token on ingestion; fails closed.
func (s *Server) requireIngestToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.IngestToken == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ingestion disabled (no token configured)"})
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.IngestToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// securityHeaders applies a strict baseline for a self-hosted, same-origin SPA.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// script-src stays strict ('self'); style-src allows inline style
		// attributes (needed for data-driven widths in the SPA) but not remote
		// stylesheets. No script inlining is permitted.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self'; font-src 'self'; "+
				"object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

// spaHandler serves the single-page app from fsys (embedded or on-disk),
// falling back to index.html for client-side routes. fs.FS path semantics
// reject traversal by construction. A nil fsys yields 503 (frontend not built).
func spaHandler(fsys fs.FS) http.Handler {
	if fsys == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "frontend not built (run the web build)", http.StatusServiceUnavailable)
		})
	}
	fileServer := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		// Serve a real file when it exists; otherwise fall back to the SPA entry
		// point so client-side routes resolve.
		if fs.ValidPath(name) {
			if f, err := fsys.Open(name); err == nil {
				info, statErr := f.Stat()
				_ = f.Close()
				if statErr == nil && !info.IsDir() {
					fileServer.ServeHTTP(w, r)
					return
				}
			}
		}
		serveIndex(w, r, fsys)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	b, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		http.Error(w, "frontend not built (run the web build)", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(b))
}
