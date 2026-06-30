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
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/enrich"
	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwned"
	"github.com/watson0x90/PasswordAtTheDisco/internal/report"
	"github.com/watson0x90/PasswordAtTheDisco/internal/rescore"
	"github.com/watson0x90/PasswordAtTheDisco/internal/secretsdump"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

const sessionCookie = "patd_session"

// Server holds the API's dependencies.
type Server struct {
	Store              *store.Store
	StaticFS           fs.FS              // embedded SPA; if nil, served from StaticDir on disk
	StaticDir          string             // disk fallback for the SPA (e.g. web/dist)
	IngestToken        string             // bearer token the analysis engine uses to push data
	MCPTokens          *auth.TokenStore   // role-scoped API tokens for MCP/programmatic access (may be nil)
	MCPLimiter         *auth.Limiter      // per-IP failed-MCP-auth throttle (may be nil)
	Users              *auth.UserStore    // live operator store (add/disable/remove without restart)
	Logins             *auth.LoginTracker // per-account lockout + login history (may be nil)
	Sessions           *auth.SessionStore
	Audit              *audit.Logger
	AuditPath          string           // on-disk audit log path, for the lead Activity view (empty = none)
	LoginLimiter       *auth.Limiter    // per-IP failed-login throttle
	UnlockLimiter      *auth.Limiter    // per-IP failed-unlock throttle (brute-force guard)
	RekeyLimiter       *auth.Limiter    // per-IP failed-rekey throttle (separate so it can't lock out unlock)
	Engine             *engine.Engine   // optional: enables lead web uploads (POST /api/upload)
	Policies           *policy.Set      // shared with Engine; exposed/edited via /api/policies
	PolicyPath         string           // where to persist policy edits (empty = in-memory only)
	ForbiddenWordsPath string           // where to persist forbidden-words edits (empty = in-memory only)
	PwnedDir           string           // PwnedPasswordsDownloader source dir (HIBP NTLM tool)
	HIBPPath           string           // configured HIBP NTLM index path (for the Pwned page status)
	BHEPath            string           // BloodHound config path (config/bloodhound.json) for the BHE settings page
	Downloads          *pwned.Manager   // background HIBP download/index job runner (may be nil)
	Enrich             *enrich.Manager  // background BloodHound enrichment job (may be nil)
	Rescore            *rescore.Manager // background re-scoring job (may be nil)
	Build              BuildInfo        // compile-time build identity, surfaced at GET /api/version

	lastActivity atomic.Int64 // unix-nano of the last unlocked data access (auto-lock)
	inFlight     atomic.Int64 // in-flight data requests; auto-lock waits for zero
}

// minStorePassphrase is the floor for a new/changed store passphrase. The keyfile
// is offline-attackable, so this is higher than a typical login minimum.
const minStorePassphrase = 12

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
const mcpTokenKey ctxKey = 1

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
	// MCP / programmatic API: bearer token, role-scoped, no session required
	mux.Handle("POST /api/mcp", s.requireMCPToken(http.HandlerFunc(s.handleMCP)))
	mux.Handle("GET /api/mcp/whoami", s.requireMCPToken(http.HandlerFunc(s.handleMCPWhoami)))
	mux.Handle("GET /api/mcp/tokens", s.requireAuth(http.HandlerFunc(s.handleListMCPTokens)))
	mux.Handle("POST /api/mcp/tokens", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleCreateMCPToken))))
	mux.Handle("DELETE /api/mcp/tokens/{id}", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleRevokeMCPToken))))
	// Authenticated operators (any role) -- redacted data only
	mux.Handle("POST /api/logout", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogout))))
	mux.Handle("GET /api/me", http.HandlerFunc(s.handleMe))
	// Unlock / first-run passphrase / change-passphrase / re-lock (lead)
	mux.Handle("POST /api/unlock", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleUnlock))))
	mux.Handle("POST /api/lock", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLock))))
	mux.Handle("POST /api/passphrase", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleChangePassphrase))))
	mux.Handle("POST /api/rekey", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleRekey))))
	// HIBP / Pwned Passwords downloader (lead): build the .NET tool + probe the source
	mux.Handle("GET /api/pwned/status", s.requireAuth(http.HandlerFunc(s.handlePwnedStatus)))
	mux.Handle("POST /api/pwned/build", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handlePwnedBuild))))
	mux.Handle("POST /api/pwned/probe", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handlePwnedProbe))))
	mux.Handle("POST /api/pwned/download", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handlePwnedDownload))))
	mux.Handle("POST /api/pwned/index", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handlePwnedIndex))))
	mux.Handle("GET /api/pwned/job", s.pollSoftAuth(http.HandlerFunc(s.handlePwnedJob)))
	mux.Handle("POST /api/pwned/cancel", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handlePwnedCancel))))
	// BloodHound enrichment job (lead): start / poll / cancel
	mux.Handle("POST /api/enrich", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleEnrichStart)))))
	mux.Handle("GET /api/enrich/job", s.pollSoftAuth(http.HandlerFunc(s.handleEnrichJob)))
	mux.Handle("POST /api/enrich/cancel", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleEnrichCancel))))
	// Re-scoring job (lead): start / poll / cancel
	mux.Handle("POST /api/rescore", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleRescoreStart)))))
	mux.Handle("GET /api/rescore/job", s.pollSoftAuth(http.HandlerFunc(s.handleRescoreJob)))
	mux.Handle("POST /api/rescore/cancel", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleRescoreCancel))))
	// Operator management (lead): live add/update/remove, no restart
	mux.Handle("GET /api/users", s.requireAuth(http.HandlerFunc(s.handleListUsers)))
	mux.Handle("POST /api/users", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleCreateUser))))
	mux.Handle("PATCH /api/users/{username}", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleUpdateUser))))
	mux.Handle("DELETE /api/users/{username}", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleDeleteUser))))
	mux.Handle("POST /api/users/{username}/unlock", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleUnlockUser))))
	mux.Handle("GET /api/login-activity", s.requireAuth(http.HandlerFunc(s.handleLoginActivity)))
	mux.Handle("GET /api/audit-log", s.requireAuth(http.HandlerFunc(s.handleAuditLog)))
	mux.Handle("GET /api/audit-log.csv", s.requireAuth(http.HandlerFunc(s.handleAuditLogCSV)))
	// BloodHound enrichment config (lead): view (redacted) / test / save + hot-swap
	mux.Handle("GET /api/bhe/status", s.requireAuth(http.HandlerFunc(s.handleBHEStatus)))
	mux.Handle("POST /api/bhe/test", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleBHETest))))
	mux.Handle("PUT /api/bhe/config", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleBHEConfig))))
	// Audit (engagement) management + selection -- needs an unlocked store
	mux.Handle("GET /api/audits", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleListAudits))))
	mux.Handle("POST /api/audits", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleCreateAudit)))))
	mux.Handle("DELETE /api/audits/{id}", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleDeleteAudit)))))
	mux.Handle("POST /api/audits/{id}/open", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleOpenAudit)))))
	mux.Handle("GET /api/audits/{a}/diff/{b}", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleDiff))))
	// Views scoped to the session's active audit
	mux.Handle("GET /api/summary", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleSummary))))
	mux.Handle("GET /api/metrics", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleMetrics))))
	mux.Handle("GET /api/accounts", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAccounts))))
	mux.Handle("GET /api/audits/{id}/accounts", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAuditAccounts))))
	mux.Handle("POST /api/probe", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleProbe)))))
	mux.Handle("GET /api/report", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleReport))))
	mux.Handle("GET /api/report/terms", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleReportTerms))))
	mux.Handle("GET /api/ingests", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleIngests))))
	// Cleartext reveal -- requires lead role, always audit-logged
	mux.Handle("GET /api/accounts/{username}/secret", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleReveal))))
	// Identity-only reuse-group relationships -- available to any authenticated operator
	mux.Handle("GET /api/accounts/{username}/relationships", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAccountRelationships))))
	// Web upload of dump files into the active audit (lead)
	mux.Handle("POST /api/upload", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleAudit)))))
	mux.Handle("POST /api/upload/cracks", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleApplyCracks)))))
	mux.Handle("POST /api/upload/bheusers", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleUploadBHEUsers)))))
	mux.Handle("DELETE /api/domains/{domain}", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleDeleteDomain)))))
	// Redacted exports of the active audit (any operator)
	mux.Handle("GET /api/export/csv", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportCSV))))
	mux.Handle("GET /api/export/cracked.csv", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportCracked))))
	mux.Handle("GET /api/export/hibp.csv", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportHIBP))))
	mux.Handle("GET /api/export/reuse.csv", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportReuse))))
	mux.Handle("GET /api/export/weak.csv", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportWeak))))
	mux.Handle("GET /api/export/html", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportHTML))))
	mux.Handle("GET /api/export/cracked.html", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportCrackedHTML))))
	mux.Handle("GET /api/export/hibp.html", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportHIBPHTML))))
	mux.Handle("GET /api/export/reuse.html", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportReuseHTML))))
	mux.Handle("GET /api/export/weak.html", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportWeakHTML))))
	mux.Handle("GET /api/export/sanitized.json", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportSanitized))))
	// Per-domain password policies: any operator may read; lead may edit
	mux.Handle("GET /api/policies", s.requireAuth(http.HandlerFunc(s.handleGetPolicies)))
	mux.Handle("PUT /api/policies", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleSetPolicies))))
	// Password-analysis forbidden words: lead-only (cleartext fragments)
	mux.Handle("GET /api/forbidden-words", s.requireAuth(http.HandlerFunc(s.handleGetForbiddenWords)))
	mux.Handle("PUT /api/forbidden-words", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleSetForbiddenWords))))
	// SPA
	mux.Handle("/", spaHandler(s.staticFS()))
	return securityHeaders(logRequests(recoverPanic(mux)))
}

// recoverPanic turns a handler panic into a 500 + log instead of letting it abort
// the request mid-flight. Inner deferred cleanups (e.g. inFlight) still run as the
// stack unwinds; this just prevents a panic from poisoning shared server state or
// leaking a stack trace to the client. The route template is logged (not the path,
// which could carry a username).
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recordingWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				route := r.Pattern
				if route == "" {
					route = r.Method
				}
				log.Printf("PANIC recovered in handler %s: %v", route, rec)
				// Only synthesize a 500 if nothing was written yet -- otherwise a
				// panic mid-response (e.g. a streaming export) would append a second
				// JSON body / superfluous header onto the partial response.
				if !rw.wrote {
					writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				}
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

// recordingWriter tracks whether a response has begun, so recoverPanic doesn't
// double-write. Unwrap exposes the underlying writer so http.ResponseController
// (deadline extension on upload/rekey) and flushing still work through it.
type recordingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *recordingWriter) WriteHeader(code int) { w.wrote = true; w.ResponseWriter.WriteHeader(code) }
func (w *recordingWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// handleHealthz is a readiness probe: 200 when the store is usable, 503 while the
// encrypted store is locked (the server is up but can't serve data yet).
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	if s.Store.Rekeying() { // lock-free: stays live while a rekey holds the vault lock
		// 200 keeps the process alive (a kill mid-rekey is safe but wasteful); the
		// elapsed time lets a monitor alert on a wedged rotation.
		writeJSON(w, http.StatusOK, map[string]any{"status": "rekeying", "elapsed_seconds": int(s.Store.RekeyElapsed().Seconds())})
		return
	}
	if !s.Store.Unlocked() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "locked"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// BuildInfo is the compile-time build identity (injected via -ldflags -X in the
// build command); zero values fall back to "dev" so an un-stamped local build is
// still legible.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	b := s.Build
	if b.Version == "" {
		b.Version = "dev"
	}
	if b.Commit == "" {
		b.Commit = "none"
	}
	if b.BuildDate == "" {
		b.BuildDate = "unknown"
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"name": "passwordatthedisco-api", "version": b.Version, "commit": b.Commit, "build_date": b.BuildDate,
	})
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
	// Per-account lockout (complements the per-IP throttle above): blocks targeting
	// one account from many IPs.
	if s.Logins != nil {
		if locked, until := s.Logins.Locked(creds.Username); locked {
			s.Logins.RecordBlocked(creds.Username, r.RemoteAddr)
			s.Audit.Log(audit.Event{Actor: creds.Username, Action: "login", Source: r.RemoteAddr, Result: "locked"})
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "account temporarily locked after repeated failed logins"})
			return
		}
	}
	user, ok := s.Users.Authenticate(creds.Username, creds.Password)
	if !ok {
		s.LoginLimiter.RecordFailure(ip)
		if s.Logins != nil {
			s.Logins.RecordFailure(creds.Username, r.RemoteAddr)
		}
		s.Audit.Log(audit.Event{Actor: creds.Username, Action: "login", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	s.LoginLimiter.Reset(ip)
	if s.Logins != nil {
		s.Logins.RecordSuccess(user.Username, r.RemoteAddr)
	}
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
	writeJSON(w, http.StatusOK, map[string]any{
		"username":          user.Username,
		"role":              string(user.Role),
		"csrf_token":        csrf,
		"active_audit":      "", // fresh session
		"store_initialized": s.Store.Initialized(),
		"store_unlocked":    s.Store.Unlocked(),
	})
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

// handleMe reports the caller's session state. It is reachable anonymously and
// always returns 200 with an "authenticated" flag (the SPA probes it on every
// fresh load; a 401 here would log a red console error each visit). Authenticated
// callers get their full payload; protected routes still gate on requireAuth.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	sess, ok := s.Sessions.Get(c.Value)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	active := sess.ActiveAudit
	if active != "" && (!s.Store.Unlocked() || !s.Store.Has(active)) {
		active = "" // store locked, or the selected audit was deleted
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":     true,
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
	ip := clientIP(r)
	if s.UnlockLimiter != nil {
		if ok, retry := s.UnlockLimiter.Allowed(ip); !ok {
			s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_unlock", Source: r.RemoteAddr, Result: "rate_limited"})
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many unlock attempts, try again later"})
			return
		}
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
		if len(body.Passphrase) < minStorePassphrase {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("store passphrase must be at least %d characters", minStorePassphrase)})
			return
		}
		action = "store_initialize"
		err = s.Store.Initialize(body.Passphrase)
	} else {
		err = s.Store.Unlock(body.Passphrase)
	}
	if err != nil {
		if s.UnlockLimiter != nil {
			s.UnlockLimiter.RecordFailure(ip)
		}
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: action, Source: r.RemoteAddr, Result: "failed"})
		if errors.Is(err, vault.ErrBadPassphrase) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "incorrect passphrase"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if s.UnlockLimiter != nil {
		s.UnlockLimiter.Reset(ip)
	}
	s.touch()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: action, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]bool{"unlocked": true, "initialized": true})
}

// handleLock re-locks the store: drops the key and clears decrypted data (lead).
func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	s.Store.Lock()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_lock", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]bool{"unlocked": false})
}

// handleChangePassphrase re-wraps the data key under a new passphrase (lead).
func (s *Server) handleChangePassphrase(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if !s.Store.Unlocked() {
		writeJSON(w, http.StatusLocked, map[string]string{"error": "unlock the store before changing its passphrase"})
		return
	}
	defer r.Body.Close()
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if len(body.New) < minStorePassphrase {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("new passphrase must be at least %d characters", minStorePassphrase)})
		return
	}
	if err := s.Store.ChangePassphrase(body.Old, body.New); err != nil {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_passphrase_change", Source: r.RemoteAddr, Result: "failed"})
		if errors.Is(err, vault.ErrBadPassphrase) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current passphrase is incorrect"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_passphrase_change", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
}

// handleRekey rotates the data-encryption key (re-encrypts every audit under a
// fresh DEK). Lead-only; requires the current passphrase to re-wrap the new key.
func (s *Server) handleRekey(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if !s.Store.Unlocked() {
		writeJSON(w, http.StatusLocked, map[string]string{"error": "unlock the store before rotating its data key"})
		return
	}
	if s.Store.Rekeying() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a data-key rotation is already in progress"})
		return
	}
	// The passphrase is verified here (argon2id), so rate-limit like unlock to blunt
	// guessing + the DoS amplification (each correct guess re-encrypts the store).
	ip := clientIP(r)
	if s.RekeyLimiter != nil {
		if ok, retry := s.RekeyLimiter.Allowed(ip); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
			return
		}
	}
	defer r.Body.Close()
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	// Re-encrypting a large store can exceed the default write timeout; extend it,
	// and keep the idle auto-lock from firing mid-rotation.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetReadDeadline(time.Now().Add(30 * time.Minute))
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Minute))
	}
	s.touch()
	s.inFlight.Add(1)
	defer func() { s.inFlight.Add(-1); s.touch() }() // survives a panic, so auto-lock can't get wedged off
	err := s.Store.Rekey(body.Passphrase)
	if err != nil {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_rekey", Source: r.RemoteAddr, Result: "failed"})
		switch {
		case errors.Is(err, vault.ErrBadPassphrase):
			if s.RekeyLimiter != nil {
				s.RekeyLimiter.RecordFailure(ip)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current passphrase is incorrect"})
		case errors.Is(err, vault.ErrRekeyInProgress):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a data-key rotation is already in progress"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	if s.RekeyLimiter != nil {
		s.RekeyLimiter.Reset(ip)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "store_rekey", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]bool{"rekeyed": true})
}

// handlePwnedStatus reports the local downloader/data state (lead).
func (s *Server) handlePwnedStatus(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	writeJSON(w, http.StatusOK, pwned.Stat(s.PwnedDir, s.HIBPPath))
}

// handlePwnedBuild compiles the bundled PwnedPasswordsDownloader via `dotnet build`
// (lead). Fixed args, no user input -> no command injection.
func (s *Server) handlePwnedBuild(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if rc := http.NewResponseController(w); rc != nil { // a build can exceed the default write timeout
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	res, err := pwned.Build(ctx, s.PwnedDir)
	logResult := "ok"
	if err != nil {
		logResult = "failed"
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "pwned_build", Source: r.RemoteAddr, Result: logResult})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "output": res.Output})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handlePwnedProbe makes a single HIBP NTLM range request to confirm the download
// source is reachable (lead). Does NOT start the full download.
func (s *Server) handlePwnedProbe(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := pwned.Probe(ctx)
	logResult := "ok"
	if err != nil {
		logResult = "failed"
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "pwned_probe", Source: r.RemoteAddr, Result: logResult})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "url": res.URL})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handlePwnedDownload starts the background NTLM download (then index build) (lead).
func (s *Server) handlePwnedDownload(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Downloads == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "downloader not configured"})
		return
	}
	var body struct {
		Resume bool `json:"resume"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	err := s.Downloads.Start(body.Resume)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "pwned_download", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, s.Downloads.Status())
}

// handlePwnedIndex (re)builds the index for the existing data file, no download (lead).
func (s *Server) handlePwnedIndex(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Downloads == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "downloader not configured"})
		return
	}
	err := s.Downloads.StartIndexOnly()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "pwned_index", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, s.Downloads.Status())
}

// handlePwnedJob reports the current download/index job (lead); polled by the UI.
func (s *Server) handlePwnedJob(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Downloads == nil {
		writeJSON(w, http.StatusOK, pwned.JobStatus{Phase: pwned.PhaseIdle})
		return
	}
	writeJSON(w, http.StatusOK, s.Downloads.Status())
}

// handlePwnedCancel stops an in-progress download (lead).
func (s *Server) handlePwnedCancel(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Downloads == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "downloader not configured"})
		return
	}
	err := s.Downloads.Cancel()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "pwned_cancel", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.Downloads.Status())
}

// kickEnrich auto-starts BloodHound enrichment for an audit if BHE is configured.
// Best-effort and non-blocking: an already-running job just returns an error we
// ignore (manual re-run covers it).
func (s *Server) kickEnrich(auditID string) {
	if s.Enrich == nil || s.Engine == nil || !s.Engine.HasEnricher() {
		return
	}
	_ = s.Enrich.Start(auditID)
}

// handleEnrichStart kicks off a background BloodHound enrichment job (lead).
func (s *Server) handleEnrichStart(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Enrich == nil || s.Engine == nil || !s.Engine.HasEnricher() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "BloodHound enrichment is not configured"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	// Coordination: a Rescore job rewrites the same audit -- refuse to run both.
	if s.Rescore != nil && s.Rescore.Running() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "re-scoring in progress; run enrichment after it finishes"})
		return
	}
	if err := s.Enrich.Start(auditID); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "enrich_start", Target: auditID, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, s.Enrich.Status())
}

// handleEnrichJob reports the current enrichment job status (lead); polled by the UI.
func (s *Server) handleEnrichJob(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Enrich == nil {
		writeJSON(w, http.StatusOK, enrich.JobStatus{Phase: enrich.PhaseIdle})
		return
	}
	writeJSON(w, http.StatusOK, s.Enrich.Status())
}

// handleEnrichCancel stops an in-progress enrichment job (lead).
func (s *Server) handleEnrichCancel(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Enrich == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "enrichment not configured"})
		return
	}
	err := s.Enrich.Cancel()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "enrich_cancel", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.Enrich.Status())
}

// handleRescoreStart kicks off a background re-scoring job over the active audit
// using current policy/wordlists/HIBP, preserving BloodHound Impact (lead).
func (s *Server) handleRescoreStart(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Rescore == nil || s.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "re-scoring is not available"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	// Coordination: an Enrich job rewrites the same audit -- refuse to run both.
	if s.Enrich != nil && s.Enrich.Running() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "enrichment in progress; recalculate after it finishes"})
		return
	}
	if err := s.Rescore.Start(auditID); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "rescore_start", Target: auditID, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, s.Rescore.Status())
}

// handleRescoreJob reports the current re-scoring job status (lead); polled by the UI.
func (s *Server) handleRescoreJob(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Rescore == nil {
		writeJSON(w, http.StatusOK, rescore.JobStatus{Phase: rescore.PhaseIdle})
		return
	}
	writeJSON(w, http.StatusOK, s.Rescore.Status())
}

// handleRescoreCancel stops an in-progress re-scoring job (lead).
func (s *Server) handleRescoreCancel(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Rescore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "re-scoring is not available"})
		return
	}
	err := s.Rescore.Cancel()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "rescore_cancel", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.Rescore.Status())
}

// okOr returns "ok" for a nil error else "failed", for audit results.
func okOr(err error) string {
	if err != nil {
		return "failed"
	}
	return "ok"
}

func userErrStatus(err error) int {
	switch {
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrLastLead):
		return http.StatusConflict
	case errors.Is(err, auth.ErrUserNotFound):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest // weak password, invalid role, bad input
	}
}

// handleListUsers lists operators (no password hashes), flagging the caller (lead).
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	type row struct {
		auth.Info
		IsSelf         bool   `json:"is_self"`
		LastLogin      string `json:"last_login,omitempty"`
		LastLoginIP    string `json:"last_login_ip,omitempty"`
		FailedAttempts int    `json:"failed_attempts"`
		Locked         bool   `json:"locked"`
		LockedUntil    string `json:"locked_until,omitempty"`
	}
	infos := s.Users.List()
	rows := make([]row, len(infos))
	for i, in := range infos {
		rows[i] = row{Info: in, IsSelf: in.Username == sess.Username}
		if s.Logins != nil {
			st := s.Logins.State(in.Username)
			rows[i].LastLogin = fmtTime(st.LastSuccess)
			rows[i].LastLoginIP = st.LastSuccessIP
			rows[i].FailedAttempts = st.FailedAttempts
			rows[i].Locked = st.Locked
			rows[i].LockedUntil = fmtTime(st.LockedUntil)
		}
	}
	writeJSON(w, http.StatusOK, rows)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// handleUnlockUser clears an account lockout (lead).
func (s *Server) handleUnlockUser(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	target := r.PathValue("username")
	if s.Logins != nil {
		s.Logins.Unlock(target)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "user_unlock", Target: target, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"unlocked": target})
}

// handleAuditLog returns recent audit events matching the query filters (lead). The
// audit log never contains cleartext, so this is a read-only oversight view.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	events, err := audit.Query(s.AuditPath, auditFilter(q, limit))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read audit log"})
		return
	}
	if events == nil {
		events = []audit.Event{}
	}
	writeJSON(w, http.StatusOK, events)
}

// handleAuditLogCSV streams the matching audit events as a CSV download (lead).
func (s *Server) handleAuditLogCSV(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-log.csv"`)
	err := audit.StreamCSV(s.AuditPath, auditFilter(r.URL.Query(), 0), w)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_export", Source: r.RemoteAddr, Result: okOr(err)})
}

// auditFilter builds an audit.Filter from query params. from/to accept either a
// YYYY-MM-DD date (parsed UTC; a `to` date covers the whole day inclusively) or a
// full RFC3339 instant (used exactly, as a half-open [from,to) bound). The UI sends
// date-only values; RFC3339 is for hand-built queries.
func auditFilter(q url.Values, limit int) audit.Filter {
	return audit.Filter{
		Text:   q.Get("q"),
		Action: q.Get("action"),
		Result: q.Get("result"),
		Actor:  q.Get("actor"),
		From:   parseAuditTime(q.Get("from"), false),
		To:     parseAuditTime(q.Get("to"), true),
		Limit:  limit,
	}
}

func parseAuditTime(s string, endOfDay bool) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil { // UTC; the log is UTC
		if endOfDay {
			return t.Add(24 * time.Hour) // exclusive upper bound -> includes the whole day
		}
		return t
	}
	return time.Time{}
}

type bheConfigBody struct {
	Scheme             string `json:"scheme"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	TokenID            string `json:"token_id"`
	TokenKey           string `json:"token_key"`
	SearchLimit        int    `json:"search_limit"`
	ControllablesLimit int    `json:"controllables_limit"`
}

// bheMerge builds a full config from the submitted body, preserving the saved token
// when a field is left blank (the token is write-only in the UI) and inheriting saved
// limits/timeouts.
func (s *Server) bheMerge(b bheConfigBody) bloodhound.Config {
	saved, _ := bloodhound.LoadConfig(s.BHEPath)
	cfg := bloodhound.Config{
		Scheme: b.Scheme, Host: b.Host, Port: b.Port,
		TokenID: b.TokenID, TokenKey: b.TokenKey,
		SearchLimit: b.SearchLimit, ControllablesLimit: b.ControllablesLimit,
		ConnectTimeout: saved.ConnectTimeout, ReadTimeout: saved.ReadTimeout,
	}
	if cfg.TokenID == "" {
		cfg.TokenID = saved.TokenID
	}
	if cfg.TokenKey == "" {
		cfg.TokenKey = saved.TokenKey
	}
	if cfg.SearchLimit == 0 {
		cfg.SearchLimit = saved.SearchLimit
	}
	if cfg.ControllablesLimit == 0 {
		cfg.ControllablesLimit = saved.ControllablesLimit
	}
	return cfg
}

// handleBHEStatus returns the BloodHound config (token redacted) + whether
// enrichment is currently active (lead).
func (s *Server) handleBHEStatus(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	cfg, _ := bloodhound.LoadConfig(s.BHEPath) // missing/invalid -> zero config
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "http"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scheme":              scheme,
		"host":                cfg.Host,
		"port":                cfg.Port,
		"search_limit":        cfg.SearchLimit,
		"controllables_limit": cfg.ControllablesLimit,
		"token_configured":    cfg.TokenID != "" && cfg.TokenKey != "",
		"active":              s.Engine != nil && s.Engine.HasEnricher(),
		"config_path":         s.BHEPath,
	})
}

// handleBHETest probes a BloodHound connection with the submitted config (blank token
// = use the saved one) and returns the server version + collected domains (lead).
func (s *Server) handleBHETest(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	var body bheConfigBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	cfg := s.bheMerge(body)
	if cfg.Host == "" || cfg.TokenID == "" || cfg.TokenKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host, token id, and token key are required"})
		return
	}
	if cfg.ReadTimeout == 0 || cfg.ReadTimeout > 15 {
		cfg.ReadTimeout = 15 // cap the probe so a dead host doesn't hang the request
	}
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	client := bloodhound.New(cfg)
	ver, err := client.GetVersion()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "bhe_test", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	type dom struct {
		Name      string `json:"name"`
		Collected bool   `json:"collected"`
	}
	out := []dom{}
	if doms, derr := client.GetDomains(); derr == nil {
		for _, d := range doms {
			out = append(out, dom{Name: d.Name, Collected: d.Collected})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "server_version": ver.Server, "domains": out})
}

// handleBHEConfig saves the BloodHound config and hot-swaps the live enricher (lead).
func (s *Server) handleBHEConfig(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.BHEPath == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "BloodHound config path not set"})
		return
	}
	var body bheConfigBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	cfg := s.bheMerge(body)
	if cfg.Host == "" || cfg.TokenID == "" || cfg.TokenKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host, token id, and token key are required"})
		return
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "http"
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if err := bloodhound.SaveConfig(s.BHEPath, cfg); err != nil {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "bhe_config", Source: r.RemoteAddr, Result: "failed"})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save config"})
		return
	}
	if s.Engine != nil {
		s.Engine.SwapEnricher(engine.BloodhoundEnricher{Client: bloodhound.New(cfg)})
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "bhe_config", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "active": s.Engine != nil})
}

// handleLoginActivity returns recent login attempts across operators (lead).
func (s *Server) handleLoginActivity(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Logins == nil {
		writeJSON(w, http.StatusOK, []auth.Attempt{})
		return
	}
	writeJSON(w, http.StatusOK, s.Logins.Recent(25))
}

// handleCreateUser adds an operator (lead).
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	var body struct {
		Username string    `json:"username"`
		Password string    `json:"password"`
		Role     auth.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	err := s.Users.Create(body.Username, body.Password, body.Role)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "user_create", Target: body.Username, Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, userErrStatus(err), map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": body.Username, "role": string(body.Role)})
}

// handleUpdateUser changes an operator's role, password, and/or enabled state (lead).
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	target := r.PathValue("username")
	var body struct {
		Role     *auth.Role `json:"role"`
		Password *string    `json:"password"`
		Disabled *bool      `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.Disabled != nil && *body.Disabled && target == sess.Username {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "you cannot disable your own account"})
		return
	}
	var err error
	if body.Role != nil {
		err = s.Users.SetRole(target, *body.Role)
	}
	if err == nil && body.Password != nil {
		err = s.Users.SetPassword(target, *body.Password)
	}
	if err == nil && body.Disabled != nil {
		err = s.Users.SetDisabled(target, *body.Disabled)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "user_update", Target: target, Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, userErrStatus(err), map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": target})
}

// handleDeleteUser removes an operator (lead).
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	target := r.PathValue("username")
	if target == sess.Username {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "you cannot delete your own account"})
		return
	}
	err := s.Users.Delete(target)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "user_delete", Target: target, Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, userErrStatus(err), map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": target})
}

// touch records activity for the idle auto-lock timer.
func (s *Server) touch() { s.lastActivity.Store(time.Now().UnixNano()) }

// HoldActivity marks a long background op in-flight so the idle auto-lock can't
// fire while it runs; release via ReleaseActivity.
func (s *Server) HoldActivity()    { s.inFlight.Add(1); s.touch() }
func (s *Server) ReleaseActivity() { s.inFlight.Add(-1); s.touch() }

// StartAutoLock locks the store after d of inactivity (no-op if d <= 0). Returns
// a stop function. Activity is any unlocked, authenticated data access.
func (s *Server) StartAutoLock(d time.Duration) func() {
	if d <= 0 {
		return func() {}
	}
	s.touch()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				last := time.Unix(0, s.lastActivity.Load())
				if shouldAutoLock(s.Store.Unlocked(), s.inFlight.Load(), last, d, time.Now()) {
					s.Store.Lock()
					s.Audit.Log(audit.Event{Action: "store_lock", Source: "auto", Result: "ok"})
					log.Printf("auto-locked encrypted store after %s idle", d)
				}
			}
		}
	}()
	return func() { close(stop) }
}

// requireUnlocked rejects requests when the encrypted store is locked (423).
func (s *Server) requireUnlocked(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail fast (don't stall on the vault lock) while a rekey re-encrypts.
		if s.Store.Rekeying() {
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "data-key rotation in progress, retry shortly"})
			return
		}
		if !s.Store.Unlocked() {
			writeJSON(w, http.StatusLocked, map[string]string{"error": "data store is locked"})
			return
		}
		s.touch()         // activity resets the idle auto-lock timer
		s.inFlight.Add(1) // count in-flight data ops so auto-lock won't fire mid-upload/reveal
		defer s.inFlight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// shouldAutoLock decides whether the idle auto-lock should fire now: the store is
// unlocked, no data request is in flight, and idle has elapsed since last activity.
func shouldAutoLock(unlocked bool, inFlight int64, last time.Time, idle time.Duration, now time.Time) bool {
	return unlocked && inFlight == 0 && now.Sub(last) >= idle
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

// activeAuditRead resolves the session's selected audit WITHOUT writing a
// response. Read endpoints use this so "no audit selected" yields an empty 200
// (a normal not-yet-started state) instead of a 409 the browser logs as an error.
func (s *Server) activeAuditRead(sess auth.Session) (string, bool) {
	if sess.ActiveAudit == "" || !s.Store.Has(sess.ActiveAudit) {
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
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, []model.Account{})
		return
	}
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		writeJSON(w, http.StatusOK, []model.Account{})
		return
	}
	writeJSON(w, http.StatusOK, accts)
}

// handleAuditAccounts returns the redacted accounts for a SPECIFIC audit by id
// (not necessarily the session's active audit) -- used by Compare to open the
// account drawer for either compared audit. Same redaction + gating as
// /api/accounts; unknown/empty id yields 200 [].
func (s *Server) handleAuditAccounts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		writeJSON(w, http.StatusOK, []model.Account{})
		return
	}
	writeJSON(w, http.StatusOK, accts)
}

// ProbeResult is the response for POST /api/probe: the redacted accounts in the
// active audit whose password matches the supplied candidate, plus the count.
type ProbeResult struct {
	Count   int             `json:"count"`
	Matches []model.Account `json:"matches"`
}

// handleProbe answers "which accounts in the active audit use this exact
// password?" by hashing the operator's candidate to NTLM and matching it against
// the stored NT hashes. The candidate is never stored, logged, or echoed; the
// response carries only redacted accounts. Any authenticated operator may probe;
// every call is audit-logged (password_probe) with the match COUNT only.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	var body struct {
		Password string `json:"password"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&body); err != nil || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password required"})
		return
	}
	candidate := hibp.NTLMHash(body.Password)
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, ProbeResult{Count: 0, Matches: []model.Account{}})
		return
	}
	full, err := s.Store.Accounts(id, true) // includeSecrets=true to read NTHash
	if err != nil {
		writeJSON(w, http.StatusOK, ProbeResult{Count: 0, Matches: []model.Account{}})
		return
	}
	matches := []model.Account{}
	for _, a := range full {
		if a.NTHash != "" && strings.EqualFold(a.NTHash, candidate) {
			matches = append(matches, a.Redacted())
		}
	}
	s.Audit.Log(audit.Event{
		Actor: sess.Username, Role: string(sess.Role),
		Action: "password_probe", Target: fmt.Sprintf("matches=%d", len(matches)),
		Source: r.RemoteAddr, Result: "ok",
	})
	writeJSON(w, http.StatusOK, ProbeResult{Count: len(matches), Matches: matches})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, model.Summary{})
		return
	}
	sum, err := s.Store.Summary(id)
	if err != nil {
		writeJSON(w, http.StatusOK, model.Summary{})
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// handleReport builds the Actionable reports (cracked accounts, cracked- and
// uncracked-password reuse groups keyed on NT hash, HIBP-exposed accounts). It
// reads the unredacted accounts so it can group by NT hash, but model.BuildReport
// returns only redacted rows -- no cleartext password, no NT hash ever leaves here.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, model.BuildReport(nil))
		return
	}
	accts, err := s.Store.Accounts(id, true) // need NT hashes to group; report is redacted
	if err != nil {
		writeJSON(w, http.StatusOK, model.BuildReport(nil))
		return
	}
	writeJSON(w, http.StatusOK, model.BuildReport(accts))
}

// handleMetrics serves the computed dashboard bundle (summary, matrix, chart
// series, report-derived series, network graphs, and per-domain bundles) for the
// session's active audit. Like handleReport it reads accounts WITH NT hashes so the
// reuse-grouped report-series/graphs can be built; metrics.Compute emits only
// redacted, descriptive numbers -- no cleartext, no NT hash ever leaves here.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	now := time.Now()
	var accts []model.Account
	if id, ok := s.activeAuditRead(sess); ok {
		if a, err := s.Store.Accounts(id, true); err == nil {
			accts = a
		}
	}
	m := metrics.Compute(accts, now)
	if d := r.URL.Query().Get("domain"); d != "" {
		for i := range m.Domains {
			if m.Domains[i].Domain == d {
				writeJSON(w, http.StatusOK, m.Domains[i])
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// handleReportTerms returns the recurring forbidden words + keyboard patterns --
// the ACTUAL matched strings (cleartext fragments). Lead-only, and every call is
// audit-logged (the terms themselves never go in the log). This is the single place
// these words leave the process; they are never persisted unredacted or exported.
func (s *Server) handleReportTerms(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		if !s.auditOrFail(w, audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_violation_terms", Source: r.RemoteAddr, Result: "denied"}) {
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, model.AggregateTerms(nil, 25))
		return
	}
	accts, err := s.Store.Accounts(id, true) // need unredacted matches
	if err != nil {
		writeJSON(w, http.StatusOK, model.AggregateTerms(nil, 25))
		return
	}
	meta, _ := s.Store.Meta(id) // id is guaranteed present by activeAuditRead above
	if !s.auditOrFail(w, audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_violation_terms", Target: meta.Name, Source: r.RemoteAddr, Result: "ok"}) {
		return
	}
	writeJSON(w, http.StatusOK, model.AggregateTerms(accts, 25))
}

// handleReveal returns a single account's cleartext password. Requires the lead
// role; every attempt (allowed or denied) is audit-logged. The password is
// never written to the audit log.
func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	target := username
	if domain != "" && !strings.Contains(username, "@") {
		target = username + "@" + domain
	}
	ev := func(result string) audit.Event {
		return audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: target, Source: r.RemoteAddr, Result: result}
	}
	// Every reveal attempt is fail-closed on the audit write -- if the audit sink is
	// down we refuse the request rather than act unlogged (symmetric across branches).
	if sess.Role != auth.RoleLead {
		if !s.auditOrFail(w, ev("denied")) {
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	var acct model.Account
	var found bool
	if domain != "" {
		acct, found = s.Store.FindByDomain(id, username, domain)
	} else {
		acct, found = s.Store.Find(id, username)
	}
	if !found {
		if !s.auditOrFail(w, ev("not_found")) {
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	if !s.auditOrFail(w, ev("ok")) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": acct.Username, "password": acct.Password})
}

// handleAccountRelationships returns the focus account's NT-hash reuse group as
// IDENTITIES ONLY (username/domain/risk/flags) — never the NT hash or cleartext. The
// page derives the reuse group, the Shared-DA peers (has_da_path), and the mass-reuse
// summary from this; near-duplicate peers come from the account's own similar_peers.
func (s *Server) handleAccountRelationships(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	id, ok := s.activeAuditRead(sess)
	if !ok {
		// No audit selected → the account simply can't be found.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	accts, err := s.Store.Accounts(id, true) // unredacted: NT hash for grouping only; never returned
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load accounts"})
		return
	}
	var focus model.Account
	found := false
	for _, a := range accts {
		if a.Username == username && (domain == "" || a.Domain == domain) {
			focus, found = a, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	peers, total, crackedCount, daCount := model.ReuseGroupPeers(accts, focus, 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": focus.Username,
		"domain":   focus.Domain,
		"reuse_group": map[string]any{
			"shares_hash":   total > 0,
			"total":         total,
			"cracked_count": crackedCount,
			"da_count":      daCount,
			"truncated":     total > len(peers),
			"members":       peers,
		},
	})
}

// auditOrFail writes an audit event; if the write fails it responds 500 and returns
// false so the caller aborts (the audit log is a security control -- a security-
// relevant action must not proceed while it can't be recorded).
func (s *Server) auditOrFail(w http.ResponseWriter, e audit.Event) bool {
	if err := s.Audit.Log(e); err != nil {
		log.Printf("audit write failed (%s/%s): %v", e.Action, e.Result, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not record the audit event"})
		return false
	}
	return true
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

	// A big dump + cold HIBP seeks can exceed the server's default read/write
	// timeouts; extend them for this route so the upload isn't cut mid-flight.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetReadDeadline(time.Now().Add(10 * time.Minute))
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))
	}

	r.Body = http.MaxBytesReader(w, r.Body, 512<<20) // 512 MiB cap, streamed (no temp spill)
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload: " + err.Error()})
		return
	}
	var domain, dumpName string
	var cracked, uncracked []secretsdump.ParsedAccount
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload: " + err.Error()})
			return
		}
		fn := part.FormName() // capture before any Close() call
		switch fn {
		case "domain":
			b, rerr := io.ReadAll(part)
			if rerr != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reading domain: " + rerr.Error()})
				return
			}
			domain = strings.TrimSpace(string(b))
		case "cracked", "uncracked":
			if domain == "" {
				part.Close()
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the domain field must be sent before the file"})
				return
			}
			parse := secretsdump.ParseUncracked
			if fn == "cracked" {
				parse = secretsdump.ParseCracked
			}
			accts, perr := parse(part, domain)
			name := part.FileName()
			part.Close()
			if perr != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": fn + " file: " + perr.Error()})
				return
			}
			dumpName = name
			if fn == "cracked" {
				cracked = accts
			} else {
				uncracked = accts
			}
		default:
			part.Close()
		}
	}
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	if len(cracked) == 0 && len(uncracked) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upload a cracked and/or uncracked (pwdump) file"})
		return
	}

	wasEmpty := true
	if existing, err := s.Store.Accounts(auditID, false); err == nil && len(existing) > 0 {
		wasEmpty = false
	}

	accts := s.Engine.ProcessDomainNoEnrich(domain, cracked, uncracked)
	if err := s.Store.ReplaceDomain(auditID, domain, accts); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	if err := s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: dumpName, Kind: "dump", Domain: domain,
		AccountsLoaded: len(accts), At: time.Now().UTC(), By: sess.Username,
	}); err != nil {
		// Best-effort: the upload already succeeded and was audit-logged; a
		// history-write failure must not fail the request, but leave a trace.
		log.Printf("record ingest event (dump %s/%s): %v", domain, dumpName, err)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_upload", Target: domain, Source: r.RemoteAddr, Result: "ok"})
	if wasEmpty {
		s.kickEnrich(auditID) // auto-enrich once, on the first data load
	}
	writeJSON(w, http.StatusOK, map[string]int{"accounts": len(accts), "cracked": len(cracked), "uncracked": len(uncracked)})
}

// handleApplyCracks applies a hashcat-style crack file (user:hash:password lines) to
// the active audit, matching by NT hash -- so one cracked hash flips EVERY account
// that shares it (cracked or uncracked, any domain) -- then re-scores. Lead only.
func (s *Server) handleApplyCracks(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
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
	// Re-scoring re-runs full password analysis on all accounts; extend the deadlines for large datasets.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetReadDeadline(time.Now().Add(10 * time.Minute))
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse upload"})
		return
	}
	var cracks map[string]string
	var crackName string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse upload"})
			return
		}
		if part.FormName() == "crackfile" {
			crackName = part.FileName()
			cracks, err = secretsdump.CrackMap(part)
			part.Close()
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse crack file"})
				return
			}
		} else {
			part.Close()
		}
	}
	if cracks == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a 'crackfile' (user:hash:password lines) is required"})
		return
	}
	accounts, err := s.Store.Accounts(auditID, true) // need NT hashes + any existing cleartext
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return
	}
	matched := map[string]bool{}
	newly := 0
	for i := range accounts {
		if accounts[i].Password != "" {
			continue // already cracked
		}
		h := strings.ToUpper(strings.TrimSpace(accounts[i].NTHash))
		if pw, ok := cracks[h]; ok {
			accounts[i].Password = pw
			matched[h] = true
			newly++
		}
	}
	rescored := s.Engine.RescoreWith(accounts, nil)
	meta, _ := s.Store.Meta(auditID)
	if err := s.Store.Replace(auditID, model.Dataset{Name: meta.Name, Accounts: rescored}); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	if err := s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: crackName, Kind: "cracks",
		HashesMatched: len(matched), NewlyCracked: newly, At: time.Now().UTC(), By: sess.Username,
	}); err != nil {
		// Best-effort: the apply already succeeded and was audit-logged.
		log.Printf("record ingest event (cracks %s): %v", crackName, err)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "apply_cracks", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]int{"crack_entries": len(cracks), "hashes_matched": len(matched), "newly_cracked": newly})
}

// handleUploadBHEUsers accepts a BloodHound users JSON export (SharpHound or BHE
// format) and merges the AD properties (pwdLastSet, pwdNeverExpires, enabled,
// controlled objects) into the active audit's accounts. This avoids querying BHE
// for per-user properties — only DA-path graph queries still need a live connection.
func (s *Server) handleUploadBHEUsers(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	// Parse multipart: expect a single file field "bheusers".
	if err := r.ParseMultipartForm(256 << 20); err != nil { // 256 MB max
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload"})
		return
	}
	f, fh, err := r.FormFile("bheusers")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bheusers file required"})
		return
	}
	defer f.Close()

	users, err := bloodhound.ParseUsersExport(f)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parse error: " + err.Error()})
		return
	}
	if len(users) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no users found in the upload"})
		return
	}

	// Mutate accounts: merge BHE properties into matching accounts.
	var matched int
	if err := s.Store.Mutate(auditID, func(current []model.Account) []model.Account {
		next := make([]model.Account, len(current))
		copy(next, current)
		for i := range next {
			key := bloodhound.LookupKey(next[i].Username, next[i].Domain)
			imp, ok := users[key]
			if !ok {
				continue
			}
			matched++
			if imp.Enabled != nil {
				next[i].Enabled = *imp.Enabled
			}
			if imp.PwdLastSet > 0 {
				next[i].PwdLastSet = imp.PwdLastSet
			}
			ne := imp.PwdNeverExpires
			next[i].PwdNeverExpires = &ne
			if imp.Controllables > 0 {
				next[i].Controlled = imp.Controllables
			}
			spn := imp.HasSPN
			next[i].HasSPN = &spn
			preauth := imp.DontReqPreauth
			next[i].DontReqPreauth = &preauth
		}
		return next
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	_ = s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: fh.Filename, Kind: "enrich",
		AccountsLoaded: matched, At: time.Now().UTC(), By: sess.Username,
	})
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "upload_bhe_users", Target: auditID, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"uploaded_users": len(users), "matched_accounts": matched})
}

// handleDeleteDomain removes one domain's accounts from the active audit (lead only).
func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	domain := r.PathValue("domain")
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	before, err := s.Store.Accounts(auditID, false)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	removed := 0
	for _, a := range before {
		if a.Domain == domain {
			removed++
		}
	}
	if removed == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no accounts for domain " + domain})
		return
	}
	if err := s.Store.ReplaceDomain(auditID, domain, nil); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	if err := s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: domain, Kind: "domain_delete", Domain: domain,
		AccountsLoaded: removed, At: time.Now().UTC(), By: sess.Username,
	}); err != nil {
		log.Printf("record domain_delete ingest (%s): %v", domain, err)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "domain_delete", Target: domain, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]int{"removed": removed})
}

// handleListAudits returns all audits' metadata + headline counts.
func (s *Server) handleListAudits(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.List())
}

// handleIngests returns the active audit's ingest history (lead only -- it mirrors
// the lead-only Upload surface). Metadata only; no password or hash.
func (s *Server) handleIngests(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, []model.IngestEvent{})
		return
	}
	evs, err := s.Store.Ingests(id)
	if err != nil {
		writeJSON(w, http.StatusOK, []model.IngestEvent{})
		return
	}
	if evs == nil {
		evs = []model.IngestEvent{} // emit [] not null
	}
	writeJSON(w, http.StatusOK, evs)
}

// handleDiff compares two audits (a = earlier, b = later), redacted.
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	idA, idB := r.PathValue("a"), r.PathValue("b")
	accA, errA := s.Store.Accounts(idA, false)
	accB, errB := s.Store.Accounts(idB, false)
	if errA != nil || errB != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "audit not found"})
		return
	}
	metaA, _ := s.Store.Meta(idA)
	metaB, _ := s.Store.Meta(idB)
	writeJSON(w, http.StatusOK, map[string]any{"a": metaA, "b": metaB, "diff": report.ComputeDiff(accA, accB)})
}

// exportResolve resolves the active audit, logs the export (with a report label),
// and returns the audit metadata + id. Callers load the accounts they need.
func (s *Server) exportResolve(w http.ResponseWriter, r *http.Request, label string) (store.AuditMeta, string, bool) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return store.AuditMeta{}, "", false
	}
	meta, _ := s.Store.Meta(id)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "export", Target: meta.Name + " — " + label, Source: r.RemoteAddr, Result: "ok"})
	return meta, id, true
}

// exportResolveRead is the read-only variant of exportResolve for the
// always-available export surfaces (full CSV + reuse groups): when no audit is
// selected it writes an empty 200 document (so the browser doesn't log a 409) and
// returns ok=false. When an audit IS selected it audit-logs the export exactly
// like exportResolve. The bool reports whether the caller should write content.
func (s *Server) exportResolveRead(w http.ResponseWriter, r *http.Request, label, emptyName, suffix, ext string, writeEmpty func(http.ResponseWriter)) (store.AuditMeta, string, bool) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAuditRead(sess)
	if !ok {
		download(w, emptyName, suffix, ext)
		writeEmpty(w)
		return store.AuditMeta{}, "", false
	}
	meta, _ := s.Store.Meta(id)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "export", Target: meta.Name + " — " + label, Source: r.RemoteAddr, Result: "ok"})
	return meta, id, true
}

// exportAccountsRead is the read-only variant of exportAccounts: no audit (or a
// Store miss) yields an empty 200 CSV instead of a 409.
func (s *Server) exportAccountsRead(w http.ResponseWriter, r *http.Request, label string) (store.AuditMeta, []model.Account, bool) {
	meta, id, ok := s.exportResolveRead(w, r, label, "audit", "", "csv", func(w http.ResponseWriter) { _ = report.CSV(w, nil) })
	if !ok {
		return store.AuditMeta{}, nil, false
	}
	accts, err := s.Store.Accounts(id, false) // redacted -- never cleartext
	if err != nil {
		download(w, "audit", "", "csv")
		_ = report.CSV(w, nil)
		return store.AuditMeta{}, nil, false
	}
	return meta, accts, true
}

// download sets attachment headers for a report file (ext "csv", "html", or "json").
func download(w http.ResponseWriter, name, suffix, ext string) {
	fn := safeFilename(name)
	if suffix != "" {
		fn += "_" + suffix
	}
	ctype := "text/csv; charset=utf-8"
	if ext == "html" {
		ctype = "text/html; charset=utf-8"
	}
	if ext == "json" {
		ctype = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+fn+"."+ext+`"`)
}

// exportAccounts resolves the active audit, audit-logs the export, and returns its
// redacted accounts. Callers filter as needed (the data is already cleartext-free).
func (s *Server) exportAccounts(w http.ResponseWriter, r *http.Request, label string) (store.AuditMeta, []model.Account, bool) {
	meta, id, ok := s.exportResolve(w, r, label)
	if !ok {
		return store.AuditMeta{}, nil, false
	}
	accts, err := s.Store.Accounts(id, false) // redacted -- never cleartext
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return store.AuditMeta{}, nil, false
	}
	return meta, accts, true
}

func filterAccounts(accts []model.Account, keep func(model.Account) bool) []model.Account {
	out := make([]model.Account, 0)
	for _, a := range accts {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

func byBreachDesc(a []model.Account) []model.Account {
	sort.SliceStable(a, func(i, j int) bool { return a[i].HIBPBreachCount > a[j].HIBPBreachCount })
	return a
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccountsRead(w, r, "accounts CSV")
	if !ok {
		return // empty 200 already written
	}
	download(w, meta.Name, "", "csv")
	_ = report.CSV(w, accts)
}

func (s *Server) handleExportCracked(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "cracked CSV")
	if !ok {
		return
	}
	download(w, meta.Name, "cracked", "csv")
	_ = report.CSV(w, filterAccounts(accts, func(a model.Account) bool { return a.Cracked }))
}

func (s *Server) handleExportHIBP(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "HIBP CSV")
	if !ok {
		return
	}
	download(w, meta.Name, "hibp", "csv")
	_ = report.CSV(w, byBreachDesc(filterAccounts(accts, func(a model.Account) bool { return a.HIBPBreached })))
}

func (s *Server) handleExportWeak(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "weak-passwords CSV")
	if !ok {
		return
	}
	download(w, meta.Name, "weak-passwords", "csv")
	_ = report.CSV(w, filterAccounts(accts, func(a model.Account) bool { return a.IsWeak() }))
}

func (s *Server) handleExportWeakHTML(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "weak-passwords HTML")
	if !ok {
		return
	}
	download(w, meta.Name, "weak-passwords", "html")
	weak := filterAccounts(accts, func(a model.Account) bool { return a.IsWeak() })
	_ = report.WeakPasswordsHTML(w, meta.Name, time.Now().UTC(), weak)
}

func (s *Server) handleExportReuse(w http.ResponseWriter, r *http.Request) {
	meta, id, ok := s.exportResolveRead(w, r, "reuse-groups CSV", "audit", "reuse-groups", "csv",
		func(w http.ResponseWriter) { _ = report.ReuseGroupsCSV(w, model.BuildReport(nil)) })
	if !ok {
		return // empty 200 already written
	}
	accts, err := s.Store.Accounts(id, true) // need NT hashes to group; output is redacted
	if err != nil {
		download(w, "audit", "reuse-groups", "csv")
		_ = report.ReuseGroupsCSV(w, model.BuildReport(nil))
		return
	}
	download(w, meta.Name, "reuse-groups", "csv")
	_ = report.ReuseGroupsCSV(w, model.BuildReport(accts))
}

func (s *Server) handleExportHTML(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "full HTML")
	if !ok {
		return
	}
	download(w, meta.Name, "", "html")
	_ = report.HTML(w, meta.Name, time.Now().UTC(), accts)
}

func (s *Server) handleExportCrackedHTML(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "cracked HTML")
	if !ok {
		return
	}
	download(w, meta.Name, "cracked", "html")
	cracked := filterAccounts(accts, func(a model.Account) bool { return a.Cracked })
	_ = report.AccountsHTML(w, meta.Name+" — Cracked accounts", "cracked accounts", time.Now().UTC(), cracked)
}

func (s *Server) handleExportHIBPHTML(w http.ResponseWriter, r *http.Request) {
	meta, accts, ok := s.exportAccounts(w, r, "HIBP HTML")
	if !ok {
		return
	}
	download(w, meta.Name, "hibp", "html")
	hibp := byBreachDesc(filterAccounts(accts, func(a model.Account) bool { return a.HIBPBreached }))
	_ = report.AccountsHTML(w, meta.Name+" — HIBP-exposed accounts", "accounts whose NT hash is in HIBP", time.Now().UTC(), hibp)
}

// handleExportSanitized streams a fully anonymized review export: every per-account
// scoring signal + audit aggregates, with no identity or secret data. It reads the
// UNREDACTED accounts because the NT hash is needed to compute opaque reuse groups
// (the hash itself is never emitted). The download filename is generic so the
// operator-chosen audit name does not leak.
func (s *Server) handleExportSanitized(w http.ResponseWriter, r *http.Request) {
	ver := s.Build.Version
	if ver == "" {
		ver = "dev"
	}
	writeEmpty := func(w http.ResponseWriter) { _ = report.SanitizedJSON(w, nil, model.Summary{}, time.Now().UTC(), ver) }
	_, id, ok := s.exportResolveRead(w, r, "sanitized JSON", "patd-sanitized", "", "json", writeEmpty)
	if !ok {
		return
	}
	accts, err := s.Store.Accounts(id, true) // unredacted: NT hash for reuse grouping only; output is sanitized
	if err != nil {
		download(w, "patd-sanitized", "", "json")
		writeEmpty(w)
		return
	}
	sum, _ := s.Store.Summary(id)
	download(w, "patd-sanitized", "", "json")
	_ = report.SanitizedJSON(w, accts, sum, time.Now().UTC(), ver)
}

func (s *Server) handleExportReuseHTML(w http.ResponseWriter, r *http.Request) {
	meta, id, ok := s.exportResolveRead(w, r, "reuse-groups HTML", "audit", "reuse-groups", "html",
		func(w http.ResponseWriter) {
			_ = report.ReuseGroupsHTML(w, "Password-reuse groups", time.Now().UTC(), model.BuildReport(nil))
		})
	if !ok {
		return // empty 200 already written
	}
	accts, err := s.Store.Accounts(id, true) // need NT hashes to group; output is redacted
	if err != nil {
		download(w, "audit", "reuse-groups", "html")
		_ = report.ReuseGroupsHTML(w, "Password-reuse groups", time.Now().UTC(), model.BuildReport(nil))
		return
	}
	download(w, meta.Name, "reuse-groups", "html")
	_ = report.ReuseGroupsHTML(w, meta.Name+" — Password-reuse groups", time.Now().UTC(), model.BuildReport(accts))
}

// safeFilename keeps only filename-safe characters from an audit name.
func safeFilename(name string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "audit"
	}
	return b.String()
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
	if err := s.Store.Delete(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "audit not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete audit: " + err.Error()})
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

// forbiddenWordsPayload is the wire shape for GET/PUT /api/forbidden-words.
type forbiddenWordsPayload struct {
	Words []string `json:"words"`
}

// handleGetForbiddenWords returns the current forbidden-words list (sorted).
// Lead-only: the words are cleartext fragments (same sensitivity as
// /api/report/terms).
func (s *Server) handleGetForbiddenWords(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "forbidden_words_read", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine not configured"})
		return
	}
	set := s.Engine.ForbiddenWords()
	words := make([]string, 0, len(set))
	for word := range set {
		words = append(words, word)
	}
	sort.Strings(words)
	writeJSON(w, http.StatusOK, forbiddenWordsPayload{Words: words})
}

// handleSetForbiddenWords replaces the forbidden-words list (lead only), persists
// it to disk if a path is configured, and hot-swaps it into the engine so it
// applies to the next analysis. Audit-logged (count only, never the words).
func (s *Server) handleSetForbiddenWords(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "forbidden_words_update", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine not configured"})
		return
	}
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	var p forbiddenWordsPayload
	if err := dec.Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if len(p.Words) > 5000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many words (max 5000)"})
		return
	}
	set := pwanalysis.Set{}
	for _, raw := range p.Words {
		word := strings.ToLower(strings.TrimSpace(raw))
		if word == "" {
			continue
		}
		if len([]rune(word)) > 64 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "word too long (max 64 chars)"})
			return
		}
		if strings.ContainsAny(word, "\n\r\x00") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "word contains a control character"})
			return
		}
		set[word] = struct{}{}
	}
	s.Engine.SwapForbiddenWords(set)
	saved := "memory"
	if s.ForbiddenWordsPath != "" {
		if err := pwanalysis.SaveSet(s.ForbiddenWordsPath, set); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saved in memory but failed to persist: " + err.Error()})
			return
		}
		saved = s.ForbiddenWordsPath
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "forbidden_words_update", Target: strconv.Itoa(len(set)) + " word(s)", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"count": len(set), "persisted": saved})
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

// pollSoftAuth is requireAuth for the background-job poll endpoints (enrich /
// pwned / rescore job status). The SPA polls these every few seconds for leads;
// when the session is gone — server restart wiped the in-memory store, or
// idle/absolute expiry — a hard 401 makes the browser log a recurring console
// error and bounces the operator mid-navigation. Instead we answer 200 with
// {"unauthenticated":true}: no console noise, and the client treats that body as
// its cue to return to the login screen. A valid session is plumbed into the
// context exactly as requireAuth does, so the wrapped handler is unchanged.
func (s *Server) pollSoftAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			if sess, ok := s.Sessions.Get(c.Value); ok {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]bool{"unauthenticated": true})
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
		if r.TLS != nil { // pin clients to HTTPS once they've connected securely
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		// Log the matched route TEMPLATE (set during routing), not the substituted
		// path -- otherwise the reveal route would leak the target username here,
		// outside the access-controlled audit log. Fall back to the path for
		// unmatched requests (which carry no path parameters).
		route := r.Pattern
		if route == "" {
			route = r.URL.Path
		}
		log.Printf("%s %s %s", r.Method, route, time.Since(start).Round(time.Millisecond))
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
