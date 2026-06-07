// Package httpapi wires the HTTP routes, middleware, and handlers for the API.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

const sessionCookie = "patd_session"

// Server holds the API's dependencies.
type Server struct {
	Store        *store.Store
	StaticDir    string
	IngestToken  string // bearer token the analysis engine uses to push data
	Users        auth.Users
	Sessions     *auth.SessionStore
	Audit        *audit.Logger
	LoginLimiter *auth.Limiter // per-IP failed-login throttle
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
	// Engine ingestion (separate token, not a user session)
	mux.Handle("POST /api/ingest", s.requireIngestToken(http.HandlerFunc(s.handleIngest)))
	// Authenticated operators (any role) -- redacted data only
	mux.Handle("POST /api/logout", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleLogout))))
	mux.Handle("GET /api/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
	mux.Handle("GET /api/summary", s.requireAuth(http.HandlerFunc(s.handleSummary)))
	mux.Handle("GET /api/accounts", s.requireAuth(http.HandlerFunc(s.handleAccounts)))
	// Cleartext reveal -- requires lead role, always audit-logged
	mux.Handle("GET /api/accounts/{username}/secret", s.requireAuth(http.HandlerFunc(s.handleReveal)))
	// SPA
	mux.Handle("/", spaHandler(s.StaticDir))
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
	writeJSON(w, http.StatusOK, map[string]string{"username": sess.Username, "role": string(sess.Role), "csrf_token": sess.CSRF})
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
	s.Store.Replace(ds)
	writeJSON(w, http.StatusOK, map[string]int{"ingested": len(ds.Accounts)})
}

func (s *Server) handleAccounts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Accounts(false))
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Summary())
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
	acct, ok := s.Store.Find(username)
	if !ok {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: username, Source: r.RemoteAddr, Result: "not_found"})
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: username, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"username": acct.Username, "password": acct.Password})
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
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; "+
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

// spaHandler serves static files from dir, falling back to index.html for
// client-side routes. Rejects path traversal; never serves outside dir.
func spaHandler(dir string) http.Handler {
	root, _ := filepath.Abs(dir)
	fs := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := filepath.Join(root, filepath.Clean(r.URL.Path))
		if !strings.HasPrefix(target, root) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if info, err := os.Stat(target); err != nil || info.IsDir() {
			index := filepath.Join(root, "index.html")
			if _, err := os.Stat(index); err != nil {
				http.Error(w, "frontend not built (run the web build)", http.StatusServiceUnavailable)
				return
			}
			http.ServeFile(w, r, index)
			return
		}
		fs.ServeHTTP(w, r)
	})
}
