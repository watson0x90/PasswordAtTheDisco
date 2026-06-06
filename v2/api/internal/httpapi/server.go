// Package httpapi wires the HTTP routes, middleware, and handlers for the API.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/v2/api/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/v2/api/internal/store"
)

// Server holds the API's dependencies.
type Server struct {
	Store       *store.Store
	StaticDir   string
	IngestToken string // bearer token the analysis engine uses to push data
}

// Routes returns the fully-wrapped handler (routes + middleware).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/version", s.handleVersion)
	mux.Handle("POST /api/ingest", s.requireIngestToken(http.HandlerFunc(s.handleIngest)))
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/accounts", s.handleAccounts)
	mux.Handle("/", spaHandler(s.StaticDir))
	return securityHeaders(logRequests(mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"name": "passwordatthedisco-api", "version": "0.1.0-dev"})
}

// handleIngest accepts a full audit dataset from the analysis engine and
// replaces the in-memory dataset. Requires a valid ingest token (middleware).
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

// handleAccounts returns the accounts redacted (no cleartext passwords).
// Cleartext access will be a separate authorized, audit-logged endpoint.
func (s *Server) handleAccounts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Accounts(false))
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Summary())
}

// requireIngestToken enforces a bearer token on the ingestion endpoint and
// fails closed: if no token is configured, all ingestion is rejected.
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
