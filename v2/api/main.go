// Command api is the v2 secure-delivery backend for Password!AtTheDisco.
//
// Design goals (see ../README.md):
//   - Single self-contained binary; standard library only (no third-party deps)
//     so the runtime supply-chain surface is just the Go toolchain.
//   - Serves the built React SPA as static assets plus a JSON API over TLS.
//   - Sensitive data (cracked credentials) is never written to static files;
//     it is served by authenticated, authorized, audit-logged endpoints (to be
//     built on top of this skeleton).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type config struct {
	addr      string
	tlsCert   string
	tlsKey    string
	staticDir string
}

func loadConfig() config {
	return config{
		addr:      env("PATD_ADDR", "127.0.0.1:8443"),
		tlsCert:   os.Getenv("PATD_TLS_CERT"),
		tlsKey:    os.Getenv("PATD_TLS_KEY"),
		staticDir: env("PATD_STATIC_DIR", "../web/dist"),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := loadConfig()
	log.SetFlags(log.LstdFlags | log.LUTC)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /api/version", handleVersion)
	mux.Handle("/", spaHandler(cfg.staticDir))

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           securityHeaders(logRequests(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		var err error
		if cfg.tlsCert != "" && cfg.tlsKey != "" {
			log.Printf("listening on https://%s", cfg.addr)
			err = srv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
		} else {
			log.Printf("WARNING: serving plain HTTP on %s (set PATD_TLS_CERT/PATD_TLS_KEY for TLS)", cfg.addr)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"name": "passwordatthedisco-api", "version": "0.1.0-dev"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// securityHeaders applies a strict baseline suitable for a self-hosted SPA that
// loads only same-origin assets (no external CDNs).
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

// spaHandler serves static files from dir and falls back to index.html for
// client-side routes. It rejects path traversal and never serves outside dir.
func spaHandler(dir string) http.Handler {
	root, _ := filepath.Abs(dir)
	fs := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean(r.URL.Path)
		target := filepath.Join(root, clean)
		// Ensure the resolved path stays within root (defense in depth).
		if !strings.HasPrefix(target, root) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if info, err := os.Stat(target); err != nil || info.IsDir() {
			// Unknown path or directory -> serve the SPA entry point.
			indexPath := filepath.Join(root, "index.html")
			if _, err := os.Stat(indexPath); err != nil {
				http.Error(w, "frontend not built (run the web build)", http.StatusServiceUnavailable)
				return
			}
			http.ServeFile(w, r, indexPath)
			return
		}
		fs.ServeHTTP(w, r)
	})
}
