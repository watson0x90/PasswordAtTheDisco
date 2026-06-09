// Command api is the v2 secure-delivery backend for Password!AtTheDisco.
//
// Design goals (see ../README.md):
//   - Single self-contained binary; only the vetted golang.org/x/crypto beyond
//     the standard library, so the runtime supply-chain surface stays tiny.
//   - Serves the built React SPA as static assets plus a JSON API over TLS.
//   - Cracked credentials live only in process memory, are served redacted by
//     default, and are revealed only to authorized operators with an audit log.
//
// Subcommand: `api hashpw` reads a password on stdin and prints an argon2id
// hash for populating users.json.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/httpapi"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
	"github.com/watson0x90/PasswordAtTheDisco/internal/webui"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hashpw":
			hashpw()
			return
		case "audit":
			runAudit(os.Args[2:])
			return
		case "reindex":
			runReindex()
			return
		}
	}

	addr := env("PATD_ADDR", "127.0.0.1:8443")
	cert, key := os.Getenv("PATD_TLS_CERT"), os.Getenv("PATD_TLS_KEY")

	users := auth.Users{}
	usersFile := env("PATD_USERS_FILE", "users.json")
	if u, err := auth.LoadUsers(usersFile); err != nil {
		log.Printf("WARNING: no operators loaded (%v) -- login disabled until %s exists", err, usersFile)
	} else {
		users = u
		log.Printf("loaded %d operator(s) from %s", len(users), usersFile)
	}

	// Audit log (JSON lines, 0600). Defaults to stdout; never contains cleartext.
	var auditW = os.Stdout
	if p := os.Getenv("PATD_AUDIT_LOG"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("cannot open audit log %s: %v", p, err)
		}
		defer f.Close()
		auditW = f
	} else {
		log.Printf("WARNING: PATD_AUDIT_LOG unset -- audit events go to stdout (ephemeral). Set it to a persistent file for real use.")
	}

	// Audit engine for web uploads (lead POST /api/audit). Same inputs as the
	// `audit` CLI, from env. cleanup closes the HIBP searcher on shutdown.
	policyPath := env("PATD_POLICY", "lists/password_policy.json")
	eng, policies, cleanup := buildEngine(
		env("PATD_HIBP", "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt"),
		env("PATD_LISTS", "lists"),
		env("PATD_BHE", "config/bloodhound.json"),
		policyPath,
	)
	defer cleanup()

	// Encrypted-at-rest store. Starts locked; a lead unlocks it via the UI (the
	// passphrase is never persisted). On first run the passphrase is set then.
	dataDir := env("PATD_DATA", "data")
	vlt, err := vault.Open(dataDir)
	if err != nil {
		log.Fatalf("cannot open data dir %s: %v", dataDir, err)
	}
	if vlt.Initialized() {
		log.Printf("encrypted store %s: locked -- a lead must unlock via the UI", dataDir)
	} else {
		log.Printf("encrypted store %s: uninitialized -- a lead sets the passphrase on first unlock", dataDir)
	}

	api := &httpapi.Server{
		Store:         store.NewPersistent(vlt),
		StaticFS:      webui.FS, // embedded SPA when built with -tags embed; else nil
		StaticDir:     env("PATD_STATIC_DIR", "web/dist"),
		IngestToken:   os.Getenv("PATD_INGEST_TOKEN"),
		Users:         users,
		Sessions:      auth.NewSessionStore(30*time.Minute, 8*time.Hour),
		Audit:         audit.New(auditW),
		LoginLimiter:  auth.NewLimiter(10, 15*time.Minute),
		UnlockLimiter: auth.NewLimiter(5, 15*time.Minute),
		Engine:        eng,
		Policies:      policies,
		PolicyPath:    policyPath,
	}

	// Idle auto-lock: drop the key + clear decrypted data after inactivity so
	// cleartext doesn't sit in memory indefinitely. PATD_AUTOLOCK_MIN=0 disables.
	autoLock := time.Duration(envInt("PATD_AUTOLOCK_MIN", 60)) * time.Minute
	defer api.StartAutoLock(autoLock)()

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		var err error
		if cert != "" && key != "" {
			log.Printf("listening on https://%s", addr)
			err = srv.ListenAndServeTLS(cert, key)
		} else {
			log.Printf("WARNING: serving plain HTTP on %s (set PATD_TLS_CERT/PATD_TLS_KEY for TLS)", addr)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

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

func hashpw() {
	fmt.Fprint(os.Stderr, "Password: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		fmt.Fprintln(os.Stderr, "empty password")
		os.Exit(1)
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(h)
}

// runReindex rebuilds the encrypted metadata index from the audit blobs (recovery
// for a lost/corrupt index.enc). Reads the store passphrase from stdin.
func runReindex() {
	dataDir := env("PATD_DATA", "data")
	vlt, err := vault.Open(dataDir)
	if err != nil {
		log.Fatalf("open data dir %s: %v", dataDir, err)
	}
	if !vlt.Initialized() {
		log.Fatalf("no encrypted store at %s", dataDir)
	}
	fmt.Fprint(os.Stderr, "Store passphrase: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	s := store.NewPersistent(vlt)
	if err := s.Unlock(strings.TrimRight(line, "\r\n")); err != nil {
		log.Fatalf("unlock: %v", err)
	}
	if err := s.Reindex(); err != nil {
		log.Fatalf("reindex: %v", err)
	}
	fmt.Fprintf(os.Stderr, "reindexed %d audit(s)\n", len(s.List()))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
