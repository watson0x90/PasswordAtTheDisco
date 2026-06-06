// Command api is the v2 secure-delivery backend for Password!AtTheDisco.
//
// Design goals (see ../README.md):
//   - Single self-contained binary; standard library only (no third-party deps)
//     so the runtime supply-chain surface is just the Go toolchain.
//   - Serves the built React SPA as static assets plus a JSON API over TLS.
//   - Cracked credentials live only in process memory and are served redacted
//     by default; unredacted access will be authorized and audit-logged.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/v2/api/internal/httpapi"
	"github.com/watson0x90/PasswordAtTheDisco/v2/api/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	addr := env("PATD_ADDR", "127.0.0.1:8443")
	cert, key := os.Getenv("PATD_TLS_CERT"), os.Getenv("PATD_TLS_KEY")
	api := &httpapi.Server{
		Store:       store.New(),
		StaticDir:   env("PATD_STATIC_DIR", "../web/dist"),
		IngestToken: os.Getenv("PATD_INGEST_TOKEN"),
	}

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

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
