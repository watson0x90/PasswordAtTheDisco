package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/v2/api/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/v2/api/internal/store"
)

func newServer(token string) *Server {
	return &Server{Store: store.New(), IngestToken: token}
}

func ingest(t *testing.T, srv *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

const oneAccount = `{"accounts":[{"username":"alice","domain":"CORP","password":"Welcome1",` +
	`"cracked":true,"risk_level":"Critical","hibp_breached":true,"da_domains":"CORP"}]}`

func TestIngestRejectsMissingToken(t *testing.T) {
	if rec := ingest(t, newServer("secret"), "", oneAccount); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestIngestFailsClosedWithoutConfiguredToken(t *testing.T) {
	if rec := ingest(t, newServer(""), "anything", oneAccount); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no token configured, got %d", rec.Code)
	}
}

func TestAccountsAreRedacted(t *testing.T) {
	srv := newServer("secret")
	if rec := ingest(t, srv, "secret", oneAccount); rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest("GET", "/api/accounts", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if bytes.Contains(rec.Body.Bytes(), []byte("Welcome1")) {
		t.Fatal("cleartext password leaked in /api/accounts")
	}
	var accts []model.Account
	if err := json.Unmarshal(rec.Body.Bytes(), &accts); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(accts) != 1 || accts[0].Username != "alice" || accts[0].Password != "" {
		t.Fatalf("unexpected accounts payload: %+v", accts)
	}
}

func TestSummaryEndpoint(t *testing.T) {
	srv := newServer("secret")
	ingest(t, srv, "secret", oneAccount)
	req := httptest.NewRequest("GET", "/api/summary", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	var sum model.Summary
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if sum.TotalAccounts != 1 || sum.Cracked != 1 || sum.DAPathways != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
}
