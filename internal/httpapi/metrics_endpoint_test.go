// Package httpapi wires the HTTP routes, middleware, and handlers for the API.
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestMetricsEndpoint(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv)
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)

	rec := do(srv, "GET", "/api/metrics", ac)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// the seeded fixture has one cracked account (alice) -> summary.total 1
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["summary"]; !ok {
		t.Error("response missing summary")
	}
	if _, ok := body["matrix"]; !ok {
		t.Error("response missing matrix")
	}
	if _, ok := body["charts"]; !ok {
		t.Error("response missing charts")
	}
	if _, ok := body["reports"]; !ok {
		t.Error("response missing reports")
	}
	// redaction: the raw JSON must not contain the seeded cleartext or any secret key
	raw := strings.ToLower(rec.Body.String())
	for _, bad := range []string{"welcome1", "nt_hash", "\"password\"", "banned_words", "keyboard_patterns"} {
		if strings.Contains(raw, bad) {
			t.Errorf("metrics response leaked %q", bad)
		}
	}
}

func TestMetricsRequiresAuth(t *testing.T) {
	srv := newServer("secret")
	if rec := do(srv, "GET", "/api/metrics", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", rec.Code)
	}
}
