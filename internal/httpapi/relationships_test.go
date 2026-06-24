package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// reuseDataset has alice/bob/administrator sharing hash "AAA" and carol with "BBB".
// administrator has da_domains="CORP" so it has a DA pathway.
const reuseDataset = `{"accounts":[
 {"username":"alice","domain":"CORP","password":"P@ss1","cracked":true,"risk_level":"Critical","nt_hash":"AAA","enabled":true,"da_domains":""},
 {"username":"bob","domain":"CORP","password":"P@ss1","cracked":true,"risk_level":"High","nt_hash":"AAA","enabled":true,"da_domains":""},
 {"username":"administrator","domain":"CORP","password":"P@ss1","cracked":true,"risk_level":"Critical","nt_hash":"AAA","enabled":true,"da_domains":"CORP"},
 {"username":"carol","domain":"CORP","password":"Other","cracked":true,"risk_level":"Low","nt_hash":"BBB","enabled":true,"da_domains":""}
]}`

// ingestDataset posts a raw JSON dataset via the ingest bearer token and returns the audit_id.
func ingestDataset(t *testing.T, srv *Server, dataset string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(dataset))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuditID string `json:"audit_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.AuditID == "" {
		t.Fatalf("ingest response missing audit_id: %v %s", err, rec.Body.String())
	}
	return body.AuditID
}

// TestRelationships_ReuseGroupIdentitiesOnly verifies the structural contract:
//   - 200 OK for focus "alice" (CORP)
//   - total == 2 (bob + administrator; carol is excluded as different hash)
//   - da_count == 1 (administrator)
//   - members sorted DA-first (administrator first, has_da_path=true)
//   - response body contains NO "nt_hash" and NO "password" key
func TestRelationships_ReuseGroupIdentitiesOnly(t *testing.T) {
	srv := newServer("secret")
	id := ingestDataset(t, srv, reuseDataset)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)

	rec := do(srv, "GET", "/api/accounts/alice/relationships?domain=CORP", lc)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// Secret material must never appear in the response.
	if strings.Contains(body, "nt_hash") {
		t.Fatalf("response contains 'nt_hash': %s", body)
	}
	if strings.Contains(body, `"password"`) {
		t.Fatalf("response contains '\"password\"': %s", body)
	}

	// Parse the structured response.
	var resp struct {
		Username   string `json:"username"`
		Domain     string `json:"domain"`
		ReuseGroup struct {
			SharesHash   bool `json:"shares_hash"`
			Total        int  `json:"total"`
			CrackedCount int  `json:"cracked_count"`
			DACount      int  `json:"da_count"`
			Truncated    bool `json:"truncated"`
			Members      []struct {
				Username  string `json:"username"`
				HasDAPath bool   `json:"has_da_path"`
			} `json:"members"`
		} `json:"reuse_group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v\nbody: %s", err, body)
	}

	if resp.Username != "alice" {
		t.Errorf("username = %q, want alice", resp.Username)
	}
	if resp.Domain != "CORP" {
		t.Errorf("domain = %q, want CORP", resp.Domain)
	}
	if !resp.ReuseGroup.SharesHash {
		t.Errorf("shares_hash = false, want true")
	}
	if resp.ReuseGroup.Total != 2 {
		t.Errorf("total = %d, want 2 (bob + administrator)", resp.ReuseGroup.Total)
	}
	if resp.ReuseGroup.CrackedCount != 2 {
		t.Errorf("cracked_count = %d, want 2", resp.ReuseGroup.CrackedCount)
	}
	if resp.ReuseGroup.DACount != 1 {
		t.Errorf("da_count = %d, want 1", resp.ReuseGroup.DACount)
	}
	if len(resp.ReuseGroup.Members) != 2 {
		t.Fatalf("members len = %d, want 2; members: %s", len(resp.ReuseGroup.Members), body)
	}

	// DA-first ordering: administrator must be first.
	if !resp.ReuseGroup.Members[0].HasDAPath {
		t.Errorf("first member should have has_da_path=true (DA-first order); got members: %s", body)
	}
	if resp.ReuseGroup.Members[0].Username != "administrator" {
		t.Errorf("first member username = %q, want administrator (DA-first)", resp.ReuseGroup.Members[0].Username)
	}
}

// TestRelationships_NotFound verifies that a request for a nonexistent account returns 404.
func TestRelationships_NotFound(t *testing.T) {
	srv := newServer("secret")
	id := ingestDataset(t, srv, reuseDataset)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)

	rec := do(srv, "GET", "/api/accounts/nobody/relationships?domain=CORP", lc)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown account, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestRelationships_NoAuditSelected verifies that a request with no audit open
// returns 404 (not 409) — activeAuditRead writes nothing; the handler normalises
// the "no context" case as account-not-found.
func TestRelationships_NoAuditSelected(t *testing.T) {
	srv := newServer("secret")
	// Ingest data so the store is populated, but do NOT open any audit.
	ingestDataset(t, srv, reuseDataset)

	lc, _ := loginCSRF(t, srv, "lead", "leadpw")

	rec := do(srv, "GET", "/api/accounts/alice/relationships?domain=CORP", lc)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (no audit selected), got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestRelationships_AnalystAllowed verifies that the analyst role gets 200 (identities
// are not secret material; no reveal gate is needed here).
func TestRelationships_AnalystAllowed(t *testing.T) {
	srv := newServer("secret")
	id := ingestDataset(t, srv, reuseDataset)

	// Open the audit with the analyst session.
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)

	rec := do(srv, "GET", "/api/accounts/alice/relationships?domain=CORP", ac)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyst expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, "nt_hash") {
		t.Fatalf("analyst response contains 'nt_hash': %s", body)
	}
	if strings.Contains(body, `"password"`) {
		t.Fatalf("analyst response contains '\"password\"': %s", body)
	}
}
