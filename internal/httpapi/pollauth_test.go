package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The three background-job poll endpoints are polled every few seconds by the
// SPA's JobsProvider (lead-only). When the session is gone — server restart wiped
// the in-memory session store, or idle/absolute expiry — a 401 would make the
// browser log a recurring console error and bounce the operator mid-navigation.
// Instead these endpoints answer 200 with {"unauthenticated":true}: no console
// noise, and the client treats that body as its cue to return to the login screen.
var pollEndpoints = []string{"/api/enrich/job", "/api/pwned/job", "/api/rescore/job"}

func TestPollEndpoints_NoSession_Returns200Unauthenticated(t *testing.T) {
	srv := newServer("secret")
	for _, path := range pollEndpoints {
		rec := do(srv, "GET", path, nil) // no cookie → session is "gone"
		if rec.Code != http.StatusOK {
			t.Errorf("%s without session: got %d, want 200", path, rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: bad json: %v (%s)", path, err, rec.Body.String())
		}
		if body["unauthenticated"] != true {
			t.Errorf("%s without session: body = %s, want unauthenticated:true", path, rec.Body.String())
		}
	}
}

func TestPollEndpoints_ValidLead_NoUnauthenticatedMarker(t *testing.T) {
	srv := newServer("secret")
	cookie := login(t, srv, "lead", "leadpw")
	for _, path := range pollEndpoints {
		rec := do(srv, "GET", path, cookie)
		if rec.Code != http.StatusOK {
			t.Errorf("%s as lead: got %d, want 200", path, rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: bad json: %v (%s)", path, err, rec.Body.String())
		}
		if _, present := body["unauthenticated"]; present {
			t.Errorf("%s as lead: body unexpectedly carries unauthenticated marker: %s", path, rec.Body.String())
		}
	}
}
