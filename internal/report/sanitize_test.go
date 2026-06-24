package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// TestSanitizedNoLeak is the decisive guarantee: no identifying/secret value
// appears anywhere in the serialized output, even though the input carries them.
func TestSanitizedNoLeak(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{{
		Username: "CANARY_USER", Domain: "CANARY.CORP", Password: "CANARY_PW",
		NTHash: "CANARYHASH", BannedWords: []string{"CANARYWORD"}, KeyboardPatterns: []string{"CANARYKBD"},
		DADomains: "CANARY.CORP", Cracked: true, PasswordLength: 9,
		SimilarPeers: []model.SimilarPeer{{Username: "CANARY_PEER", Domain: "CANARY.CORP", Score: 0.9}},
	}}
	var buf bytes.Buffer
	if err := SanitizedJSON(&buf, accts, model.Summary{}, now, "v9.9.9"); err != nil {
		t.Fatalf("SanitizedJSON: %v", err)
	}
	for _, canary := range []string{"CANARY_USER", "CANARY.CORP", "CANARY_PW", "CANARYHASH", "CANARYWORD", "CANARYKBD", "CANARY_PEER"} {
		if bytes.Contains(buf.Bytes(), []byte(canary)) {
			t.Errorf("LEAK: output contains %q", canary)
		}
	}
}

func TestSanitizedTransforms(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	pwdLastSet := now.AddDate(0, 0, -100).Unix() // 100 days old
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", DADomains: "CORP.LOCAL", PwdLastSet: pwdLastSet}, // has DA path
		{Username: "b", Domain: "CORP", DADomains: "None"},                               // no DA path, no pwdlastset
	}, model.Summary{}, now, "v1")

	if got := rep.Accounts[0].HasDAPath; !got {
		t.Errorf("acct a HasDAPath = false, want true (DADomains set)")
	}
	if got := rep.Accounts[1].HasDAPath; got {
		t.Errorf("acct b HasDAPath = true, want false (DADomains None)")
	}
	if got := rep.Accounts[0].PasswordAgeDays; got != 100 {
		t.Errorf("acct a PasswordAgeDays = %d, want 100", got)
	}
	if got := rep.Accounts[1].PasswordAgeDays; got != 0 {
		t.Errorf("acct b PasswordAgeDays = %d, want 0 (no pwdlastset)", got)
	}
	if rep.Accounts[0].ID != "a1" || rep.Accounts[1].ID != "a2" {
		t.Errorf("ids = %q,%q, want a1,a2", rep.Accounts[0].ID, rep.Accounts[1].ID)
	}
	if rep.Accounts[0].DomainLabel != "D1" || rep.Accounts[1].DomainLabel != "D1" {
		t.Errorf("same domain must share a label, got %q,%q", rep.Accounts[0].DomainLabel, rep.Accounts[1].DomainLabel)
	}
}

func TestSanitizedReuseGroupsAndPeers(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", NTHash: "SHARED", SimilarPeers: []model.SimilarPeer{{Username: "c", Domain: "CORP", Score: 0.8}}},
		{Username: "b", Domain: "CORP", NTHash: "SHARED"},
		{Username: "c", Domain: "CORP", NTHash: "UNIQUE"},
	}, model.Summary{}, now, "v1")

	if rep.Accounts[0].ReuseGroup == "" || rep.Accounts[0].ReuseGroup != rep.Accounts[1].ReuseGroup {
		t.Errorf("a,b reuse_group = %q,%q, want equal+non-empty", rep.Accounts[0].ReuseGroup, rep.Accounts[1].ReuseGroup)
	}
	if rep.Accounts[2].ReuseGroup != "" {
		t.Errorf("c reuse_group = %q, want \"\" (no sharing)", rep.Accounts[2].ReuseGroup)
	}
	if len(rep.Accounts[0].SimilarPeers) != 1 || rep.Accounts[0].SimilarPeers[0].ID != "a3" {
		t.Errorf("a similar_peers = %+v, want one peer id a3", rep.Accounts[0].SimilarPeers)
	}
}

func TestSanitizedSummaryAndDomainsCarried(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	sum := model.Summary{TotalAccounts: 2, Cracked: 1}
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", RiskLevel: "High"},
		{Username: "b", Domain: "EU", RiskLevel: "Low"},
	}, sum, now, "v2.24.0")
	if rep.Summary.TotalAccounts != 2 || rep.ToolVersion != "v2.24.0" || rep.SchemaVersion != 1 {
		t.Errorf("header/summary not carried: %+v", rep)
	}
	if len(rep.Domains) != 2 {
		t.Fatalf("domains = %d, want 2 (CORP, EU as D1/D2)", len(rep.Domains))
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(rep); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

// forbiddenKeys are JSON object keys that must NEVER appear anywhere in the
// sanitized output -- a structural guard so an accidentally-named future field is
// caught even if its value happens not to collide with a canary value.
func walkKeys(t *testing.T, v any, forbidden map[string]bool) {
	t.Helper()
	switch m := v.(type) {
	case map[string]any:
		for k, val := range m {
			if forbidden[k] {
				t.Errorf("forbidden key present in sanitized output: %q", k)
			}
			walkKeys(t, val, forbidden)
		}
	case []any:
		for _, e := range m {
			walkKeys(t, e, forbidden)
		}
	}
}

func TestSanitizedCarriesMassReuse(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", Cracked: true, EscalatedByMassReuse: true},
		{Username: "b", Domain: "CORP", Cracked: true},
	}, model.Summary{}, now, "v1")
	if !rep.Accounts[0].EscalatedByMassReuse {
		t.Errorf("acct a EscalatedByMassReuse = false, want true (carried)")
	}
	if rep.Accounts[1].EscalatedByMassReuse {
		t.Errorf("acct b EscalatedByMassReuse = true, want false")
	}
}

// TestSanitizedSummaryHasReachabilityFields verifies that the new executive
// aggregate fields (reachability, verdict, dormant_privileged, etc.) are
// present in the serialized sanitized report, and that the existing canary /
// forbidden-key guards still pass (no per-account secret leakage).
func TestSanitizedSummaryHasReachabilityFields(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)

	// One enabled, cracked account with a DA pathway → PostureScore returns
	// Verdict="Critical", Reachability="High" (L=0.55 → band High).
	// ControlsTier0=false so it's High not Critical-Tier0, keeping the test
	// independent of the exact gating order.
	accts := []model.Account{{
		Username:  "svc_da",
		Domain:    "CORP.LOCAL",
		DADomains: "CORP.LOCAL",
		Cracked:   true,
		Enabled:   true,
		RiskLevel: "Critical",
	}}
	sum := model.Summary{
		TotalAccounts:     1,
		Cracked:           1,
		DormantPrivileged: 0,
		Posture:           model.PostureScore(accts),
	}
	// Also verify dormant_privileged path: add a disabled cracked DA account
	// and rebuild the summary so DormantPrivileged == 1.
	dormantAcct := model.Account{
		Username:  "old_da",
		Domain:    "CORP.LOCAL",
		DADomains: "CORP.LOCAL",
		Cracked:   true,
		Enabled:   false, // disabled -> dormant
		RiskLevel: "Critical",
	}
	allAccts := append(accts, dormantAcct)
	sum.Posture = model.PostureScore(allAccts)
	sum.DormantPrivileged = 1 // simulated; normally set by store

	rep := Sanitize(allAccts, sum, now, "v-test")

	// ---- structural field checks (via the typed struct) ----
	if rep.Summary.Posture.Verdict == "" {
		t.Errorf("Summary.Posture.Verdict is empty — new fields not flowing through")
	}
	if rep.Summary.Posture.Reachability == "" {
		t.Errorf("Summary.Posture.Reachability is empty")
	}
	if rep.Summary.Posture.ReachabilityPct == "" {
		t.Errorf("Summary.Posture.ReachabilityPct is empty")
	}
	if rep.Summary.Posture.Overall < 0 {
		t.Errorf("Summary.Posture.Overall < 0")
	}
	if rep.Summary.DormantPrivileged != 1 {
		t.Errorf("Summary.DormantPrivileged = %d, want 1", rep.Summary.DormantPrivileged)
	}

	// The reachable DA account (cracked+enabled+DADomains) must drive verdict to
	// Critical (because the DA path is High → L≈0.55, but critN also fires for
	// the Critical risk level; overall the reachable DA → High band → "High Risk"
	// OR if t0Reachable>=1 → Critical).  Accept either Critical or High Risk —
	// the key property is that it is NOT "Sound" / "No Data".
	if rep.Summary.Posture.Verdict == "Sound" || rep.Summary.Posture.Verdict == "No Data" {
		t.Errorf("Summary.Posture.Verdict = %q — expected a gated result (High Risk or Critical), not Sound/No Data",
			rep.Summary.Posture.Verdict)
	}

	// ---- JSON key presence check ----
	var buf bytes.Buffer
	if err := SanitizedJSON(&buf, allAccts, sum, now, "v-test"); err != nil {
		t.Fatalf("SanitizedJSON: %v", err)
	}
	for _, key := range []string{
		`"reachability"`, `"reachability_score"`, `"reachability_pct"`,
		`"overall"`, `"verdict"`, `"verdict_reason"`, `"dormant_privileged"`,
	} {
		if !bytes.Contains(buf.Bytes(), []byte(key)) {
			t.Errorf("sanitized JSON missing key %s", key)
		}
	}

	// ---- canary / no-leak check ----
	// The input accounts carry usernames; they must NOT appear in the sanitized JSON.
	for _, secret := range []string{"svc_da", "old_da", "CORP.LOCAL"} {
		if bytes.Contains(buf.Bytes(), []byte(secret)) {
			t.Errorf("LEAK: sanitized output contains %q", secret)
		}
	}
}

func TestSanitizedNoForbiddenKeys(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{{
		Username: "u", Domain: "CORP", Password: "p", NTHash: "ABC",
		BannedWords: []string{"x"}, KeyboardPatterns: []string{"y"}, DADomains: "CORP.LOCAL",
		Cracked: true, ScoreBreakdown: &model.ScoreBreakdown{ExposureScore: 1},
		SimilarPeers: []model.SimilarPeer{{Username: "u", Domain: "CORP", Score: 0.5}},
	}}
	var buf bytes.Buffer
	if err := SanitizedJSON(&buf, accts, model.Summary{}, now, "v1"); err != nil {
		t.Fatalf("SanitizedJSON: %v", err)
	}
	var tree any
	if err := json.Unmarshal(buf.Bytes(), &tree); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	forbidden := map[string]bool{
		"username": true, "domain": true, "nt_hash": true, "password": true,
		"da_domains": true, "banned_words": true, "keyboard_patterns": true, "pwd_last_set": true,
	}
	walkKeys(t, tree, forbidden)
}
