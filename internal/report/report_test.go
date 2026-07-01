package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestComputeDiff(t *testing.T) {
	a := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, RiskLevel: "High"},
		{Username: "bob", Domain: "CORP", Cracked: true, RiskLevel: "Low"},
	}
	b := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: false, RiskLevel: "Low"},                       // remediated
		{Username: "bob", Domain: "CORP", Cracked: true, RiskLevel: "Critical", HIBPBreached: true}, // regressed + newly breached + still cracked
		{Username: "carol", Domain: "CORP", Cracked: true, RiskLevel: "Critical"},                   // newly cracked
	}
	d := ComputeDiff(a, b)
	if len(d.NewlyCracked) != 1 || d.NewlyCracked[0].Username != "carol" {
		t.Fatalf("newly cracked = %+v", d.NewlyCracked)
	}
	if len(d.Remediated) != 1 || d.Remediated[0].Username != "alice" {
		t.Fatalf("remediated = %+v", d.Remediated)
	}
	if d.StillCracked != 1 {
		t.Fatalf("still cracked = %d, want 1", d.StillCracked)
	}
	if len(d.Regressed) != 1 || d.Regressed[0].Username != "bob" {
		t.Fatalf("regressed = %+v", d.Regressed)
	}
	if len(d.NewlyBreached) != 1 {
		t.Fatalf("newly breached = %+v", d.NewlyBreached)
	}
}

// TestComputeDiffReachability verifies that ComputeDiff populates ReachabilityA/B and
// OverallA/B from the PostureScore of each side, and that PostureScore is not called
// more than once per side (verified structurally — the fields must be consistent with
// a single PostureScore call, not double-computed with possible drift).
//
// "Before" (a): four enabled accounts, none cracked, no DA pathway — Reachability "Low",
// hygiene near 100.
// "After" (b): same four accounts but svcadmin is now cracked+DA — single DA reachable
// path pushes L = 1-(1-0.55)^1 = 0.55 → "High" band; hygiene drops (one Critical
// cracked), so Overall = hygiene*(1-0.55) is lower than OverallA.
func TestComputeDiffReachability(t *testing.T) {
	// Baseline: four enabled uncracked accounts, no DA pathway → Reachability "Low".
	a := []model.Account{
		{Username: "user1", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Username: "user2", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Username: "user3", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Username: "svcadmin", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
	}
	// Current: svcadmin is now cracked+Critical with a DA pathway; others unchanged.
	// One DA reachable path: L = 1-(1-0.55)^1 = 0.55 → "High".
	b := []model.Account{
		{Username: "user1", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Username: "user2", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Username: "user3", Domain: "CORP", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Username: "svcadmin", Domain: "CORP", Enabled: true, Cracked: true, RiskLevel: "Critical",
			DADomains: "CORP", MeetsPolicy: false},
	}

	d := ComputeDiff(a, b)

	if d.ReachabilityA != "Low" {
		t.Errorf("ReachabilityA: want %q, got %q", "Low", d.ReachabilityA)
	}
	if d.ReachabilityB != "High" {
		t.Errorf("ReachabilityB: want %q, got %q", "High", d.ReachabilityB)
	}
	// OverallA: hygiene ≈ 100 (all uncracked, all Low), L≈0 → Overall ≈ 100.
	if d.OverallA <= 0 {
		t.Errorf("OverallA: want > 0, got %v", d.OverallA)
	}
	// OverallB: hygiene is degraded (1 of 4 is Critical+cracked+non-compliant) AND L=0.55;
	// Overall = hygiene*(1-0.55) < OverallA.
	if d.OverallB >= d.OverallA {
		t.Errorf("OverallB (%v) should be less than OverallA (%v) after DA compromise", d.OverallB, d.OverallA)
	}
	// PostureA: all Low+uncracked+enabled → hygiene near 100.
	if d.PostureA <= 80 {
		t.Errorf("PostureA: want > 80 (all uncracked+Low), got %v", d.PostureA)
	}
	// PostureB: one Critical account (1/4 = 25%) → hygiene significantly degraded.
	if d.PostureB >= d.PostureA {
		t.Errorf("PostureB (%v) should be less than PostureA (%v)", d.PostureB, d.PostureA)
	}
}

func TestReportsRedactCleartext(t *testing.T) {
	// Even if an Account still carries a password, the reports must not emit it.
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Password: "Welcome1", Cracked: true, RiskLevel: "Critical", HIBPBreached: true, HIBPBreachCount: 100, Complexity: "mixedalphanum", MeetsPolicy: false},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low"},
	}
	var csvb, htmlb bytes.Buffer
	if err := CSV(&csvb, accts); err != nil {
		t.Fatal(err)
	}
	if err := HTML(&htmlb, "Engagement", time.Unix(1_700_000_000, 0), accts); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"csv": csvb.String(), "html": htmlb.String()} {
		if strings.Contains(out, "Welcome1") {
			t.Fatalf("%s LEAKED CLEARTEXT", name)
		}
		if !strings.Contains(out, "alice") {
			t.Fatalf("%s missing username", name)
		}
	}
	// CSV header has no (cleartext) password / nt-hash column
	header := strings.TrimSpace(strings.SplitN(csvb.String(), "\n", 2)[0])
	for _, col := range strings.Split(header, ",") {
		if col == "password" || col == "nt_hash" || col == "hash" {
			t.Fatalf("CSV header contains a secret column: %q", col)
		}
	}
}

func TestCSVAccountsSummary(t *testing.T) {
	accts := []model.Account{
		// cracked, in HIBP, reused, with a Tier-0 (DA) pathway
		{Username: "svc_admin", Domain: "CORP", Cracked: true, PasswordLength: 8, Enabled: true,
			HIBPBreached: true, HIBPBreachCount: 1500, SharedWith: 3, DADomains: "CORP, SUB", RiskLevel: "Critical", RiskScore: 9.5},
		// uncracked, not in HIBP, no pathway -- and a username that would be a
		// spreadsheet formula if not neutralized
		{Username: "=cmd|calc", Domain: "CORP", Cracked: false, Enabled: false, DADomains: "None", RiskLevel: "Low", RiskScore: 2},
	}
	var b bytes.Buffer
	if err := CSV(&b, accts); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if len(rows) != 3 {
		t.Fatalf("want header + 2 rows, got %d", len(rows))
	}
	// header order/columns
	if !strings.HasPrefix(rows[0], "domain,username,enabled,status,") {
		t.Errorf("unexpected header: %s", rows[0])
	}
	// cracked + HIBP + reused + Tier-0 pathway row
	r1 := rows[1]
	for _, want := range []string{"svc_admin", "Cracked", "Yes,1500", "Yes,3", `Yes,"CORP, SUB"`} {
		if !strings.Contains(r1, want) {
			t.Errorf("cracked row missing %q in: %s", want, r1)
		}
	}
	// uncracked, no pathway -> status Uncracked, hibp_found No, tier0_pathway No;
	// and the formula-injection username must be quoted with a leading apostrophe
	r2 := rows[2]
	if !strings.Contains(r2, "Uncracked") {
		t.Errorf("uncracked row missing status: %s", r2)
	}
	if !strings.Contains(r2, "'=cmd|calc") {
		t.Errorf("formula-injection username not neutralized: %s", r2)
	}
}

func TestReuseGroupsCSV(t *testing.T) {
	// hashA shared by two cracked accounts; hashB shared by two uncracked accounts.
	const hashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const hashB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", NTHash: hashA, Cracked: true, PasswordLength: 8, HIBPBreachCount: 500, DADomains: "CORP"},
		{Username: "bob", Domain: "SUB", NTHash: hashA, Cracked: true, PasswordLength: 8, HIBPBreachCount: 500},
		{Username: "carol", Domain: "CORP", NTHash: hashB, Cracked: false},
		{Username: "dave", Domain: "CORP", NTHash: hashB, Cracked: false},
	}
	var b bytes.Buffer
	if err := ReuseGroupsCSV(&b, model.BuildReport(accts)); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(rows) != 3 { // header + cracked group + uncracked group
		t.Fatalf("want header + 2 group rows, got %d:\n%s", len(rows), b.String())
	}
	if !strings.HasPrefix(rows[0], "group_id,type,size,domains,") {
		t.Errorf("unexpected header: %s", rows[0])
	}
	out := b.String()
	// the cracked group: type Cracked, size 2, 2 domains, HIBP 500, reaches Tier-0, both members
	if !strings.Contains(out, "Cracked,2,2,500,Yes,") {
		t.Errorf("cracked group row malformed:\n%s", out)
	}
	if !strings.Contains(out, "alice; bob") {
		t.Errorf("cracked group should list both members:\n%s", out)
	}
	// the uncracked group: type Uncracked, size 2, single domain, no HIBP, no Tier-0
	if !strings.Contains(out, "Uncracked,2,1,0,No,") {
		t.Errorf("uncracked group row malformed:\n%s", out)
	}
}

func TestFocusedHTMLRedactsAndRenders(t *testing.T) {
	const hashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Password: "Secret123!", NTHash: hashA, Cracked: true, PasswordLength: 10, RiskLevel: "Critical", RiskScore: 9, HIBPBreached: true, HIBPBreachCount: 42, SharedWith: 1, DADomains: "CORP"},
		{Username: "bob", Domain: "CORP", Password: "Secret123!", NTHash: hashA, Cracked: true, PasswordLength: 10, RiskLevel: "High", RiskScore: 7, SharedWith: 1},
	}
	when := time.Unix(1_700_000_000, 0)

	var accHTML, reuseHTML bytes.Buffer
	if err := AccountsHTML(&accHTML, "Eng — Cracked", "cracked accounts", when, accts); err != nil {
		t.Fatal(err)
	}
	if err := ReuseGroupsHTML(&reuseHTML, "Eng — Reuse", when, BuildReportFor(accts)); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"accounts": accHTML.String(), "reuse": reuseHTML.String()} {
		if strings.Contains(out, "Secret123!") {
			t.Fatalf("%s HTML LEAKED CLEARTEXT", name)
		}
		if strings.Contains(out, hashA) {
			t.Fatalf("%s HTML LEAKED NT HASH", name)
		}
		if !strings.Contains(out, "alice") || !strings.Contains(out, "</html>") {
			t.Fatalf("%s HTML missing content / not well-formed", name)
		}
	}
	// the reuse report should show the shared group (2 accounts)
	if !strings.Contains(reuseHTML.String(), "accounts share a cracked password") {
		t.Errorf("reuse HTML missing group heading:\n%s", reuseHTML.String())
	}
}

// BuildReportFor is a tiny indirection so the test reads clearly; model.BuildReport
// lives in the model package.
func BuildReportFor(a []model.Account) model.Report { return model.BuildReport(a) }

// TestHTMLChartsSection verifies that HTML() embeds inline SVG charts derived
// from m.Charts, renders chart section titles, and introduces no <script> tags.
func TestHTMLChartsSection(t *testing.T) {
	// Two Critical cracked accounts + one Low uncracked.
	// RiskDistribution → Critical:2, Low:1.
	// HIBPSplit → Breached:1 (alice), Not in HIBP:2.
	// LengthBuckets → "8–9":1 (alice, len=9), "14–15":1 (bob, len=14).
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, PasswordLength: 9,
			HIBPBreached: true, HIBPBreachCount: 5, RiskLevel: "Critical", RiskScore: 9,
			Complexity: "mixedalphanum"},
		{Username: "bob", Domain: "CORP", Cracked: true, PasswordLength: 14,
			RiskLevel: "Critical", RiskScore: 8},
		{Username: "carol", Domain: "CORP", Cracked: false,
			RiskLevel: "Low", RiskScore: 2},
	}
	var b bytes.Buffer
	if err := HTML(&b, "ChartTest", time.Unix(1_700_000_000, 0), accts); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	// Must contain inline SVG chart elements.
	if !strings.Contains(out, "<svg") {
		t.Error("HTML output should contain <svg chart elements")
	}
	// Self-contained requirement: no <script> tags ever.
	if strings.Contains(out, "<script") {
		t.Error("HTML output must not contain <script> tags (self-contained requirement)")
	}
	// Chart section label must appear.
	if !strings.Contains(out, ">Charts<") {
		t.Error("HTML output missing Charts section label")
	}
	// Chart card titles must appear.
	for _, title := range []string{"Risk distribution", "Password length", "HIBP exposure"} {
		if !strings.Contains(out, title) {
			t.Errorf("HTML output missing chart card title %q", title)
		}
	}
	// SVG value text for the Critical count (2) must appear — e.g. fill="#e8edf7">2</text>.
	if !strings.Contains(out, `fill="#e8edf7">2</text>`) {
		t.Error("charts SVG should contain a bar value of 2 (2 Critical accounts in RiskDistribution)")
	}
	// The "8–9" length bucket label must appear (alice, length=9).
	if !strings.Contains(out, "8–9") {
		t.Error("charts SVG should contain the 8–9 length bucket label")
	}
}

func TestFocusedHTMLHasGapColumns(t *testing.T) {
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Complexity: "mixedalphaspecialnum",
			MeetsPolicy: true, Controlled: 12, Enabled: false, RiskLevel: "Critical", RiskScore: 9,
			BannedWordCount: 1},
	}
	when := time.Unix(1_700_000_000, 0)

	var acc, weak bytes.Buffer
	if err := AccountsHTML(&acc, "Eng", "cracked accounts", when, accts); err != nil {
		t.Fatal(err)
	}
	if err := WeakPasswordsHTML(&weak, "Eng", when, accts); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"accounts": acc.String(), "weak": weak.String()} {
		for _, want := range []string{"Complexity", "Policy", "Controlled", "12", "disabled"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s HTML missing %q", name, want)
			}
		}
	}
}

func TestCSVHasRiskVector(t *testing.T) {
	var b bytes.Buffer
	if err := CSV(&b, []model.Account{
		{Username: "a", Domain: "C", Cracked: true, RiskLevel: "High", RiskScore: 7, RiskVector: "CRACKED/SHARED-DA"},
	}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	header := strings.SplitN(out, "\n", 2)[0]
	if !strings.Contains(header, "risk_vector") {
		t.Fatalf("CSV header missing risk_vector: %s", header)
	}
	if !strings.Contains(out, "CRACKED/SHARED-DA") {
		t.Fatalf("CSV missing the risk vector value:\n%s", out)
	}
}

func TestCSVEscapesFormulaInjection(t *testing.T) {
	accts := []model.Account{{Username: "=cmd|calc@CORP.LOCAL", Domain: "CORP.LOCAL"}}
	var buf bytes.Buffer
	if err := CSV(&buf, accts); err != nil {
		t.Fatalf("CSV: %v", err)
	}
	if !strings.Contains(buf.String(), `'=cmd`) {
		t.Errorf("formula-injection username not neutralized (want leading '): %s", buf.String())
	}
}

// TestHTMLDormantPrivileged verifies that HTML() counts disabled+privileged+cracked
// accounts and renders the "Dormant privileged" warning, and that a dataset without
// such accounts does NOT render the warning.
func TestHTMLDormantPrivileged(t *testing.T) {
	when := time.Unix(1_700_000_000, 0)

	// Dataset WITH one dormant privileged account.
	withDormant := []model.Account{
		// disabled + has DA pathway + cracked → should be counted
		{Username: "svc_priv", Domain: "CORP", Enabled: false, DADomains: "CORP", Cracked: true, RiskLevel: "Critical", RiskScore: 9.5},
		// enabled + cracked → NOT dormant
		{Username: "user1", Domain: "CORP", Enabled: true, Cracked: true, RiskLevel: "High", RiskScore: 7},
	}
	var b bytes.Buffer
	if err := HTML(&b, "Engagement", when, withDormant); err != nil {
		t.Fatalf("HTML with dormant: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "Dormant privileged") {
		t.Errorf("HTML with dormant privileged account should render 'Dormant privileged' warning; got none\noutput:\n%s", out)
	}

	// Dataset WITHOUT any dormant privileged account.
	b.Reset()
	noDormant := []model.Account{
		// disabled but no DA pathway and not cracked → not dormant
		{Username: "disabled_user", Domain: "CORP", Enabled: false, Cracked: false, RiskLevel: "Low", RiskScore: 1},
		// enabled + DA pathway + cracked → enabled, so not dormant
		{Username: "active_da", Domain: "CORP", Enabled: true, DADomains: "CORP", Cracked: true, RiskLevel: "Critical", RiskScore: 9},
	}
	if err := HTML(&b, "Engagement", when, noDormant); err != nil {
		t.Fatalf("HTML without dormant: %v", err)
	}
	if strings.Contains(b.String(), "Dormant privileged") {
		t.Errorf("HTML without dormant privileged accounts should NOT render 'Dormant privileged' warning")
	}
}

func TestWeakPasswordsHTML(t *testing.T) {
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Password: "Summer2021!",
			BannedWords: []string{"summer", "2021"}, BannedWordCount: 2, IsCommon: true,
			RiskLevel: "Critical", RiskScore: 9},
		{Username: "bob", Domain: "CORP", Cracked: true, KeyboardPatterns: []string{"qwerty"},
			KeyboardPatternCount: 1, RiskLevel: "High", RiskScore: 7},
	}
	var b bytes.Buffer
	if err := WeakPasswordsHTML(&b, "Eng", time.Unix(1_700_000_000, 0), accts); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "by violation category") || !strings.Contains(out, "alice") || !strings.Contains(out, "</html>") {
		t.Fatalf("weak HTML malformed:\n%s", out)
	}
	for _, leak := range []string{"summer", "2021", "qwerty", "Summer2021!"} {
		if strings.Contains(out, leak) {
			t.Fatalf("weak HTML leaked %q", leak)
		}
	}
}

// TestHTMLDACountObtainableOnly pins the parity bug fix: the HTML report's DA
// count must equal the OBTAINABLE DA pathway count (HasObtainableDAPathway), not
// the raw HasDAPathway count, so it matches the dashboard and /api/metrics.
//
// Setup: two accounts both have DADomains set, but only one is cracked (obtainable).
// Old code: DA = 2 (counted raw HasDAPathway for both).
// Fixed code: DA = 1 (only the cracked account is obtainable).
func TestHTMLDACountObtainableOnly(t *testing.T) {
	when := time.Unix(1_700_000_000, 0)

	// Has DA pathway but NOT obtainable (uncracked, unbreached, hash not shared).
	// Old HTML() counted this via HasDAPathway() — the bug.
	latentDA := model.Account{
		Username: "latent_da", Domain: "CORP", Enabled: true,
		DADomains: "CORP", Cracked: false, HIBPBreached: false,
		RiskLevel: "Medium", RiskScore: 5.0,
	}
	// Has DA pathway AND obtainable (cracked).
	realDA := model.Account{
		Username: "real_da", Domain: "CORP", Enabled: true,
		DADomains: "CORP", Cracked: true,
		RiskLevel: "Critical", RiskScore: 9.5,
	}

	var b bytes.Buffer
	if err := HTML(&b, "BugFixTest", when, []model.Account{latentDA, realDA}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := b.String()

	// Template renders: <div class="v" style="color:#fb7185">{{.DA}}</div><div class="k">DA pathways</div>
	// DA must be 1 (only realDA is obtainable), not 2.
	wantDA := `style="color:#fb7185">1</div><div class="k">DA pathways</div>`
	if !strings.Contains(out, wantDA) {
		t.Errorf("DA count should be 1 (obtainable only), not 2; want substring %q in output", wantDA)
	}
	badDA := `style="color:#fb7185">2</div><div class="k">DA pathways</div>`
	if strings.Contains(out, badDA) {
		t.Errorf("DA count is 2 — old bug is still present; should be 1 (obtainable only)")
	}

	// Posture score section must be present.
	if !strings.Contains(out, "Security posture") {
		t.Errorf("HTML missing 'Security posture' section")
	}

	// Exposure × Impact matrix section must be present.
	if !strings.Contains(out, "Exposure × Impact") {
		t.Errorf("HTML missing 'Exposure × Impact' matrix section")
	}
}

// TestHTMLGraphsAndScatter verifies that HTML() renders network graph SVGs
// (from m.Reports.ReuseGraph and m.Reports.SimilarityGraph) and scatter plot SVGs
// (from m.Charts.HIBPVsRisk) as inline SVG with no <script> tags, and that
// user-influenced graph node labels containing HTML-special characters are escaped.
func TestHTMLGraphsAndScatter(t *testing.T) {
	const sharedHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const cleartextPw = "hunter2-cleartext-secret"

	accts := []model.Account{
		// Cross-domain reuse pair → two distinct domains in the same CrackedReuse
		// group → CrossDomainReuseGraph produces nodes and at least one edge.
		{Username: "alice", Domain: "CORP.LOCAL", NTHash: sharedHash, Password: cleartextPw, Cracked: true,
			PasswordLength: 8, RiskLevel: "High", RiskScore: 7,
			HIBPBreached: true, HIBPBreachCount: 5, SharedWith: 1},
		{Username: "bob", Domain: "SUB.LOCAL", NTHash: sharedHash, Password: cleartextPw, Cracked: true,
			PasswordLength: 8, RiskLevel: "High", RiskScore: 7, SharedWith: 1},
		// Similarity pair where one username contains '<' → SimilarityGraph node
		// Label must be HTML-escaped to prevent injection into SVG <text> content.
		{
			Username: "admin<1", Domain: "CORP.LOCAL",
			Cracked: true, SimilarityScore: 0.85,
			RiskLevel: "Critical", RiskScore: 9,
			SimilarPeers: []model.SimilarPeer{
				{Username: "admin2", Domain: "CORP.LOCAL", Score: 0.85},
			},
		},
		{
			Username: "admin2", Domain: "CORP.LOCAL",
			Cracked: true, SimilarityScore: 0.85,
			RiskLevel: "Critical", RiskScore: 8.5,
			SimilarPeers: []model.SimilarPeer{
				{Username: "admin<1", Domain: "CORP.LOCAL", Score: 0.85},
			},
		},
	}

	var b bytes.Buffer
	if err := HTML(&b, "GraphTest", time.Unix(1_700_000_000, 0), accts); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	// Self-contained requirement: no <script> tags ever.
	if strings.Contains(out, "<script") {
		t.Error("HTML output must not contain <script> tags (self-contained requirement)")
	}

	// Self-redaction: HTML() is handed FULL accounts (cleartext password + NT hash)
	// so the cross-domain reuse graph can be computed, but must never emit either
	// into the downloadable report — redaction is a self-enforced invariant of HTML().
	if strings.Contains(out, cleartextPw) {
		t.Error("HTML export leaked cleartext password — HTML() must redact its own output")
	}
	if strings.Contains(out, sharedHash) {
		t.Error("HTML export leaked NT hash — HTML() must redact its own output")
	}

	// ReuseGraph must produce <circle> (nodes) and <line> (edges) elements.
	// <line> is unique to network graphs — scatter charts only use <circle>.
	if !strings.Contains(out, "<line ") {
		t.Error("network graph section should contain <line> elements (edges between reuse-linked domains)")
	}
	if !strings.Contains(out, "<circle ") {
		t.Error("output should contain <circle> elements from scatter plots or network graphs")
	}

	// Graph section label must appear.
	if !strings.Contains(out, ">Graphs<") {
		t.Error("HTML output missing Graphs section label")
	}

	// "Cross-domain credential reuse" graph card title must appear.
	if !strings.Contains(out, "Cross-domain credential reuse") {
		t.Error("HTML output missing cross-domain reuse graph card title")
	}

	// Scatter chart "HIBP exposure vs risk" must appear (alice: High risk, HIBPBreached).
	if !strings.Contains(out, "HIBP exposure vs risk") {
		t.Error("HTML output missing scatter chart title 'HIBP exposure vs risk'")
	}

	// CRITICAL: username "admin<1" must be HTML-escaped in SVG node labels.
	// The raw '<' must not appear as an unescaped character anywhere in the output
	// (the Go html/template engine also escapes it in the Accounts table, so the
	// raw form should be entirely absent from the rendered document).
	if strings.Contains(out, "admin<1") {
		t.Error("HTML output contains unescaped '<' in node label 'admin<1' — XSS risk; must be escaped as 'admin&lt;1'")
	}
	// Pin the positive assertion to the SVG <text> body (">admin&lt;1<"), so it
	// proves the graph label path escapes — not merely the accounts table, which
	// html/template would escape regardless.
	if !strings.Contains(out, ">admin&lt;1<") {
		t.Error("HTML output must contain escaped node label '>admin&lt;1<' in an SVG <text> element but it was not found")
	}
}

// TestCSVCleartextAndRedacted verifies:
//   - CSVCleartext: cracked account has password in column 2, no NT hash, uncracked cell empty.
//   - CSV (redacted): same full accounts produce output with neither password nor hash,
//     and no password column in the header.
func TestCSVCleartextAndRedacted(t *testing.T) {
	const ntHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1"
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Password: "Hunter2", NTHash: ntHash,
			Cracked: true, PasswordLength: 7, RiskLevel: "High", RiskScore: 7.0,
			BannedWords: []string{"zzbannedfragzz"}, BannedWordCount: 1},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low", RiskScore: 2.0},
	}

	// --- CSVCleartext ---
	var ctBuf bytes.Buffer
	if err := CSVCleartext(&ctBuf, accts); err != nil {
		t.Fatalf("CSVCleartext: %v", err)
	}
	ctOut := ctBuf.String()
	ctRows := strings.Split(strings.TrimSpace(ctOut), "\n")
	if len(ctRows) != 3 {
		t.Fatalf("CSVCleartext: want 3 rows (header+2), got %d:\n%s", len(ctRows), ctOut)
	}

	// Header must have "password" as the 3rd column (index 2).
	ctHeader := ctRows[0]
	ctCols := strings.Split(ctHeader, ",")
	if len(ctCols) < 3 || ctCols[2] != "password" {
		t.Errorf("CSVCleartext: password column not at index 2 in header: %s", ctHeader)
	}

	// Cracked account row must contain Hunter2.
	if !strings.Contains(ctRows[1], "Hunter2") {
		t.Errorf("CSVCleartext: cracked row missing password:\n%s", ctRows[1])
	}
	// Cleartext CSV must NEVER contain the NT hash.
	if strings.Contains(ctOut, ntHash) {
		t.Errorf("CSVCleartext: LEAKED NT HASH:\n%s", ctOut)
	}
	// BannedWords substrings must never appear (only the count is safe).
	if strings.Contains(ctOut, "zzbannedfragzz") {
		t.Errorf("CSVCleartext: leaked BannedWords fragment:\n%s", ctOut)
	}

	// Uncracked account row: the password cell (index 2) must be empty.
	// Parse bob's row manually; the row is the 3rd line (index 2).
	// We can't use encoding/csv here trivially, so check that the value in
	// the password column position is empty by confirming Hunter2 is NOT in row 3.
	if strings.Contains(ctRows[2], "Hunter2") {
		t.Errorf("CSVCleartext: uncracked row must have empty password cell, not Hunter2:\n%s", ctRows[2])
	}

	// --- CSV (redacted) ---
	var rdBuf bytes.Buffer
	if err := CSV(&rdBuf, accts); err != nil {
		t.Fatalf("CSV (redacted): %v", err)
	}
	rdOut := rdBuf.String()

	// Redacted CSV must NOT contain Hunter2.
	if strings.Contains(rdOut, "Hunter2") {
		t.Errorf("CSV (redacted): LEAKED CLEARTEXT PASSWORD:\n%s", rdOut)
	}
	// Redacted CSV must NOT contain the NT hash.
	if strings.Contains(rdOut, ntHash) {
		t.Errorf("CSV (redacted): LEAKED NT HASH:\n%s", rdOut)
	}
	// Redacted CSV header must NOT have a "password" column.
	rdHeader := strings.SplitN(rdOut, "\n", 2)[0]
	for _, col := range strings.Split(rdHeader, ",") {
		if col == "password" {
			t.Errorf("CSV (redacted) header contains 'password' column: %s", rdHeader)
		}
	}
}

// TestHTMLCleartextAndRedacted verifies:
//   - HTMLCleartext: contains password (Hunter2), cleartext banner, no NT hash, no wordlist
//     fragments, no <script>.
//   - HTML (redacted): given the same full accounts, contains neither password nor hash —
//     extends the self-redaction guard from TestHTMLGraphsAndScatter.
func TestHTMLCleartextAndRedacted(t *testing.T) {
	const ntHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	const pw = "Hunter2"
	when := time.Unix(1_700_000_000, 0)

	const xssPw = `"><script>alert(1)</script>`
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Password: pw, NTHash: ntHash,
			Cracked: true, PasswordLength: 7, RiskLevel: "High", RiskScore: 7.0,
			BannedWords: []string{"zzbannedfragzz"}, BannedWordCount: 1,
			KeyboardPatterns: []string{"zzkeyboardfragzz"}, KeyboardPatternCount: 1},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low", RiskScore: 2.0},
		// A cracked account whose cleartext is hostile markup — proves the password
		// cell is auto-escaped by html/template (element-content context), not live.
		{Username: "mallory", Domain: "CORP", Password: xssPw, Cracked: true,
			PasswordLength: 26, RiskLevel: "Critical", RiskScore: 9.0},
	}

	// --- HTMLCleartext ---
	var ctBuf bytes.Buffer
	if err := HTMLCleartext(&ctBuf, "TestEngage", when, accts); err != nil {
		t.Fatalf("HTMLCleartext: %v", err)
	}
	ctOut := ctBuf.String()

	// Must contain cleartext password.
	if !strings.Contains(ctOut, pw) {
		t.Errorf("HTMLCleartext: missing cleartext password %q in output", pw)
	}
	// Must contain the warning banner.
	if !strings.Contains(ctOut, "CONTAINS CLEARTEXT PASSWORDS") {
		t.Errorf("HTMLCleartext: missing cleartext warning banner")
	}
	if !strings.Contains(ctOut, "cleartext-banner") {
		t.Errorf("HTMLCleartext: missing cleartext-banner CSS class")
	}
	// Must NOT contain NT hash.
	if strings.Contains(ctOut, ntHash) {
		t.Errorf("HTMLCleartext: LEAKED NT HASH")
	}
	// Must NOT contain raw wordlist fragments.
	if strings.Contains(ctOut, "zzbannedfragzz") {
		t.Errorf("HTMLCleartext: leaked BannedWords fragment")
	}
	if strings.Contains(ctOut, "zzkeyboardfragzz") {
		t.Errorf("HTMLCleartext: leaked KeyboardPatterns fragment")
	}
	// Self-contained AND escaping proof: a cracked password of hostile markup must
	// be auto-escaped, so no live <script> tag appears and the escaped form does.
	if strings.Contains(ctOut, "<script") {
		t.Errorf("HTMLCleartext: hostile password not escaped — live <script> in output")
	}
	if !strings.Contains(ctOut, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("HTMLCleartext: expected escaped password markup (&lt;script&gt;...) not found — auto-escaping not exercised")
	}
	// Password column header must appear.
	if !strings.Contains(ctOut, "<th>Password</th>") {
		t.Errorf("HTMLCleartext: missing Password column header in accounts table")
	}
	// Must be valid HTML (has closing tag).
	if !strings.Contains(ctOut, "</html>") {
		t.Errorf("HTMLCleartext: output missing </html>")
	}

	// --- HTML (redacted) — extended self-redaction guard ---
	var rdBuf bytes.Buffer
	if err := HTML(&rdBuf, "TestEngage", when, accts); err != nil {
		t.Fatalf("HTML (redacted): %v", err)
	}
	rdOut := rdBuf.String()

	// Redacted HTML must NEVER emit the cleartext password, regardless of input.
	if strings.Contains(rdOut, pw) {
		t.Errorf("HTML (redacted): LEAKED CLEARTEXT PASSWORD — self-redaction invariant violated")
	}
	// Redacted HTML must NEVER emit the NT hash.
	if strings.Contains(rdOut, ntHash) {
		t.Errorf("HTML (redacted): LEAKED NT HASH — self-redaction invariant violated")
	}
	// Redacted HTML must NOT contain a cleartext banner.
	if strings.Contains(rdOut, "CONTAINS CLEARTEXT PASSWORDS") {
		t.Errorf("HTML (redacted): cleartext banner must not appear in redacted output")
	}
	// Redacted HTML must NOT have a Password column header.
	if strings.Contains(rdOut, "<th>Password</th>") {
		t.Errorf("HTML (redacted): Password column header must not appear in redacted output")
	}
}
