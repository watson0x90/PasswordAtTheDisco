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
