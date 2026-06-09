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
	// CSV header has no (cleartext) password column
	header := strings.TrimSpace(strings.SplitN(csvb.String(), "\n", 2)[0])
	for _, col := range strings.Split(header, ",") {
		if col == "password" {
			t.Fatal("CSV header contains a password column")
		}
	}
}
