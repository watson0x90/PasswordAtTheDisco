package bloodhound

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestControlEdgeTypesBroadened(t *testing.T) {
	q := controlEdgeTypes()
	for _, want := range []string{"GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "Owns",
		"ForceChangePassword", "AddMember", "AllExtendedRights", "AddKeyCredentialLink", "AddSelf",
		"WriteSPN", "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword"} {
		if !strings.Contains(q, "'"+want+"'") {
			t.Errorf("controlEdgeTypes() missing %q", want)
		}
	}
	if !strings.Contains(controllableCountQuery(), controlEdgeTypes()) {
		t.Error("FetchControllableCounts query must embed controlEdgeTypes()")
	}
	if !strings.Contains(tier0ControllersQuery(), controlEdgeTypes()) {
		t.Error("tier0ControllersQuery must embed controlEdgeTypes()")
	}
}

func TestTier0NameList(t *testing.T) {
	got := tier0NameList()
	for _, name := range tier0Names {
		if !strings.Contains(got, "'"+name+"'") {
			t.Errorf("tier0NameList()=%q missing %q", got, name)
		}
	}
}

func TestTier0ControllersQuery(t *testing.T) {
	q := tier0ControllersQuery()
	// Guards the per-user/bulk definition agreement against a silent refactor:
	// the built-in Administrators match MUST be exact (not CONTAINS), DCSync via n:Domain,
	// and every tier0Names fragment present.
	for _, want := range []string{
		"STARTS WITH 'ADMINISTRATORS@'", // exact local-part (BHE-CE supported; not CONTAINS, else "Backup Administrators" over-matches)
		"n:Domain",                      // DCSync / domain-object control
	} {
		if !strings.Contains(q, want) {
			t.Errorf("tier0ControllersQuery missing %q\nquery=%s", want, q)
		}
	}
	for _, name := range tier0Names {
		if !strings.Contains(q, "'"+name+"'") {
			t.Errorf("tier0ControllersQuery missing tier0Names fragment %q", name)
		}
	}
}

func TestParseTier0Literals(t *testing.T) {
	lits := []literal{{Value: "svc"}, {Value: "CORP"}, {Value: "alice"}, {Value: "EU.CORP"}}
	got := parseTier0Literals(lits)
	if !got["svc@CORP"] || !got["alice@EU.CORP"] {
		t.Errorf("parseTier0Literals = %v, want svc@CORP and alice@EU.CORP true", got)
	}
	if len(got) != 2 {
		t.Errorf("len=%d, want 2", len(got))
	}
}

func TestParseTier0Rows(t *testing.T) {
	rows := [][]interface{}{{"svc", "CORP"}, {"", "CORP"}}
	got := parseTier0(rows)
	if !got["svc@CORP"] || len(got) != 1 {
		t.Errorf("parseTier0 = %v, want only svc@CORP", got)
	}
}

func TestParseTier0FromResults(t *testing.T) {
	// neo4j-compat tabular shape: results[].data[].row = [sam, domain]
	data := []json.RawMessage{
		json.RawMessage(`{"row":["svc","CORP"]}`),
		json.RawMessage(`{"row":["","CORP"]}`), // blank sam -> skipped
		json.RawMessage(`{"row":["alice"]}`),   // < 2 cols -> skipped
	}
	got := parseTier0FromResults(data)
	if !got["svc@CORP"] || len(got) != 1 {
		t.Errorf("parseTier0FromResults = %v, want only svc@CORP", got)
	}
}
