package bloodhound

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTier0NameList(t *testing.T) {
	got := tier0NameList()
	for _, name := range tier0Names {
		if !strings.Contains(got, "'"+name+"'") {
			t.Errorf("tier0NameList()=%q missing %q", got, name)
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
