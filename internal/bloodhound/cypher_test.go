package bloodhound

import "testing"

func TestTier0NameList(t *testing.T) {
	got := tier0NameList()
	for _, name := range tier0Names {
		if !contains(got, "'"+name+"'") {
			t.Errorf("tier0NameList()=%q missing %q", got, name)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
