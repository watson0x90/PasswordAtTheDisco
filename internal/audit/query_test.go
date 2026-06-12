package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeLog(t *testing.T, events []Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	l := New(f)
	for _, e := range events {
		if err := l.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	return path
}

func TestQueryFilters(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	path := writeLog(t, []Event{
		{Time: base, Actor: "alice", Action: "login", Result: "ok", Source: "1.1.1.1"},
		{Time: base.Add(time.Minute), Actor: "bob", Action: "login", Result: "denied", Source: "2.2.2.2"},
		{Time: base.Add(2 * time.Minute), Actor: "alice", Action: "reveal_secret", Target: `DOMAIN\joe`, Result: "ok"},
	})

	all, err := Query(path, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Action != "reveal_secret" {
		t.Fatalf("all should be newest-first, got %+v", all)
	}
	if logins, _ := Query(path, Filter{Action: "login"}); len(logins) != 2 {
		t.Fatalf("action filter = %d, want 2", len(logins))
	}
	if denied, _ := Query(path, Filter{Result: "denied"}); len(denied) != 1 || denied[0].Actor != "bob" {
		t.Fatalf("result filter = %+v", denied)
	}
	if rev, _ := Query(path, Filter{Text: "joe"}); len(rev) != 1 || rev[0].Action != "reveal_secret" {
		t.Fatalf("text search = %+v", rev)
	}
	if one, _ := Query(path, Filter{Limit: 1}); len(one) != 1 || one[0].Action != "reveal_secret" {
		t.Fatalf("limit=1 newest = %+v", one)
	}
}

func TestQueryMissingFile(t *testing.T) {
	if ev, err := Query(filepath.Join(t.TempDir(), "nope.log"), Filter{}); err != nil || ev != nil {
		t.Fatalf("missing file should yield (nil,nil), got %v %v", ev, err)
	}
}

func TestQueryDateRangeAndCSV(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	path := writeLog(t, []Event{
		{Time: base, Actor: "alice", Action: "login", Result: "ok"},
		{Time: base.Add(48 * time.Hour), Actor: "bob", Action: "login", Result: "ok"},
		{Time: base.Add(96 * time.Hour), Actor: "carol", Action: "login", Result: "ok"},
	})

	// From bound (inclusive): drop the first
	got, _ := Query(path, Filter{From: base.Add(24 * time.Hour)})
	if len(got) != 2 {
		t.Fatalf("From filter = %d, want 2", len(got))
	}
	// To bound (exclusive): keep only the first two
	got, _ = Query(path, Filter{To: base.Add(72 * time.Hour)})
	if len(got) != 2 || got[0].Actor != "bob" {
		t.Fatalf("To filter = %+v", got)
	}
	// window: just the middle one
	got, _ = Query(path, Filter{From: base.Add(24 * time.Hour), To: base.Add(72 * time.Hour)})
	if len(got) != 1 || got[0].Actor != "bob" {
		t.Fatalf("window filter = %+v", got)
	}

	// CSV: header + all matching rows (chronological), filtered
	var buf strings.Builder
	if err := StreamCSV(path, Filter{Action: "login"}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "time,actor,role,action,target,source,result\n") {
		t.Fatalf("csv header missing: %q", out[:40])
	}
	if n := strings.Count(out, "\n"); n != 4 { // header + 3 rows
		t.Fatalf("csv rows = %d lines, want 4", n)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "carol") {
		t.Fatalf("csv missing rows: %s", out)
	}
}

func TestStreamCSVSanitizesFormulas(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	path := writeLog(t, []Event{
		{Time: ts, Actor: "=2+2", Action: "login", Result: "denied", Source: "+1.2.3.4"},
	})
	var buf strings.Builder
	if err := StreamCSV(path, Filter{}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "'=2+2") || strings.Contains(out, ",=2+2,") {
		t.Fatalf("actor formula not neutralized: %s", out)
	}
	if !strings.Contains(out, "'+1.2.3.4") {
		t.Fatalf("source formula not neutralized: %s", out)
	}
}
