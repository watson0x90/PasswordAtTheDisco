package audit

import (
	"os"
	"path/filepath"
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
