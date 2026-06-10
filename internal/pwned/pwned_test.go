package pwned

import (
	"strings"
	"testing"
)

func TestTail(t *testing.T) {
	if got := tail("short", 100); got != "short" {
		t.Fatalf("tail kept-short = %q", got)
	}
	got := tail(strings.Repeat("x", 50), 10)
	if len(got) >= 50 || !strings.HasSuffix(got, strings.Repeat("x", 10)) {
		t.Fatalf("tail truncate = %q", got)
	}
}

func TestFindProjectMissing(t *testing.T) {
	if _, err := findProject(t.TempDir()); err == nil {
		t.Fatal("expected an error when the downloader project is absent")
	}
}
