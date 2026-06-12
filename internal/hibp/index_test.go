package hibp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildIndexRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "ntlm.txt")

	// Construct 32-hex hashes so lengths are guaranteed. Sorted, across three
	// distinct 5-char prefixes (00000 appears twice -> one index entry).
	h1 := "00000" + strings.Repeat("0", 26) + "A"  // prefix 00000
	h2 := "00000" + strings.Repeat("F", 27)        // prefix 00000, h2 > h1
	h3 := "00001" + strings.Repeat("1", 27)        // prefix 00001
	h4 := "ABCDE" + strings.Repeat("0", 25) + "FF" // prefix ABCDE
	for _, h := range []string{h1, h2, h3, h4} {
		if len(h) != 32 {
			t.Fatalf("test hash %q is %d chars, want 32", h, len(h))
		}
	}
	lines := []string{h1 + ":3", h2 + ":1", h3 + ":7", h4 + ":99"}
	if err := os.WriteFile(dump, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := BuildIndex(dump, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("index entries = %d, want 3 (00000, 00001, ABCDE)", n)
	}
	if _, err := os.Stat(IndexPath(dump, 5)); err != nil {
		t.Fatalf("index not written: %v", err)
	}

	s, err := Open(dump, 5)
	if err != nil {
		t.Fatalf("Open after BuildIndex: %v", err)
	}
	defer s.Close()

	cases := []struct {
		h     string
		want  bool
		count int
	}{
		{h1, true, 3},
		{h2, true, 1}, // second line in the 00000 block -> exercises block scanning
		{h3, true, 7},
		{h4, true, 99},
		{"00000" + strings.Repeat("0", 27), false, 0}, // present prefix, absent hash
		{strings.Repeat("F", 32), false, 0},           // absent prefix
	}
	for _, c := range cases {
		found, cnt, err := s.LookupHash(c.h)
		if err != nil {
			t.Fatalf("LookupHash(%s): %v", c.h, err)
		}
		if found != c.want || (found && cnt != c.count) {
			t.Fatalf("LookupHash(%s) = (%v, %d), want (%v, %d)", c.h, found, cnt, c.want, c.count)
		}
	}
}

func TestBuildIndexEmpty(t *testing.T) {
	dir := t.TempDir()
	dump := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(dump, []byte("\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildIndex(dump, 5, nil); err == nil {
		t.Fatal("expected an error building an index from a dump with no hash lines")
	}
}
