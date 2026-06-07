package hibp

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestNTLMHash(t *testing.T) {
	// Well-known NTLM vectors.
	cases := map[string]string{
		"Password123!": "2B576ACBE6BCFDA7294D6BD18041B8FE",
		"password":     "8846F7EAEE8FB117AD06BDD830B7586C",
		"":             "31D6CFE0D16AE931B73C59D7E0C089C0",
	}
	for pw, want := range cases {
		if got := NTLMHash(pw); got != want {
			t.Errorf("NTLMHash(%q) = %s, want %s", pw, got, want)
		}
	}
}

func TestCategorizeRisk(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "None"}, {1, "Low"}, {9, "Low"}, {10, "Medium"}, {99, "Medium"},
		{100, "High"}, {999, "High"}, {1000, "Very High"}, {9999, "Very High"},
		{10000, "Extreme"}, {500000, "Extreme"},
	}
	for _, c := range cases {
		if got := CategorizeRisk(c.n); got != c.want {
			t.Errorf("CategorizeRisk(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestFactor(t *testing.T) {
	cases := []struct {
		n    int
		want float64
	}{
		{0, 1.0}, {1, 1.1}, {99, 1.1}, {100, 1.2}, {999, 1.2},
		{1000, 1.3}, {9999, 1.3}, {10000, 1.4}, {99999, 1.4}, {100000, 1.5},
	}
	for _, c := range cases {
		if got := Factor(c.n); got != c.want {
			t.Errorf("Factor(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}

// buildTestDB writes a synthetic sorted hash file + prefix index (mirroring the
// Python build_index byte-offset scheme) and returns the hash-file path.
func buildTestDB(t *testing.T, prefixLen int, rows [][2]string) string {
	t.Helper()
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "ntlm.txt")

	var data bytes.Buffer
	firstOffset := map[string]int64{}
	var prefixes []string
	var offset int64
	for _, r := range rows {
		p := r[0][:prefixLen]
		if _, ok := firstOffset[p]; !ok {
			firstOffset[p] = offset
			prefixes = append(prefixes, p)
		}
		line := r[0] + ":" + r[1] + "\n"
		data.WriteString(line)
		offset += int64(len(line))
	}
	if err := os.WriteFile(hashPath, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	sort.Strings(prefixes)
	var idx bytes.Buffer
	for _, p := range prefixes {
		fmt.Fprintf(&idx, "%s:%d\n", p, firstOffset[p])
	}
	if err := os.WriteFile(hashPath+fmt.Sprintf(".index%d", prefixLen), idx.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return hashPath
}

func TestSearcherLookup(t *testing.T) {
	hashPath := buildTestDB(t, 5, [][2]string{
		{"0000000000000000000000000000000A", "5"},
		{"0000000000000000000000000000000B", "10"},
		{"00001000000000000000000000000000", "3"},
		{"FFFFF000000000000000000000000000", "99999"},
	})
	s, err := Open(hashPath, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cases := []struct {
		hash  string
		found bool
		count int
	}{
		{"0000000000000000000000000000000A", true, 5},
		{"0000000000000000000000000000000B", true, 10},
		{"00001000000000000000000000000000", true, 3},
		{"FFFFF000000000000000000000000000", true, 99999},
		{"0000000000000000000000000000000a", true, 5},  // lowercase normalized
		{"0000000000000000000000000000000C", false, 0}, // prefix exists, hash absent (scan to block end)
		{"00000000000000000000000000000005", false, 0}, // hash < first in block (early > break)
		{"00002000000000000000000000000000", false, 0}, // prefix not indexed
		{"abcd", false, 0}, // invalid length
		{"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", false, 0}, // 32 chars, prefix not indexed
	}
	for _, c := range cases {
		found, count, err := s.LookupHash(c.hash)
		if err != nil {
			t.Fatalf("LookupHash(%s): %v", c.hash, err)
		}
		if found != c.found || count != c.count {
			t.Errorf("LookupHash(%s) = (%v, %d), want (%v, %d)", c.hash, found, count, c.found, c.count)
		}
	}
}

// TestSearcherRealFile exercises the actual 74GB dump when present (local dev);
// it skips in environments without the index (e.g. CI).
func TestSearcherRealFile(t *testing.T) {
	const real = "../../PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt"
	if _, err := os.Stat(real + ".index5"); err != nil {
		t.Skip("real HIBP index not present; skipping")
	}
	s, err := Open(real, DefaultPrefixLen)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// First line of the dump: 000000018C025E9A2B8275701A958ABC:4
	if found, count, err := s.LookupHash("000000018C025E9A2B8275701A958ABC"); err != nil || !found || count != 4 {
		t.Fatalf("known-hash lookup = (%v, %d, %v), want (true, 4, nil)", found, count, err)
	}
	// "password" is heavily breached.
	if found, count, _ := s.LookupPassword("password"); !found || count <= 0 {
		t.Fatalf(`LookupPassword("password") = (%v, %d), want found with count > 0`, found, count)
	}
}
