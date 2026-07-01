package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustJSON: %v", err)
	}
	return string(b)
}

func TestBundleZip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "A", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, Password: "Hunter2", PasswordLength: 7, RiskLevel: "High", RiskScore: 7},
		{Username: "bob", Domain: "B", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, Password: "Hunter2", PasswordLength: 7, RiskLevel: "High", RiskScore: 7},
	}
	m := metrics.Compute(accts, now)

	// --- sanitized ---
	var buf bytes.Buffer
	if err := BundleZip(&buf, "Eng", "org", false, m, accts, now, "vtest"); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	rj, ok := files["report.json"]
	if !ok {
		t.Fatal("missing report.json")
	}
	var rep bundleReport
	if err := json.Unmarshal(rj, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Cleartext || rep.Scope != "org" {
		t.Errorf("scope/cleartext wrong: scope=%q cleartext=%v", rep.Scope, rep.Cleartext)
	}
	if rep.Name != "Eng" {
		t.Errorf("audit name missing from report.json: got %q, want %q", rep.Name, "Eng")
	}
	// The images manifest and the actual images/ zip entries must be the SAME set.
	for name, path := range rep.Images {
		if _, ok := files[path]; !ok {
			t.Errorf("manifest references missing image %s -> %s", name, path)
		}
	}
	for fname := range files {
		if strings.HasPrefix(fname, "images/") {
			found := false
			for _, path := range rep.Images {
				if path == fname {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("zip has image entry %s absent from the manifest", fname)
			}
		}
	}
	// Sanitized bundle must carry no cleartext/hash. Scan DECOMPRESSED entry
	// contents — raw zip bytes are DEFLATE-compressed and cannot be searched
	// literally (the vacuous raw-bytes scan is replaced here).
	for name, content := range files {
		if bytes.Contains(content, []byte("Hunter2")) {
			t.Errorf("sanitized bundle entry %q LEAKED cleartext password", name)
		}
		if bytes.Contains(content, []byte("AAAA0000")) {
			t.Errorf("sanitized bundle entry %q LEAKED NT hash", name)
		}
	}

	// --- cleartext ---
	var cbuf bytes.Buffer
	if err := BundleZip(&cbuf, "Eng", "org", true, m, accts, now, "vtest"); err != nil {
		t.Fatal(err)
	}
	czr, err := zip.NewReader(bytes.NewReader(cbuf.Bytes()), int64(cbuf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var cj []byte
	imgHasSecret := false
	for _, f := range czr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "report.json" {
			cj = b
		} else if strings.HasPrefix(f.Name, "images/") && strings.Contains(string(b), "Hunter2") {
			imgHasSecret = true
		}
	}
	if !strings.Contains(string(cj), "Hunter2") {
		t.Error("cleartext bundle report.json should contain the password")
	}
	if imgHasSecret {
		t.Error("cleartext MUST NOT appear in any image svg")
	}
	if strings.Contains(string(cj), "AAAA0000") {
		t.Error("NT hash must never appear")
	}
}

func TestWriteBundleIntoPrefix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{{Username: "alice", Domain: "A", Cracked: true, RiskLevel: "High", RiskScore: 7}}
	m := metrics.Compute(accts, now)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeBundleInto(zw, "model_bundle/", "Eng", "org", false, m, accts, now, "v"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	var haveReport bool
	for _, f := range zr.File {
		if f.Name == "model_bundle/report.json" {
			haveReport = true
		}
		if !strings.HasPrefix(f.Name, "model_bundle/") {
			t.Errorf("entry %q not under prefix", f.Name)
		}
	}
	if !haveReport {
		t.Error("missing model_bundle/report.json")
	}
}

func TestBundleAccounts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Password: "Hunter2", NTHash: "AAAA1111AAAA1111AAAA1111AAAA1111",
			BannedWords: []string{"zzbanzz"}, KeyboardPatterns: []string{"zzkbzz"}, BannedWordCount: 1, KeyboardPatternCount: 1,
			RiskLevel: "Critical", RiskScore: 8.1, DADomains: "CORP", PasswordLength: 7},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low"},
	}
	// sanitized: identities present, no password/hash/wordlist.
	san := bundleAccounts(accts, false, now)
	if len(san) != 2 || san[0].Username != "alice" || san[0].Domain != "CORP" {
		t.Fatalf("identities missing: %+v", san)
	}
	if san[0].Password != "" {
		t.Error("sanitized bundle must not carry a password")
	}
	if san[0].DADomains != "CORP" || !san[0].HasDAPath {
		t.Error("da_domains / has_da_path should be identified, not stripped")
	}
	// The safe wordlist COUNTS are wired (only the raw matched strings are excluded).
	if san[0].BannedWordCount != 1 || san[0].KeyboardPatternCount != 1 {
		t.Errorf("wordlist counts not wired: banned=%d keyboard=%d", san[0].BannedWordCount, san[0].KeyboardPatternCount)
	}
	// Defense in depth: the sanitized JSON must not carry the cleartext anywhere.
	if rawSan := mustJSON(t, san); strings.Contains(rawSan, "Hunter2") {
		t.Error("sanitized bundle JSON leaked the cleartext password")
	}
	// cleartext: password present for cracked, empty for uncracked; still no hash/wordlist.
	ct := bundleAccounts(accts, true, now)
	if ct[0].Password != "Hunter2" {
		t.Errorf("cleartext bundle: cracked account missing password, got %q", ct[0].Password)
	}
	if ct[1].Password != "" {
		t.Error("uncracked account must have empty password")
	}
	// The struct must have no NTHash/BannedWords/KeyboardPatterns fields at all —
	// assert via JSON that those never appear.
	raw := mustJSON(t, ct)
	for _, bad := range []string{"AAAA1111", "zzbanzz", "zzkbzz", "nt_hash"} {
		if strings.Contains(raw, bad) {
			t.Errorf("bundle account leaked %q", bad)
		}
	}
}
