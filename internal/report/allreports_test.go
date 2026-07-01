package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func unzipAll(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		d, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = d
	}
	return out
}

func TestAllReportsZip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Password: "Welcome1",
			Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7, HIBPBreached: true, HIBPBreachCount: 5},
		{Username: "bob", Domain: "SUB", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Password: "Welcome1",
			Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7},
	}
	sum := model.Summarize(accts, now)

	// --- redacted ---
	var buf bytes.Buffer
	if err := AllReportsZip(&buf, "Eng", false, accts, sum, now, "vt"); err != nil {
		t.Fatal(err)
	}
	files := unzipAll(t, buf.Bytes())
	for _, want := range []string{
		"accounts.csv", "cracked.csv", "cracked.html", "hibp.csv", "hibp.html",
		"weak.csv", "weak.html", "reuse.csv", "reuse.html", "full_report.html",
		"sanitized.json", "model_bundle/report.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("redacted zip missing %s", want)
		}
	}
	for name, content := range files {
		if bytes.Contains(content, []byte("Welcome1")) {
			t.Errorf("redacted entry %s LEAKED cleartext", name)
		}
		if bytes.Contains(content, []byte("AAAA0000")) {
			t.Errorf("redacted entry %s LEAKED NT hash", name)
		}
		if strings.HasPrefix(name, "cleartext/") {
			t.Errorf("redacted zip must have no cleartext/ folder, got %s", name)
		}
	}

	// --- cleartext ---
	var cbuf bytes.Buffer
	if err := AllReportsZip(&cbuf, "Eng", true, accts, sum, now, "vt"); err != nil {
		t.Fatal(err)
	}
	cf := unzipAll(t, cbuf.Bytes())
	// cleartext folder present with the password; NO NT hash anywhere.
	ctFound := false
	for name, content := range cf {
		hasPw := bytes.Contains(content, []byte("Welcome1"))
		if strings.HasPrefix(name, "cleartext/") {
			if hasPw {
				ctFound = true
			}
		} else if hasPw {
			t.Errorf("non-cleartext entry %s LEAKED cleartext", name)
		}
		if bytes.Contains(content, []byte("AAAA0000")) {
			t.Errorf("entry %s LEAKED NT hash", name)
		}
	}
	if !ctFound {
		t.Error("cleartext zip: no cleartext/ entry contains the password")
	}
	for _, want := range []string{
		"cleartext/accounts_CLEARTEXT.csv", "cleartext/full_report_CLEARTEXT.html",
		"cleartext/model_bundle/report.json",
	} {
		if _, ok := cf[want]; !ok {
			t.Errorf("cleartext zip missing %s", want)
		}
	}
}
