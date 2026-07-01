package report

import (
	"archive/zip"
	"io"
	"sort"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// AllReportsZip assembles every export for the audit into one ZIP by delegating to the
// existing generators. cleartext=false is the redacted, open bundle; cleartext=true adds a
// segregated cleartext/ folder (cracked passwords only, never NT hashes) and MUST be caller-gated.
func AllReportsZip(w io.Writer, name string, cleartext bool, accounts []model.Account, summary model.Summary, now time.Time, version string) error {
	zw := zip.NewWriter(w)
	rep := model.BuildReport(accounts)
	m := metrics.Compute(accounts, now)

	filter := func(keep func(model.Account) bool) []model.Account {
		out := make([]model.Account, 0)
		for _, a := range accounts {
			if keep(a) {
				out = append(out, a)
			}
		}
		return out
	}
	cracked := filter(func(a model.Account) bool { return a.Cracked })
	hibp := filter(func(a model.Account) bool { return a.HIBPBreached })
	sort.SliceStable(hibp, func(i, j int) bool { return hibp[i].HIBPBreachCount > hibp[j].HIBPBreachCount })
	weak := filter(func(a model.Account) bool { return a.IsWeak() })

	// add creates a zip entry and runs gen(entryWriter); the first error aborts.
	var firstErr error
	add := func(path string, gen func(io.Writer) error) {
		if firstErr != nil {
			return
		}
		f, err := zw.Create(path)
		if err != nil {
			firstErr = err
			return
		}
		if err := gen(f); err != nil {
			firstErr = err
		}
	}

	// All entries below are REDACTED. CSV, HTML, SanitizedJSON, and the sanitized
	// bundle self-project (Redacted()/allowlist) so they're secret-free even on the
	// full accounts loaded above. AccountsHTML/WeakPasswordsHTML do NOT self-project —
	// they are safe only because their templates render column-restricted fields
	// (username/domain/risk/counts) and never .Password or .NTHash. Keep those
	// templates column-restricted, or switch these to self-projecting generators.
	add("accounts.csv", func(f io.Writer) error { return CSV(f, accounts) })
	add("cracked.csv", func(f io.Writer) error { return CSV(f, cracked) })
	add("cracked.html", func(f io.Writer) error {
		return AccountsHTML(f, name+" — Cracked accounts", "cracked accounts", now, cracked)
	})
	add("hibp.csv", func(f io.Writer) error { return CSV(f, hibp) })
	add("hibp.html", func(f io.Writer) error {
		return AccountsHTML(f, name+" — HIBP-exposed accounts", "accounts whose NT hash is in HIBP", now, hibp)
	})
	add("weak.csv", func(f io.Writer) error { return CSV(f, weak) })
	add("weak.html", func(f io.Writer) error { return WeakPasswordsHTML(f, name, now, weak) })
	add("reuse.csv", func(f io.Writer) error { return ReuseGroupsCSV(f, rep) })
	add("reuse.html", func(f io.Writer) error { return ReuseGroupsHTML(f, name+" — Password-reuse groups", now, rep) })
	add("full_report.html", func(f io.Writer) error { return HTML(f, name, now, accounts) })
	add("sanitized.json", func(f io.Writer) error { return SanitizedJSON(f, accounts, summary, now, version) })

	if firstErr == nil {
		firstErr = writeBundleInto(zw, "model_bundle/", name, "org", false, m, accounts, now, version)
	}

	if cleartext && firstErr == nil {
		add("cleartext/accounts_CLEARTEXT.csv", func(f io.Writer) error { return CSVCleartext(f, accounts) })
		add("cleartext/full_report_CLEARTEXT.html", func(f io.Writer) error { return HTMLCleartext(f, name, now, accounts) })
		if firstErr == nil {
			firstErr = writeBundleInto(zw, "cleartext/model_bundle/", name, "org", true, m, accounts, now, version)
		}
	}

	if firstErr != nil {
		_ = zw.Close()
		return firstErr
	}
	return zw.Close()
}
