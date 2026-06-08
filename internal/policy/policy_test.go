package policy

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `{
  "default":     {"policy": {"min_length": 14, "require_lowercase": true, "require_uppercase": true, "require_digits": true, "require_special": true, "max_password_age_days": 261}},
  "PHANTOM.CORP":{"policy": {"min_length": 16, "require_lowercase": true, "require_uppercase": true, "require_digits": true, "require_special": true, "max_password_age_days": 90}}
}`

func TestLoadAndFor(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "password_policy.json")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := set.For("PHANTOM.CORP"); got.MinLength != 16 || got.MaxPasswordAgeDays != 90 {
		t.Errorf("PHANTOM.CORP override = %+v", got)
	}
	if got := set.For("UNKNOWN.CORP"); got.MinLength != 14 || got.MaxPasswordAgeDays != 261 {
		t.Errorf("unknown domain should fall back to default, got %+v", got)
	}
}

func TestLoadMissingIsDefault(t *testing.T) {
	set, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got := set.For("anything"); got != Default() {
		t.Errorf("missing file should yield Default(), got %+v", got)
	}
}

func TestReplaceSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "password_policy.json")
	set := DefaultSet()
	set.Replace(
		Policy{MinLength: 12, RequireLowercase: true, MaxPasswordAgeDays: 180},
		map[string]Policy{"GHOST.CORP": {MinLength: 20, MaxPasswordAgeDays: 30}},
	)
	if err := set.Save(p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.For("GHOST.CORP"); got.MinLength != 20 || got.MaxPasswordAgeDays != 30 {
		t.Errorf("round-trip GHOST.CORP = %+v", got)
	}
	if got := reloaded.For("other"); got.MinLength != 12 || got.MaxPasswordAgeDays != 180 {
		t.Errorf("round-trip default = %+v", got)
	}
}

func TestAnalysisSubset(t *testing.T) {
	a := Policy{MinLength: 16, RequireLowercase: true, RequireSpecial: true, MaxPasswordAgeDays: 90}.Analysis()
	if a.MinLength != 16 || !a.RequireLowercase || !a.RequireSpecial || a.RequireDigits {
		t.Errorf("Analysis() subset wrong: %+v", a)
	}
}
