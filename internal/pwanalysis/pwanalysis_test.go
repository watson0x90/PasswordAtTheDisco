package pwanalysis

import (
	"math"
	"testing"
)

func TestCharacterPredicates(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) bool
		pw   string
		want bool
	}{
		{"lower-yes", HasLower, "abc", true}, {"lower-no", HasLower, "ABC123!", false},
		{"upper-yes", HasUpper, "ABC", true}, {"upper-no", HasUpper, "abc123!", false},
		{"digit-yes", HasDigit, "123", true}, {"digit-no", HasDigit, "abcABC!", false},
		{"special-yes", HasSpecial, "!@#", true}, {"special-no", HasSpecial, "abcABC123", false},
		{"unicode-yes", HasUnicode, "café", true}, {"unicode-no", HasUnicode, "cafe", false},
	}
	for _, c := range cases {
		if got := c.fn(c.pw); got != c.want {
			t.Errorf("%s(%q) = %v, want %v", c.name, c.pw, got, c.want)
		}
	}
}

func TestComplexity(t *testing.T) {
	cases := map[string]string{
		"abc": "loweralpha", "ABC": "upperalpha", "123": "numeric", "!!!": "special",
		"abc123": "loweralphanum", "ABC123": "upperalphanum", "abcABC": "mixedalpha",
		"abc!!!": "loweralphaspecial", "ABC!!!": "upperalphaspecial", "123!!!": "specialnum",
		"abcABC123": "mixedalphanum", "abc123!!!": "loweralphaspecialnum",
		"abcABC!!!": "mixedalphaspecial", "ABC123!!!": "upperalphaspecialnum",
		"abcABC123!!!": "mixedalphaspecialnum", "": "none",
	}
	for pw, want := range cases {
		if got := Complexity(pw); got != want {
			t.Errorf("Complexity(%q) = %q, want %q", pw, got, want)
		}
	}
}

func TestCheckPolicy(t *testing.T) {
	p := Policy{MinLength: 14, RequireLowercase: true, RequireUppercase: true, RequireDigits: true, RequireSpecial: true}

	if meets, v := CheckPolicy("Abcdefghij123!", p); !meets || len(v) != 0 {
		t.Errorf("compliant: meets=%v violations=%v", meets, v)
	}
	if meets, v := CheckPolicy("Ab1!", p); meets || !contains(v, "Length < 14") {
		t.Errorf("too short: meets=%v violations=%v", meets, v)
	}
	meets, v := CheckPolicy("abcdefghijklmn", p)
	if meets || !contains(v, "No uppercase") || !contains(v, "No digits") || !contains(v, "No special character") {
		t.Errorf("missing classes: meets=%v violations=%v", meets, v)
	}
}

func TestWordlistMatchers(t *testing.T) {
	if got := ForbiddenWordsIn("MyAcmeCorp2024", NewSet("acme", "corp")); !equalSet(got, []string{"acme", "corp"}) {
		t.Errorf("forbidden = %v", got)
	}
	if got := ForbiddenWordsIn("xyz123", NewSet("acme")); len(got) != 0 {
		t.Errorf("forbidden none = %v", got)
	}
	if got := KeyboardPatternsIn("qwerty123", NewSet("qwerty", "asdf")); len(got) != 1 || got[0] != "qwerty" {
		t.Errorf("keyboard = %v", got)
	}
	if !IsCommon("Password", NewSet("password")) || IsCommon("unique-xyz", NewSet("password")) {
		t.Error("IsCommon case-insensitivity failed")
	}
	if !IsDictionaryWord("Hello", NewSet("hello")) || IsDictionaryWord("hello123", NewSet("hello")) {
		t.Error("IsDictionaryWord exact-match failed")
	}
}

func TestLevenshteinRatio(t *testing.T) {
	cases := []struct {
		a, b string
		want float64
	}{
		{"abc", "abc", 1.0},
		{"abc", "xyz", 0.0},               // 3 subs * 2 = 6, lensum 6
		{"kitten", "sitting", 8.0 / 13.0}, // classic: dist(sub=2)=5, lensum 13
		{"Summer2024!", "Summer2023!", 20.0 / 22.0},
	}
	for _, c := range cases {
		if got := levenshteinRatio(c.a, c.b); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("ratio(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSimilar(t *testing.T) {
	others := []string{"Summer2024!", "Summer2023!", "totally-different-xyz", "Summer2024!"}
	got := Similar("Summer2024!", others)
	if len(got) != 1 || got[0].Password != "Summer2023!" {
		t.Fatalf("Similar = %+v (exact matches should be skipped, <0.7 excluded)", got)
	}
	if math.Abs(got[0].Score-20.0/22.0) > 1e-9 {
		t.Errorf("score = %v", got[0].Score)
	}
	// sorted descending by score
	multi := Similar("password1", []string{"password2", "passwXYZ1", "password12"})
	for i := 1; i < len(multi); i++ {
		if multi[i-1].Score < multi[i].Score {
			t.Errorf("not sorted descending: %+v", multi)
		}
	}
}

func TestAnalyze(t *testing.T) {
	if Analyze("", Lists{}, nil, DefaultPolicy()) != nil {
		t.Error("empty password should return nil")
	}
	a := Analyze("Acme123!", Lists{ForbiddenWords: NewSet("acme")}, nil, Policy{
		MinLength: 8, RequireLowercase: true, RequireUppercase: true, RequireDigits: true, RequireSpecial: true,
	})
	if a == nil {
		t.Fatal("nil analysis")
	}
	if a.PasswordLength != 8 || a.ComplexityLabel != "mixedalphaspecialnum" ||
		!equalSet(a.BannedWords, []string{"acme"}) || !a.MeetsPolicy {
		t.Errorf("unexpected analysis: %+v", a)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func equalSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !contains(got, w) {
			return false
		}
	}
	return true
}
