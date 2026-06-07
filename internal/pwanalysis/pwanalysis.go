// Package pwanalysis evaluates a cleartext password's intrinsic weaknesses:
// character-class complexity, policy compliance, wordlist/keyboard matches, and
// similarity to other passwords. Its output feeds the risk scoring engine.
//
// Ported from legacy-python/core/password_analysis.py. Two deliberate, documented
// deviations: empty lines are dropped from wordlists (the Python kept ""
// which makes every substring match), and wordlist match order is sorted for
// determinism (the Python iterated a set, whose order is unspecified).
package pwanalysis

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"
)

// Set is a set of lowercased words/patterns.
type Set map[string]struct{}

// NewSet builds a Set from words (lowercased, trimmed; empties dropped).
func NewSet(words ...string) Set {
	s := make(Set, len(words))
	for _, w := range words {
		if w = strings.ToLower(strings.TrimSpace(w)); w != "" {
			s[w] = struct{}{}
		}
	}
	return s
}

// LoadSet reads a wordlist file (one entry per line) into a Set.
func LoadSet(path string) (Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := Set{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if w := strings.ToLower(strings.TrimSpace(sc.Text())); w != "" {
			s[w] = struct{}{}
		}
	}
	return s, sc.Err()
}

// Lists bundles the wordlists used during analysis.
type Lists struct {
	ForbiddenWords   Set
	KeyboardPatterns Set
	CommonPasswords  Set
	DictionaryWords  Set
}

// Policy is a password policy.
type Policy struct {
	MinLength        int
	RequireLowercase bool
	RequireUppercase bool
	RequireDigits    bool
	RequireSpecial   bool
}

// DefaultPolicy mirrors the Python default (min length 8, all classes required).
func DefaultPolicy() Policy {
	return Policy{MinLength: 8, RequireLowercase: true, RequireUppercase: true, RequireDigits: true, RequireSpecial: true}
}

// Similarity is another password and its similarity score (0-1).
type Similarity struct {
	Password string
	Score    float64
}

// Analysis is the full result of analyzing one password.
type Analysis struct {
	PasswordLength   int
	ComplexityLabel  string
	MeetsPolicy      bool
	PolicyViolations []string
	ContainsUnicode  bool
	BannedWords      []string
	KeyboardPatterns []string
	IsCommon         bool
	IsDictionaryWord bool
	SimilarPasswords []Similarity // sorted by score, descending
}

// Character-class predicates (Unicode-aware, matching Python str methods).

func HasLower(pw string) bool {
	for _, r := range pw {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func HasUpper(pw string) bool {
	for _, r := range pw {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func HasDigit(pw string) bool {
	for _, r := range pw {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// HasSpecial reports any non-alphanumeric rune (Python's `not c.isalnum()`).
func HasSpecial(pw string) bool {
	for _, r := range pw {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return true
		}
	}
	return false
}

// HasUnicode reports any non-ASCII rune.
func HasUnicode(pw string) bool {
	for _, r := range pw {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// Complexity classifies a password by the character classes it contains.
func Complexity(pw string) string {
	l, u, d, s := HasLower(pw), HasUpper(pw), HasDigit(pw), HasSpecial(pw)
	switch {
	case l && !u && !d && !s:
		return "loweralpha"
	case u && !l && !d && !s:
		return "upperalpha"
	case d && !l && !u && !s:
		return "numeric"
	case s && !l && !u && !d:
		return "special"
	case l && d && !u && !s:
		return "loweralphanum"
	case u && d && !l && !s:
		return "upperalphanum"
	case l && u && !d && !s:
		return "mixedalpha"
	case l && s && !u && !d:
		return "loweralphaspecial"
	case u && s && !l && !d:
		return "upperalphaspecial"
	case s && d && !l && !u:
		return "specialnum"
	case l && u && d && !s:
		return "mixedalphanum"
	case l && d && s && !u:
		return "loweralphaspecialnum"
	case l && u && s && !d:
		return "mixedalphaspecial"
	case u && d && s && !l:
		return "upperalphaspecialnum"
	case l && u && d && s:
		return "mixedalphaspecialnum"
	default:
		return "none"
	}
}

// CheckPolicy reports whether pw satisfies p and lists any violations.
func CheckPolicy(pw string, p Policy) (bool, []string) {
	meets := true
	var violations []string
	if len([]rune(pw)) < p.MinLength {
		meets = false
		violations = append(violations, fmt.Sprintf("Length < %d", p.MinLength))
	}
	if p.RequireLowercase && !HasLower(pw) {
		meets = false
		violations = append(violations, "No lowercase")
	}
	if p.RequireUppercase && !HasUpper(pw) {
		meets = false
		violations = append(violations, "No uppercase")
	}
	if p.RequireDigits && !HasDigit(pw) {
		meets = false
		violations = append(violations, "No digits")
	}
	if p.RequireSpecial && !HasSpecial(pw) {
		meets = false
		violations = append(violations, "No special character")
	}
	return meets, violations
}

// ForbiddenWordsIn returns the forbidden words appearing as substrings of pw.
func ForbiddenWordsIn(pw string, set Set) []string { return substringMatches(pw, set) }

// KeyboardPatternsIn returns the keyboard patterns appearing as substrings of pw.
func KeyboardPatternsIn(pw string, set Set) []string { return substringMatches(pw, set) }

func substringMatches(pw string, set Set) []string {
	low := strings.ToLower(pw)
	var out []string
	for w := range set {
		if strings.Contains(low, w) {
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}

// IsCommon reports whether pw (case-insensitively) is a known common password.
func IsCommon(pw string, set Set) bool {
	_, ok := set[strings.ToLower(pw)]
	return ok
}

// IsDictionaryWord reports whether pw is exactly a dictionary word.
func IsDictionaryWord(pw string, set Set) bool {
	_, ok := set[strings.ToLower(pw)]
	return ok
}

// Similar returns the passwords in others with a Levenshtein ratio >= 0.7 to
// password (exact matches excluded), sorted by score descending.
func Similar(password string, others []string) []Similarity {
	var out []Similarity
	for _, o := range others {
		if o == password {
			continue
		}
		if r := levenshteinRatio(password, o); r >= 0.7 {
			out = append(out, Similarity{Password: o, Score: r})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// levenshteinRatio implements python-Levenshtein's ratio: an edit distance with
// insert/delete cost 1 and substitution cost 2, then (lensum-dist)/lensum.
func levenshteinRatio(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 && lb == 0 {
		return 1.0
	}
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur := make([]int, lb+1)
		cur[0] = i
		for j := 1; j <= lb; j++ {
			if ra[i-1] == rb[j-1] {
				cur[j] = prev[j-1]
			} else {
				cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+2)
			}
		}
		prev = cur
	}
	lensum := la + lb
	return float64(lensum-prev[lb]) / float64(lensum)
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// Analyze runs the full analysis. Returns nil for an empty password. compare may
// be nil (no similarity analysis).
func Analyze(password string, lists Lists, compare []string, policy Policy) *Analysis {
	if password == "" {
		return nil
	}
	meets, violations := CheckPolicy(password, policy)
	a := &Analysis{
		PasswordLength:   len([]rune(password)),
		ComplexityLabel:  Complexity(password),
		MeetsPolicy:      meets,
		PolicyViolations: violations,
		ContainsUnicode:  HasUnicode(password),
		BannedWords:      ForbiddenWordsIn(password, lists.ForbiddenWords),
		KeyboardPatterns: KeyboardPatternsIn(password, lists.KeyboardPatterns),
		IsCommon:         IsCommon(password, lists.CommonPasswords),
		IsDictionaryWord: IsDictionaryWord(password, lists.DictionaryWords),
	}
	if len(compare) > 0 {
		a.SimilarPasswords = Similar(password, compare)
	}
	return a
}
