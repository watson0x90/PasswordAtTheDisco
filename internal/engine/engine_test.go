package engine

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/secretsdump"
)

// --- fakes ---

type fakeHIBP map[string]int // ntlm (upper) -> breach count

func (f fakeHIBP) LookupHash(ntlm string) (bool, int, error) {
	c, ok := f[ntlm]
	return ok, c, nil
}

type fakeEnricher map[string]Enrichment // normalized username -> enrichment

func (f fakeEnricher) Enrich(username string) Enrichment { return f[username] }

func bp(b bool) *bool { return &b }
func ipv(n int) *int  { return &n }

func newEngine() *Engine {
	return &Engine{
		Lists:    pwanalysis.Lists{CommonPasswords: pwanalysis.NewSet("welcome1")},
		Policies: policy.DefaultSet(),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

func TestProcessDomainCrackedBasics(t *testing.T) {
	e := newEngine()
	cracked := []secretsdump.ParsedAccount{
		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Welcome1", Cracked: true},
		{Username: "bob", Domain: "CORP", Hash: "H2", Password: "Welcome1", Cracked: true}, // shares pw
		{Username: "carol", Domain: "CORP", Hash: "H3", Password: "Tr0ub4dour&3xtra!Long", Cracked: true},
	}
	accts := e.ProcessDomain("CORP", cracked, nil)
	if len(accts) != 3 {
		t.Fatalf("expected 3 accounts, got %d", len(accts))
	}
	byUser := map[string]int{}
	for i, a := range accts {
		byUser[a.Username] = i
		if !a.Cracked || a.Domain != "CORP" {
			t.Errorf("%s: bad base fields %+v", a.Username, a)
		}
	}

	alice := accts[byUser["alice"]]
	bob := accts[byUser["bob"]]
	// shared password -> SharedWith == 1 each
	if alice.SharedWith != 1 || bob.SharedWith != 1 {
		t.Errorf("shared-with: alice=%d bob=%d, want 1/1", alice.SharedWith, bob.SharedWith)
	}
	// "Welcome1" is common -> base floor 7.0, reduced by unknown temporal factors
	// to ~6.2 == High; far above a strong unique password.
	if alice.RiskLevel != "High" || alice.RiskScore < 6.0 {
		t.Errorf("common password: level=%q score=%v, want High / >=6.0", alice.RiskLevel, alice.RiskScore)
	}
	if carol := accts[byUser["carol"]]; !(carol.RiskScore < alice.RiskScore) {
		t.Errorf("strong pw (%v) should score below common pw (%v)", carol.RiskScore, alice.RiskScore)
	}
	if alice.DADomains != "None" {
		t.Errorf("no enricher -> DADomains should be None, got %q", alice.DADomains)
	}
	// no HIBP configured -> not breached
	if alice.HIBPBreached {
		t.Error("no HIBP configured, should not be breached")
	}
}

func TestProcessDomainHIBPAndDAPath(t *testing.T) {
	e := newEngine()
	e.HIBP = fakeHIBP{"H1": 150000}
	e.Enricher = fakeEnricher{
		"alice@CORP": {DADomains: []string{"CORP"}, ControlledObjects: ipv(20), PwdNeverExpires: bp(true), Enabled: bp(true)},
	}
	cracked := []secretsdump.ParsedAccount{
		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Str0ng&Unique!Passphrase", Cracked: true},
	}
	a := e.ProcessDomain("CORP", cracked, nil)[0]

	if !a.HIBPBreached || a.HIBPBreachCount != 150000 {
		t.Errorf("HIBP: breached=%v count=%d", a.HIBPBreached, a.HIBPBreachCount)
	}
	if a.DADomains != "CORP" {
		t.Errorf("DADomains = %q, want CORP", a.DADomains)
	}
	if a.RiskLevel != "Critical" {
		t.Errorf("DA pathway must be Critical, got %q", a.RiskLevel)
	}
	if a.Controlled != 20 || !a.Enabled {
		t.Errorf("enrichment not applied: controlled=%d enabled=%v", a.Controlled, a.Enabled)
	}
}

func TestProcessDomainUncracked(t *testing.T) {
	e := newEngine()
	e.HIBP = fakeHIBP{"UH": 5000}
	uncracked := []secretsdump.ParsedAccount{
		{Username: "svc", Domain: "CORP", Hash: "UH"},
	}
	a := e.ProcessDomain("CORP", nil, uncracked)[0]
	if a.Cracked || a.Password != "" {
		t.Errorf("uncracked should have no cleartext: %+v", a)
	}
	if !a.HIBPBreached || a.HIBPBreachCount != 5000 {
		t.Errorf("uncracked HIBP: %v/%d", a.HIBPBreached, a.HIBPBreachCount)
	}
	// base 5.0 * priv 1.0 * share 1.0 * hibp(5000)=1.3 = 6.5
	if a.RiskScore != 6.5 {
		t.Errorf("uncracked score = %v, want 6.5", a.RiskScore)
	}
	want := "UNCRACKED/DA:N/CO:L/S:0/HIBP:VH"
	if a.RiskVector != want {
		t.Errorf("uncracked vector = %q, want %q", a.RiskVector, want)
	}
}

func TestPasswordExpiresAndDays(t *testing.T) {
	if passwordExpires(nil) != "Unknown" || passwordExpires(bp(true)) != "No" || passwordExpires(bp(false)) != "Yes" {
		t.Error("passwordExpires mapping wrong")
	}
	e := newEngine() // now = 1_700_000_000
	// pwdlastset 200 days before now, maxAge 90 -> ~110 days out
	setEpoch := int64(1_700_000_000 - 200*24*3600)
	d := daysOutOfCompliance(&setEpoch, e.now(), 90)
	if d == nil || *d < 105 || *d > 115 {
		t.Errorf("daysOutOfCompliance = %v, want ~110", d)
	}
	if daysOutOfCompliance(nil, e.now(), 90) != nil {
		t.Error("nil pwdlastset -> nil days")
	}
}

func TestNormalizeUsername(t *testing.T) {
	if NormalizeUsername("alice", "CORP") != "alice@CORP" {
		t.Error("should append domain")
	}
	if NormalizeUsername("alice@CORP", "CORP") != "alice@CORP" {
		t.Error("should not double-suffix")
	}
}

func TestRescoreWithExplicitEnricher(t *testing.T) {
	e := newEngine()
	accts := []model.Account{{
		Username: "alice", Domain: "CORP", NTHash: "H1", Password: "Summer2024!", Cracked: true,
	}}
	plain := e.RescoreWith(accts, nil)
	if plain[0].DADomains != "None" {
		t.Fatalf("nil enricher should yield no DA, got %q", plain[0].DADomains)
	}
	enr := fakeEnricher{NormalizeUsername("alice", "CORP"): Enrichment{DADomains: []string{"CORP"}}}
	withDA := e.RescoreWith(accts, enr)
	if withDA[0].DADomains != "CORP" {
		t.Fatalf("map enricher should yield DA=CORP, got %q", withDA[0].DADomains)
	}
}

func TestProcessDomainNoEnrichSkipsBHE(t *testing.T) {
	e := newEngine()
	e.Enricher = fakeEnricher{NormalizeUsername("bob", "CORP"): Enrichment{DADomains: []string{"CORP"}}}
	out := e.ProcessDomainNoEnrich("CORP", []secretsdump.ParsedAccount{
		{Username: "bob", Domain: "CORP", Hash: "H2", Password: "pw", Cracked: true},
	}, nil)
	if out[0].DADomains != "None" {
		t.Fatalf("ProcessDomainNoEnrich must ignore e.Enricher, got DA=%q", out[0].DADomains)
	}
}

func TestUnknownEnabledTreatedAsEnabled(t *testing.T) {
	// No Enricher configured -> enr.Enabled is nil (unknown). The account must
	// default to enabled, not disabled.
	eng := &Engine{Lists: pwanalysis.Lists{
		ForbiddenWords:   pwanalysis.NewSet(),
		KeyboardPatterns: pwanalysis.NewSet(),
		CommonPasswords:  pwanalysis.NewSet(),
		DictionaryWords:  pwanalysis.NewSet(),
	},
		Policies: policy.DefaultSet(),
	}
	a := eng.scoreCracked("CORP",
		secretsdump.ParsedAccount{Username: "x", Hash: "ABC", Password: "Passw0rd!", Cracked: true},
		0, nil, nil, map[string]*pwanalysis.Analysis{}, map[string]float64{}, map[string][]model.SimilarPeer{}, time.Now(), nil)
	if !a.Enabled {
		t.Fatalf("unknown BHE enabled-status should default to Enabled=true, got false")
	}
}

func TestScoreCrackedStoresMatchedWords(t *testing.T) {
	eng := &Engine{
		Lists: pwanalysis.Lists{
			ForbiddenWords:   pwanalysis.NewSet("summer"),
			KeyboardPatterns: pwanalysis.NewSet("qwerty"),
			CommonPasswords:  pwanalysis.NewSet(),
			DictionaryWords:  pwanalysis.NewSet(),
		},
		Policies: policy.DefaultSet(),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	a := eng.scoreCracked("CORP",
		secretsdump.ParsedAccount{Username: "alice", Hash: "ABC", Password: "Summerqwerty1", Cracked: true},
		0, nil, nil, map[string]*pwanalysis.Analysis{}, map[string]float64{}, map[string][]model.SimilarPeer{}, time.Now(), nil)
	if len(a.BannedWords) == 0 || a.BannedWords[0] != "summer" {
		t.Fatalf("BannedWords not stored: %+v", a.BannedWords)
	}
	if len(a.KeyboardPatterns) == 0 || a.KeyboardPatterns[0] != "qwerty" {
		t.Fatalf("KeyboardPatterns not stored: %+v", a.KeyboardPatterns)
	}
	if a.BannedWordCount != 1 || a.KeyboardPatternCount != 1 {
		t.Fatalf("counts wrong: %d / %d", a.BannedWordCount, a.KeyboardPatternCount)
	}
}

func TestSwapForbiddenWords(t *testing.T) {
	eng := &Engine{Lists: pwanalysis.Lists{ForbiddenWords: pwanalysis.NewSet("acme")}}
	if got := eng.ForbiddenWords(); len(got) != 1 {
		t.Fatalf("initial size = %d", len(got))
	}
	eng.SwapForbiddenWords(pwanalysis.NewSet("acme", "summer"))
	if got := eng.ForbiddenWords(); len(got) != 2 {
		t.Fatalf("after swap size = %d", len(got))
	}
	if _, ok := eng.ForbiddenWords()["summer"]; !ok {
		t.Error("swapped set missing 'summer'")
	}
}

func TestSimilarPeers(t *testing.T) {
	e := newEngine()
	cracked := []secretsdump.ParsedAccount{
		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Summer2024!", Cracked: true},
		{Username: "bob", Domain: "CORP", Hash: "H2", Password: "Summer2023!", Cracked: true},
		{Username: "carol", Domain: "CORP", Hash: "H3", Password: "totally-different-xyz", Cracked: true},
		{Username: "dave", Domain: "CORP", Hash: "H4", Password: "Summer2024!", Cracked: true},
	}
	out := e.ProcessDomainNoEnrich("CORP", cracked, nil)
	by := map[string]model.Account{}
	for _, a := range out {
		by[a.Username] = a
	}
	peers := by["alice"].SimilarPeers
	if len(peers) != 1 || peers[0].Username != "bob" {
		t.Fatalf("alice.SimilarPeers = %+v, want [bob]", peers)
	}
	if peers[0].Score < 0.7 {
		t.Errorf("alice->bob score = %v, want >= 0.7", peers[0].Score)
	}
	if peers[0].Domain != "CORP" {
		t.Errorf("peer domain = %q, want CORP", peers[0].Domain)
	}
	if len(by["carol"].SimilarPeers) != 0 {
		t.Errorf("carol.SimilarPeers = %+v, want empty", by["carol"].SimilarPeers)
	}
	red := by["alice"].Redacted()
	if len(red.SimilarPeers) != 1 || red.Password != "" {
		t.Errorf("redacted alice = %+v (peers should survive, password cleared)", red)
	}
}
