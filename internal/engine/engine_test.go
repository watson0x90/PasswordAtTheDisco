package engine

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
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
	// v2: HIBP no longer triple-counted; level now from Exposure/Impact axes.
	// "Welcome1" (common, len 8, shared) -> Exposure = weakness(~5.64) floored by
	// crackedFloor(3.0), + reuse bump 0.5 = 6.1 (High tier). No enricher => Coverage
	// "none" => Impact Unknown, so Level comes from the Exposure tier alone == High.
	// Score back-compat blend == Exposure when Impact is Unknown == 6.1.
	if alice.RiskLevel != "High" || alice.RiskScore != 6.1 {
		t.Errorf("common password: level=%q score=%v, want High / 6.1", alice.RiskLevel, alice.RiskScore)
	}
	if alice.Coverage != "none" {
		t.Errorf("no enricher -> coverage should be none (Impact Unknown), got %q", alice.Coverage)
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
	// v2: cracked + confirmed DA path -> hard override to Critical (the daOverride
	// branch in LevelFromAxes fires because scoreCracked now sets Cracked:true).
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
	// v2: the uncracked path now routes through risk.Score (Cracked:false) instead of
	// the deleted ad-hoc uncrackedScore/uncrackedVector. With no enrichment Impact is
	// Unknown, so Level comes from the Exposure tier alone.
	// Exposure = hibpExposureFloor(5000): 5000 is in [1000,10000) -> 7.0 (NOT 8.0,
	// which needs >=10000); no share/roastable bump. tierOf(7.0)=High. Score
	// back-compat blend == Exposure when Impact Unknown == 7.0.
	if a.ExposureScore != 7.0 {
		t.Errorf("uncracked exposure = %v, want 7.0", a.ExposureScore)
	}
	if a.ImpactKnown {
		t.Errorf("unenriched uncracked must have Impact Unknown, got known=%v", a.ImpactKnown)
	}
	if a.RiskLevel != "High" {
		t.Errorf("uncracked level = %q, want High (from Exposure 7.0 tier)", a.RiskLevel)
	}
	if a.RiskScore != 7.0 {
		t.Errorf("uncracked score = %v, want 7.0", a.RiskScore)
	}
	// v2 standard risk.Vector (no more "UNCRACKED/..." form); ends with the two axes.
	want := "C:C10/L:VS/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/T0:N/S:0/RO:N/DR:U/HIBP:VH/EXP:H/IMP:U"
	if a.RiskVector != want {
		t.Errorf("uncracked vector = %q, want %q", a.RiskVector, want)
	}
	// v2 fix: uncracked accounts now carry the axis breakdown too, so they show up
	// in the axis-factor dashboard (their Exposure floor is real signal), not just
	// cracked accounts. Previously scoreUncracked left ScoreBreakdown nil.
	if a.ScoreBreakdown == nil {
		t.Fatal("uncracked account must carry a ScoreBreakdown (axis sub-scores)")
	}
	if a.ScoreBreakdown.ExposureScore != a.ExposureScore {
		t.Errorf("uncracked breakdown ExposureScore = %v, want %v", a.ScoreBreakdown.ExposureScore, a.ExposureScore)
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
		{Username: "bob", Domain: "CORP", Hash: "H2", Password: "Summer2023!", Cracked: true},  // ~0.9 to alice
		{Username: "erin", Domain: "CORP", Hash: "H5", Password: "Summer2023!", Cracked: true}, // shares bob's pw (reuse)
		{Username: "carol", Domain: "CORP", Hash: "H3", Password: "totally-different-xyz", Cracked: true},
		{Username: "dave", Domain: "CORP", Hash: "H4", Password: "Summer2024!", Cracked: true}, // exact reuse of alice
	}
	out := e.ProcessDomainNoEnrich("CORP", cracked, nil)
	by := map[string]model.Account{}
	for _, a := range out {
		by[a.Username] = a
	}
	peers := by["alice"].SimilarPeers
	got := map[string]int{}
	for _, p := range peers {
		got[p.Domain+"/"+p.Username]++
		if p.Score < 0.7 {
			t.Errorf("alice peer %s score %v < 0.7", p.Username, p.Score)
		}
	}
	if got["CORP/bob"] != 1 || got["CORP/erin"] != 1 {
		t.Errorf("alice peers should include bob and erin exactly once: %+v", peers)
	}
	if got["CORP/dave"] != 0 || got["CORP/alice"] != 0 {
		t.Errorf("alice peers must exclude exact-reuse dave and self: %+v", peers)
	}
	if len(peers) != 2 {
		t.Errorf("alice should have exactly 2 deduped peers, got %d: %+v", len(peers), peers)
	}
	if len(by["carol"].SimilarPeers) != 0 {
		t.Errorf("carol.SimilarPeers = %+v, want empty", by["carol"].SimilarPeers)
	}
	red := by["alice"].Redacted()
	if len(red.SimilarPeers) != 2 || red.Password != "" {
		t.Errorf("redacted alice = %+v (peers should survive, password cleared)", red)
	}
}

func TestCoverageFromEnriched(t *testing.T) {
	e := newEngine()
	e.Enricher = fakeEnricher{
		"alice@CORP": {Enriched: true, ControlledObjects: ipv(20), Enabled: bp(true)},
	}
	cracked := []secretsdump.ParsedAccount{
		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Str0ng&Unique!Pass", Cracked: true},
		{Username: "ghost", Domain: "CORP", Hash: "H2", Password: "Another!Pass99", Cracked: true}, // no enrichment entry
	}
	out := e.ProcessDomain("CORP", cracked, nil)
	by := map[string]model.Account{}
	for _, a := range out {
		by[a.Username] = a
	}
	if by["alice"].Coverage != "full" {
		t.Errorf("alice coverage = %q, want full", by["alice"].Coverage)
	}
	if by["ghost"].Coverage != "none" {
		t.Errorf("ghost (no enrichment) coverage = %q, want none", by["ghost"].Coverage)
	}
	// Uncracked path too.
	e.Enricher = fakeEnricher{"svc@CORP": {Enriched: true, Enabled: bp(true)}}
	uncracked := []secretsdump.ParsedAccount{
		{Username: "svc", Domain: "CORP", Hash: "UH"},
		{Username: "phantom", Domain: "CORP", Hash: "UH2"}, // no enrichment entry
	}
	byU := map[string]model.Account{}
	for _, a := range e.ProcessDomain("CORP", nil, uncracked) {
		byU[a.Username] = a
	}
	if byU["svc"].Coverage != "full" {
		t.Errorf("uncracked svc coverage = %q, want full", byU["svc"].Coverage)
	}
	if byU["phantom"].Coverage != "none" {
		t.Errorf("uncracked phantom (no enrichment) coverage = %q, want none", byU["phantom"].Coverage)
	}
}

func TestBloodhoundEnricherSurfacesRoastable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/api/v2/available-domains":
			_, _ = io.WriteString(w, `{"data":[{"name":"CORP.INT","id":"D1","collected":true,"type":"Domain"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "User":
			_, _ = io.WriteString(w, `{"data":[{"name":"svc@CORP.INT","objectid":"S-1-5-SVC"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "Group":
			_, _ = io.WriteString(w, `{"data":[{"name":"DOMAIN ADMINS@CORP.INT","objectid":"S-1-5-DA"}]}`)
		case len(r.URL.Path) > len("/controllables") && r.URL.Path[len(r.URL.Path)-len("/controllables"):] == "/controllables":
			_, _ = io.WriteString(w, `{"count":0,"data":[]}`)
		case r.URL.Path == "/api/v2/users/S-1-5-SVC":
			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true,"pwdneverexpires":false,"hasspn":true,"dontreqpreauth":true,"pwdlastset":133000000000000000}}}`)
		case r.URL.Path == "/api/v2/graphs/shortest-path":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected request: %s", r.URL.RequestURI())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	cl := bloodhound.New(bloodhound.Config{Scheme: "http", Host: host, Port: port, TokenID: "tid", TokenKey: "tkey"})

	enr := BloodhoundEnricher{Client: cl}.Enrich("svc@CORP.INT")
	if enr.HasSPN == nil || !*enr.HasSPN {
		t.Errorf("HasSPN not surfaced on live path: %v", enr.HasSPN)
	}
	if enr.DontReqPreauth == nil || !*enr.DontReqPreauth {
		t.Errorf("DontReqPreauth not surfaced on live path: %v", enr.DontReqPreauth)
	}
}

func TestControlsTier0WiredLive(t *testing.T) {
	// Live BloodhoundEnricher: a controllable named "DOMAIN ADMINS" (a Tier-0 group)
	// must set Enrichment.ControlsTier0 = true via bloodhound.ExtractControlsTier0.
	// The /controllables item shape mirrors GetUserControllables' parser, which reads
	// {"label":..,"name":..}; isTier0Name matches the "DOMAIN ADMINS" name substring.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/api/v2/available-domains":
			_, _ = io.WriteString(w, `{"data":[{"name":"CORP.INT","id":"D1","collected":true,"type":"Domain"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "User":
			_, _ = io.WriteString(w, `{"data":[{"name":"svc@CORP.INT","objectid":"S-1-5-SVC"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "Group":
			_, _ = io.WriteString(w, `{"data":[{"name":"DOMAIN ADMINS@CORP.INT","objectid":"S-1-5-DA"}]}`)
		case len(r.URL.Path) > len("/controllables") && r.URL.Path[len(r.URL.Path)-len("/controllables"):] == "/controllables":
			_, _ = io.WriteString(w, `{"count":1,"data":[{"name":"DOMAIN ADMINS@CORP.INT","label":"Group","objectid":"S-1-5-DA"}]}`)
		case r.URL.Path == "/api/v2/users/S-1-5-SVC":
			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true}}}`)
		case r.URL.Path == "/api/v2/graphs/shortest-path":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	cl := bloodhound.New(bloodhound.Config{Scheme: "http", Host: host, Port: port, TokenID: "tid", TokenKey: "tkey"})
	enr := BloodhoundEnricher{Client: cl}.Enrich("svc@CORP.INT")
	if !enr.ControlsTier0 {
		t.Fatal("ControlsTier0 not surfaced on live path")
	}
}

func TestAxisFieldsPopulated(t *testing.T) {
	e := newEngine()
	e.Enricher = fakeEnricher{
		"alice@CORP": {Enriched: true, Enabled: bp(true), ControlledObjects: ipv(200)},
	}
	a := e.ProcessDomain("CORP", []secretsdump.ParsedAccount{
		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Str0ng&Unique!Pass", Cracked: true},
	}, nil)[0]
	if a.ExposureScore <= 0 {
		t.Fatalf("exposure not populated: %v", a.ExposureScore)
	}
	if !a.ImpactKnown || a.ImpactScore == nil {
		t.Fatalf("enriched account must have known impact: known=%v ptr=%v", a.ImpactKnown, a.ImpactScore)
	}
	if *a.ImpactScore != 7.0 { // controlled 200 -> privilegeSubScore 7
		t.Fatalf("impact = %v, want 7.0", *a.ImpactScore)
	}
	if a.ScoreBreakdown == nil || a.ScoreBreakdown.PrivilegeSubScore != 7.0 {
		t.Fatalf("breakdown PrivilegeSubScore wrong: %+v", a.ScoreBreakdown)
	}
}

func TestAgePenaltyWired(t *testing.T) {
	// Two enriched cracked accounts, identical except PwdLastSet: one ~3y old, one fresh.
	// The old one must carry AgePenalty 0.5 (730-1824d band) and Exposure >= the fresh one.
	eng := &Engine{
		Lists: pwanalysis.Lists{
			ForbiddenWords:   pwanalysis.NewSet(),
			KeyboardPatterns: pwanalysis.NewSet(),
			CommonPasswords:  pwanalysis.NewSet(),
			DictionaryWords:  pwanalysis.NewSet(),
		},
		Policies: policy.DefaultSet(),
	}
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	oldSet := now.AddDate(-3, 0, 0).Unix()    // ~1095 days -> ageBump 0.5
	freshSet := now.AddDate(0, 0, -10).Unix() // 10 days -> ageBump 0

	score := func(pwdLastSet int64) model.Account {
		enr := fakeEnricher{"alice@CORP": Enrichment{Enriched: true, Enabled: bp(true), PwdLastSet: &pwdLastSet}}
		return eng.scoreCracked("CORP",
			secretsdump.ParsedAccount{Username: "alice", Hash: "ABC", Password: "Tr0ub4dour&3xpl0it!", Cracked: true},
			0, nil, nil, map[string]*pwanalysis.Analysis{}, map[string]float64{}, map[string][]model.SimilarPeer{}, now, enr)
	}

	oldAcct := score(oldSet)
	freshAcct := score(freshSet)

	if oldAcct.ScoreBreakdown == nil || freshAcct.ScoreBreakdown == nil {
		t.Fatal("expected score_breakdown on both accounts")
	}
	if got := oldAcct.ScoreBreakdown.AgePenalty; got != 0.5 {
		t.Errorf("old AgePenalty = %v, want 0.5", got)
	}
	if got := freshAcct.ScoreBreakdown.AgePenalty; got != 0 {
		t.Errorf("fresh AgePenalty = %v, want 0", got)
	}
	if oldAcct.ExposureScore < freshAcct.ExposureScore {
		t.Errorf("old exposure %v should be >= fresh %v", oldAcct.ExposureScore, freshAcct.ExposureScore)
	}

	// Uncracked path must ALSO forward AgePenalty (NTLM pass-the-hash: never cracked but
	// the password is 3y stale). Exercises the scoreUncracked copy independently.
	uncrackedEnr := fakeEnricher{"bob@CORP": Enrichment{Enriched: true, Enabled: bp(true), PwdLastSet: &oldSet}}
	uncracked := eng.scoreUncracked("CORP",
		secretsdump.ParsedAccount{Username: "bob", Hash: "DEF", Cracked: false},
		0, now, uncrackedEnr)
	if uncracked.ScoreBreakdown == nil {
		t.Fatal("expected score_breakdown on the uncracked account")
	}
	if got := uncracked.ScoreBreakdown.AgePenalty; got != 0.5 {
		t.Errorf("uncracked old AgePenalty = %v, want 0.5", got)
	}
}

func TestRescorePreservesHIBPWhenIndexUnavailable(t *testing.T) {
	// Build a bare engine with no HIBP index attached (HIBP == nil).
	eng := &Engine{
		Lists: pwanalysis.Lists{
			ForbiddenWords:   pwanalysis.NewSet(),
			KeyboardPatterns: pwanalysis.NewSet(),
			CommonPasswords:  pwanalysis.NewSet(),
			DictionaryWords:  pwanalysis.NewSet(),
		},
		Policies: policy.DefaultSet(),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	// HIBP is nil (zero value of *Engine); verify that explicitly.
	if eng.HIBP != nil {
		t.Fatal("fixture setup error: HIBP must be nil for this test")
	}
	in := []model.Account{{
		Username: "bob", Domain: "CORP", NTHash: "ABCD", Password: "password1", Cracked: true,
		HIBPBreached: true, HIBPBreachCount: 5000, ExposureScore: 9,
	}}
	out := eng.RescoreWith(in, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 account, got %d", len(out))
	}
	if out[0].HIBPBreachCount != 5000 {
		t.Fatalf("rescore zeroed the breach count when HIBP unavailable: got %d", out[0].HIBPBreachCount)
	}
	if !out[0].HIBPBreached {
		t.Fatalf("HIBPBreached should remain true (floor preserved)")
	}
}
