package bloodhound

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSign locks the BHE HMAC scheme to values independently computed with the
// Python reference implementation (cross-validation, not self-reference).
func TestSign(t *testing.T) {
	if got := sign("testkey", "GET", "/api/version", "2026-06-06T14", nil); got != "bkrBSw53iqs/3TALKUscuGPRoqdB/lltWqaHBAnNFuw=" {
		t.Errorf("sign(no body) = %q", got)
	}
	if got := sign("testkey", "GET", "/api/version", "2026-06-06T14", []byte(`{"q":1}`)); got != "WHyXzVuB+Yhw9gVNDI79/WH3037QQfhdYMe5IVXv3CQ=" {
		t.Errorf("sign(body) = %q", got)
	}
}

// verifySig re-derives the signature server-side and checks the client sent it.
func verifySig(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "bhesignature tid" {
		t.Errorf("Authorization = %q", got)
	}
	rd := r.Header.Get("RequestDate")
	if len(rd) < 13 {
		t.Errorf("RequestDate too short: %q", rd)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var b []byte
	if len(body) > 0 {
		b = body
	}
	if want := sign("tkey", r.Method, r.URL.RequestURI(), rd[:13], b); r.Header.Get("Signature") != want {
		t.Errorf("signature mismatch for %s %s", r.Method, r.URL.RequestURI())
	}
}

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	c := New(Config{Scheme: "http", Host: host, Port: port, TokenID: "tid", TokenKey: "tkey"})
	return c, srv
}

func TestGetVersion(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r)
		_, _ = io.WriteString(w, `{"data":{"API":{"current_version":"v2"},"server_version":"5.0"}}`)
	})
	defer srv.Close()
	v, err := c.GetVersion()
	if err != nil || v.API != "v2" || v.Server != "5.0" {
		t.Fatalf("GetVersion = %+v, err %v", v, err)
	}
}

func TestGetUserDataEndToEnd(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r)
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/api/v2/available-domains":
			_, _ = io.WriteString(w, `{"data":[{"name":"CORP.INT","id":"D1","collected":true,"type":"Domain"},{"name":"OLD.INT","id":"D2","collected":false,"type":"Domain"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "User":
			_, _ = io.WriteString(w, `{"data":[{"name":"alice@CORP.INT","objectid":"S-1-5-USER"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "Group":
			_, _ = io.WriteString(w, `{"data":[{"name":"DOMAIN ADMINS@CORP.INT","objectid":"S-1-5-DA"}]}`)
		case len(r.URL.Path) > len("/controllables") && r.URL.Path[len(r.URL.Path)-len("/controllables"):] == "/controllables":
			_, _ = io.WriteString(w, `{"count":2,"data":[{"label":"Computer","name":"PC1@CORP.INT"},{"label":"User","name":"bob@CORP.INT"}]}`)
		case r.URL.Path == "/api/v2/users/S-1-5-USER":
			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true,"pwdneverexpires":false,"distinguishedname":"CN=alice","pwdlastset":133000000000000000}}}`)
		case r.URL.Path == "/api/v2/graphs/shortest-path":
			w.WriteHeader(http.StatusOK) // a path exists
		default:
			t.Errorf("unexpected request: %s", r.URL.RequestURI())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer srv.Close()

	ud, err := c.GetUserData("alice@CORP.INT")
	if err != nil {
		t.Fatal(err)
	}
	if ud == nil {
		t.Fatal("GetUserData returned nil")
	}
	if ud.Username != "alice@CORP.INT" || ud.ObjectID != "S-1-5-USER" || !ud.Props.Enabled {
		t.Fatalf("unexpected user data: %+v", ud)
	}
	if got := ExtractControllableCount(ud); got != 2 {
		t.Errorf("controllable count = %d, want 2", got)
	}
	da := ExtractDADomains(ud)
	if len(da) != 1 || da[0] != "CORP.INT" {
		t.Errorf("DA domains = %v, want [CORP.INT]", da)
	}
}

func TestExtractHelpers(t *testing.T) {
	yes, no := true, false
	ud := &UserData{Controllables: []DomainControllables{
		{Domain: "A.INT", Labels: map[string]int{"User": 3, "Computer": 2}, HasDAPath: &yes},
		{Domain: "B.INT", Labels: map[string]int{"Group": 1}, HasDAPath: &no},
		{Domain: "C.INT", HasDAPath: nil}, // unknown
	}}
	if got := ExtractControllableCount(ud); got != 6 {
		t.Errorf("count = %d, want 6", got)
	}
	if da := ExtractDADomains(ud); len(da) != 1 || da[0] != "A.INT" {
		t.Errorf("da = %v, want [A.INT]", da)
	}
	if ExtractControllableCount(nil) != 0 || ExtractDADomains(nil) != nil {
		t.Error("nil UserData should yield 0 / nil")
	}
}

func TestExtractControllableCountUsesTotal(t *testing.T) {
	// True total from env.Count is 5000 even though only a small label sample
	// (10 items) was paged in. ExtractControllableCount must return 5000.
	ud := &UserData{
		ControllableTotal: 5000,
		Controllables: []DomainControllables{
			{Domain: "CORP.INT", Labels: map[string]int{"User": 7, "Group": 3}},
		},
	}
	if got := ExtractControllableCount(ud); got != 5000 {
		t.Errorf("count = %d, want 5000 (true total, not the 10-item sample)", got)
	}
	// Fallback: when the total is absent (0), sum the sampled label map.
	udNoTotal := &UserData{
		Controllables: []DomainControllables{
			{Domain: "A.INT", Labels: map[string]int{"User": 3, "Computer": 2}},
			{Domain: "B.INT", Labels: map[string]int{"Group": 1}},
		},
	}
	if got := ExtractControllableCount(udNoTotal); got != 6 {
		t.Errorf("fallback count = %d, want 6", got)
	}
	if ExtractControllableCount(nil) != 0 {
		t.Error("nil UserData should yield 0")
	}
}

func TestGetUserDataCountFromEnvelope(t *testing.T) {
	// Mock returns count:5000 but only a 2-item data page. The true total (5000)
	// must survive — proving the >10 cap is gone.
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r)
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/api/v2/available-domains":
			_, _ = io.WriteString(w, `{"data":[{"name":"CORP.INT","id":"D1","collected":true,"type":"Domain"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "User":
			_, _ = io.WriteString(w, `{"data":[{"name":"alice@CORP.INT","objectid":"S-1-5-USER"}]}`)
		case r.URL.Path == "/api/v2/search" && q.Get("type") == "Group":
			_, _ = io.WriteString(w, `{"data":[{"name":"DOMAIN ADMINS@CORP.INT","objectid":"S-1-5-DA"}]}`)
		case len(r.URL.Path) > len("/controllables") && r.URL.Path[len(r.URL.Path)-len("/controllables"):] == "/controllables":
			_, _ = io.WriteString(w, `{"count":5000,"data":[{"label":"User","name":"bob@CORP.INT"},{"label":"User","name":"carol@CORP.INT"}]}`)
		case r.URL.Path == "/api/v2/users/S-1-5-USER":
			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true,"pwdneverexpires":false,"pwdlastset":133000000000000000}}}`)
		case r.URL.Path == "/api/v2/graphs/shortest-path":
			w.WriteHeader(http.StatusNotFound) // no DA path needed for this test
		default:
			t.Errorf("unexpected request: %s", r.URL.RequestURI())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer srv.Close()

	ud, err := c.GetUserData("alice@CORP.INT")
	if err != nil {
		t.Fatal(err)
	}
	if ud == nil {
		t.Fatal("GetUserData returned nil")
	}
	if ud.ControllableTotal != 5000 {
		t.Errorf("ControllableTotal = %d, want 5000", ud.ControllableTotal)
	}
	if got := ExtractControllableCount(ud); got != 5000 {
		t.Errorf("ExtractControllableCount = %d, want 5000 (not the 2-item sample)", got)
	}
}

func TestDomainFromName(t *testing.T) {
	cases := map[string]string{
		"alice@CORP.INT": "CORP.INT",
		"PC1.corp.int":   "corp.int",
		"plainname":      "Unknown",
	}
	for in, want := range cases {
		if got := domainFromName(in); got != want {
			t.Errorf("domainFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientConcurrencySemaphore(t *testing.T) {
	var cur, max int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&cur, 1)
		for {
			old := atomic.LoadInt32(&max)
			if n <= old || atomic.CompareAndSwapInt32(&max, old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	c := New(Config{Scheme: "http", Host: host, Port: port, EnrichConcurrency: 4})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, _ = c.get("/api/v2/available-domains") }()
	}
	wg.Wait()
	// Semaphore is sized at EnrichConcurrency*4 = 16 to avoid self-contention
	// when enrichment workers make sequential calls. With 20 goroutines competing,
	// we expect max concurrency capped at 16.
	if got := atomic.LoadInt32(&max); got == 0 || got > 16 {
		t.Fatalf("max concurrent = %d, want 1..16", got)
	}
}

func TestGetDomainsCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"name":"CORP","collected":true}]}`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	c := New(Config{Scheme: "http", Host: host, Port: port})

	for i := 0; i < 5; i++ {
		ds, err := c.GetDomains()
		if err != nil || len(ds) != 1 {
			t.Fatalf("call %d: ds=%v err=%v", i, ds, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("backend hits = %d, want 1 (cached)", got)
	}
}

func TestGetRetriesOnThrottle(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"name":"CORP","collected":true}]}`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	c := New(Config{Scheme: "http", Host: host, Port: port})
	ds, err := c.GetDomains()
	if err != nil || len(ds) != 1 {
		t.Fatalf("after retry: ds=%v err=%v (n=%d)", ds, err, atomic.LoadInt32(&n))
	}
	if atomic.LoadInt32(&n) < 2 {
		t.Fatalf("expected a retry, server hit %d times", atomic.LoadInt32(&n))
	}
}

// splitHostPort extracts host + numeric port from an httptest URL.
func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), p
}

func TestExtractControlsTier0(t *testing.T) {
	// Controlling the Domain Admins group is DA-equivalent.
	udTier0 := &UserData{Controllables: []DomainControllables{
		{Domain: "CORP.LOCAL", Items: []ControllableItem{
			{Label: "Group", Name: "DOMAIN ADMINS@CORP.LOCAL"},
			{Label: "User", Name: "bob@CORP.LOCAL"},
		}},
	}}
	if !ExtractControlsTier0(udTier0) {
		t.Error("control of DOMAIN ADMINS group must be Tier-0")
	}
	// Controlling only ordinary users is NOT Tier-0.
	udOrdinary := &UserData{Controllables: []DomainControllables{
		{Domain: "CORP.LOCAL", Items: []ControllableItem{
			{Label: "User", Name: "carol@CORP.LOCAL"},
			{Label: "User", Name: "dave@CORP.LOCAL"},
		}},
	}}
	if ExtractControlsTier0(udOrdinary) {
		t.Error("control of ordinary users must not be Tier-0")
	}
	// Case-insensitive + other sensitive names.
	for _, name := range []string{"krbtgt@corp.local", "Enterprise Admins@CORP.LOCAL", "AdminSDHolder@CORP.LOCAL", "DOMAIN CONTROLLERS@CORP.LOCAL"} {
		ud := &UserData{Controllables: []DomainControllables{
			{Domain: "CORP.LOCAL", Items: []ControllableItem{{Label: "Group", Name: name}}},
		}}
		if !ExtractControlsTier0(ud) {
			t.Errorf("name %q should be Tier-0", name)
		}
	}
	if ExtractControlsTier0(nil) {
		t.Error("nil UserData must not be Tier-0")
	}
}

func TestControllablesLimitDefault(t *testing.T) {
	// An unset ControllablesLimit defaults to 100 so the Tier-0/sensitivity sample
	// is wide enough in a single call (env.Count still gives the true magnitude).
	c := New(Config{Scheme: "http", Host: "h", Port: 1, TokenID: "t", TokenKey: "k"})
	if c.controllablesLimit != 100 {
		t.Errorf("default controllablesLimit = %d, want 100", c.controllablesLimit)
	}
	// An explicit value is honored.
	c2 := New(Config{ControllablesLimit: 25})
	if c2.controllablesLimit != 25 {
		t.Errorf("explicit controllablesLimit = %d, want 25", c2.controllablesLimit)
	}
}
