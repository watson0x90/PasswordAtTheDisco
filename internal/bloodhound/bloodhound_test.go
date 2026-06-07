package bloodhound

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
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
	c.minInterval = 0 // no throttling in tests
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
