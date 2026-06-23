package bloodhound

import (
	"strings"
	"testing"
)

func TestParseUsersExportRoastableFields(t *testing.T) {
	// SharpHound collection shape: {"data":[{"Properties":{...},"ObjectIdentifier":"..."}]}
	sharp := `{"data":[
		{"Properties":{"samaccountname":"svc1","domain":"corp.local","enabled":true,"hasspn":true,"dontreqpreauth":false},"ObjectIdentifier":"S-1-1"},
		{"Properties":{"samaccountname":"svc2","domain":"corp.local","enabled":true,"hasspn":false,"dontreqpreauth":true},"ObjectIdentifier":"S-1-2"}
	]}`
	got, err := ParseUsersExport(strings.NewReader(sharp))
	if err != nil {
		t.Fatalf("sharphound parse: %v", err)
	}
	if u := got["svc1@CORP.LOCAL"]; !u.HasSPN || u.DontReqPreauth {
		t.Errorf("svc1 sharphound: HasSPN=%v DontReqPreauth=%v, want true/false", u.HasSPN, u.DontReqPreauth)
	}
	if u := got["svc2@CORP.LOCAL"]; u.HasSPN || !u.DontReqPreauth {
		t.Errorf("svc2 sharphound: HasSPN=%v DontReqPreauth=%v, want false/true", u.HasSPN, u.DontReqPreauth)
	}

	// BHE flat shape: [{"props":{...},"objectid":"..."}]
	bhe := `[{"props":{"samaccountname":"svc3","domain":"corp.local","enabled":true,"hasspn":true,"dontreqpreauth":true},"objectid":"S-1-3"}]`
	got, err = ParseUsersExport(strings.NewReader(bhe))
	if err != nil {
		t.Fatalf("bhe parse: %v", err)
	}
	if u := got["svc3@CORP.LOCAL"]; !u.HasSPN || !u.DontReqPreauth {
		t.Errorf("svc3 bhe: HasSPN=%v DontReqPreauth=%v, want true/true", u.HasSPN, u.DontReqPreauth)
	}

	// Simplified shape: omitting hasspn tests zero-value (false); dontreqpreauth explicit true.
	simple := `[{"username":"svc4","domain":"CORP.LOCAL","enabled":true,"dontreqpreauth":true}]`
	got, err = ParseUsersExport(strings.NewReader(simple))
	if err != nil {
		t.Fatalf("simple parse: %v", err)
	}
	if u := got["svc4@CORP.LOCAL"]; u.HasSPN || !u.DontReqPreauth {
		t.Errorf("svc4 simple: HasSPN=%v DontReqPreauth=%v, want false/true", u.HasSPN, u.DontReqPreauth)
	}
}
