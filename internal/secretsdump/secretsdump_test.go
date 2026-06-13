package secretsdump

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSkipsMachineAccounts(t *testing.T) {
	in := "alice:1001:aad3b435b51404eeaad3b435b51404ee:NTHASH:::Welcome1\n" +
		"WK01$:1002:aad3b435b51404eeaad3b435b51404ee:NTHASH:::Random120CharMachinePw\n"
	got, err := ParseCracked(strings.NewReader(in), "CORP")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Username != "alice" {
		t.Fatalf("machine account (WK01$) should be filtered: %+v", got)
	}
}

func TestParseUTF16AndBOM(t *testing.T) {
	line := "alice:1001:aad3b435b51404eeaad3b435b51404ee:NTHASHVALUE:::Welcome1\n"

	// UTF-16LE + BOM (PowerShell Out-File default)
	var le bytes.Buffer
	le.Write([]byte{0xFF, 0xFE})
	for _, r := range line {
		le.WriteByte(byte(r))
		le.WriteByte(0)
	}
	got, err := ParseCracked(&le, "CORP")
	if err != nil || len(got) != 1 || got[0].Username != "alice" || got[0].Password != "Welcome1" {
		t.Fatalf("UTF-16LE+BOM parse failed: %v %+v", err, got)
	}

	// UTF-8 + BOM
	utf8b := append([]byte{0xEF, 0xBB, 0xBF}, []byte(line)...)
	got2, err := ParseCracked(bytes.NewReader(utf8b), "CORP")
	if err != nil || len(got2) != 1 || got2[0].Username != "alice" {
		t.Fatalf("UTF-8+BOM parse failed: %v %+v", err, got2)
	}
}

// --- decodeHex (ported from TestDecodeHex) ---

func TestDecodeHex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Sup3rSecret!", "Sup3rSecret!"},       // plain unchanged
		{"$HEX[48656c6c6f]", "Hello"},          // hex block decoded
		{"contains$dollar", "contains$dollar"}, // no $HEX marker -> passthrough
		{"$HEX[ff]", "ÿ"},                      // non-UTF-8 -> lossless Latin-1
		{"$HEX[zz]", "HEX[zz]"},                // malformed hex -> literal segment
	}
	for _, c := range cases {
		if got := decodeHex(c.in); got != c.want {
			t.Errorf("decodeHex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- ParseCracked (ported from TestProcessDomain*) ---

func cracked(t *testing.T, lines ...string) []ParsedAccount {
	t.Helper()
	accts, err := ParseCracked(strings.NewReader(strings.Join(lines, "\n")+"\n"), "CORP.INT")
	if err != nil {
		t.Fatal(err)
	}
	return accts
}

func TestParseCrackedSecretsDump7Fields(t *testing.T) {
	got := cracked(t, "alice:1001:aad3b435b51404eeaad3b435b51404ee:ntlmhashvalue:::Summer2024!")
	if len(got) != 1 {
		t.Fatalf("want 1 account, got %d", len(got))
	}
	a := got[0]
	if a.Username != "alice" || a.Hash != "ntlmhashvalue" || a.Password != "Summer2024!" ||
		a.Domain != "CORP.INT" || !a.Cracked {
		t.Fatalf("unexpected account: %+v", a)
	}
}

func TestParseCrackedSecretsDump8Fields(t *testing.T) {
	got := cracked(t, "alice:1001:aad3b435b51404eeaad3b435b51404ee:ntlmhashvalue::::Summer2024!")
	if len(got) != 1 || got[0].Password != "Summer2024!" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestParseCrackedEmptyPasswordSkipped(t *testing.T) {
	if got := cracked(t, "bob:1002:aad3b435b51404eeaad3b435b51404ee:ntlm::::"); len(got) != 0 {
		t.Fatalf("empty password should be skipped, got %+v", got)
	}
}

func TestParseCrackedColonInPasswordPreserved(t *testing.T) {
	got := cracked(t, "carol:1003:aad3b435b51404eeaad3b435b51404ee:ntlm::::pa:ss:word")
	if len(got) != 1 || got[0].Password != "pa:ss:word" {
		t.Fatalf("colon password not preserved: %+v", got)
	}
}

func TestParseCrackedSimpleFormat(t *testing.T) {
	got := cracked(t, "eve:abc123hash:Winter2024!")
	if len(got) != 1 || got[0].Username != "eve" || got[0].Hash != "abc123hash" || got[0].Password != "Winter2024!" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestParseCrackedHexPassword(t *testing.T) {
	got := cracked(t, "grace:hash:$HEX[48656c6c6f]")
	if len(got) != 1 || got[0].Password != "Hello" {
		t.Fatalf("hex password not decoded: %+v", got)
	}
}

// --- ParseUncracked ---

func uncracked(t *testing.T, lines ...string) []ParsedAccount {
	t.Helper()
	accts, err := ParseUncracked(strings.NewReader(strings.Join(lines, "\n")+"\n"), "CORP.INT")
	if err != nil {
		t.Fatal(err)
	}
	return accts
}

func TestParseUncrackedSecretsDump(t *testing.T) {
	got := uncracked(t, "dave:1004:aad3b435b51404eeaad3b435b51404ee:uncrackedntlm:::")
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	a := got[0]
	if a.Username != "dave" || a.Hash != "uncrackedntlm" || a.Password != "" || a.Cracked {
		t.Fatalf("unexpected: %+v", a)
	}
}

func TestParseUncrackedSimpleFormat(t *testing.T) {
	got := uncracked(t, "frank:defhash")
	if len(got) != 1 || got[0].Username != "frank" || got[0].Hash != "defhash" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestParseSkipsBlankAndMalformedLines(t *testing.T) {
	got := cracked(t, "", "   ", "too:few", "eve:hash:pw")
	if len(got) != 1 || got[0].Username != "eve" {
		t.Fatalf("expected only the valid line, got %+v", got)
	}
}

func TestCrackMap(t *testing.T) {
	lines := []string{
		"alice:aabbccddeeff00112233445566778899:Summer2024!",    // user:hash:password
		"bob:ccddeeff00112233445566778899aabb:p@ss:with:colons", // password contains ':'
		"deadbeefdeadbeefdeadbeefdeadbeef:PotfilePw",            // bare potfile hash:password
		"WK01$:1111111111111111:MachinePw",                      // machine account -> skipped
		"svc2:31D6CFE0D16AE931B73C59D7E0C089C0:Ignored",         // empty-NT hash -> excluded
	}
	m, err := CrackMap(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if m["AABBCCDDEEFF00112233445566778899"] != "Summer2024!" {
		t.Fatalf("user:hash:password not mapped: %v", m)
	}
	if m["CCDDEEFF00112233445566778899AABB"] != "p@ss:with:colons" {
		t.Fatalf("colon password not preserved: %q", m["CCDDEEFF00112233445566778899AABB"])
	}
	if m["DEADBEEFDEADBEEFDEADBEEFDEADBEEF"] != "PotfilePw" {
		t.Fatalf("bare potfile line not mapped: %v", m)
	}
	if _, ok := m["31D6CFE0D16AE931B73C59D7E0C089C0"]; ok {
		t.Fatal("empty-password NT hash must be excluded")
	}
	if len(m) != 3 {
		t.Fatalf("expected 3 usable cracks (machine + empty-hash dropped), got %d: %v", len(m), m)
	}
}
