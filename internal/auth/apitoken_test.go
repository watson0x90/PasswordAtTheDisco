package auth

import (
	"strings"
	"testing"
)

func TestNewTokenFormatAndParse(t *testing.T) {
	id, secret, full, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(full, "patdmcp_") {
		t.Fatalf("token missing prefix: %q", full)
	}
	if full != "patdmcp_"+id+"_"+secret {
		t.Fatalf("token assembly mismatch: %q", full)
	}
	if strings.ContainsAny(id, "_") || strings.ContainsAny(secret, "_") {
		t.Fatalf("id/secret must not contain '_': id=%q secret=%q", id, secret)
	}
	gotID, gotSecret, ok := parseToken(full)
	if !ok || gotID != id || gotSecret != secret {
		t.Fatalf("parseToken round-trip failed: %q %q %v", gotID, gotSecret, ok)
	}
	if len(secret) < 40 {
		t.Fatalf("secret too short (%d), want >=40 chars of entropy", len(secret))
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "nope", "patdmcp_", "patdmcp_onlyid", "Bearer x", "patdmcp__nosecret"} {
		if _, _, ok := parseToken(bad); ok {
			t.Errorf("parseToken(%q) accepted a malformed token", bad)
		}
	}
}

func TestHashSecretDeterministic(t *testing.T) {
	if hashSecret("abc") != hashSecret("abc") {
		t.Fatal("hashSecret not deterministic")
	}
	if hashSecret("abc") == hashSecret("abd") {
		t.Fatal("hashSecret collision on different inputs")
	}
	if len(hashSecret("abc")) != 64 {
		t.Fatal("hashSecret not 64 hex chars")
	}
}
