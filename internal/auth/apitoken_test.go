package auth

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if len(secret) != 52 {
		t.Fatalf("secret length = %d, want 52 (32 bytes base32 no-pad)", len(secret))
	}
	if len(id) != 16 {
		t.Fatalf("id length = %d, want 16 (10 bytes base32 no-pad)", len(id))
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

func TestVerifySecretRoundTrip(t *testing.T) {
	_, secret, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	h := hashSecret(secret)
	if !verifySecret(secret, h) {
		t.Fatal("verifySecret rejected the correct secret")
	}
	if verifySecret(secret+"x", h) {
		t.Fatal("verifySecret accepted a wrong secret")
	}
	if len(h) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h))
	}
}

func TestTokenStoreIssueVerify(t *testing.T) {
	s := NewTokenStore("", nil)
	full, rec, err := s.Issue(RoleAnalyst, "gemini", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Role != RoleAnalyst || rec.Label != "gemini" || rec.SecretHash == "" {
		t.Fatalf("bad record: %+v", rec)
	}
	got, ok := s.Verify(full)
	if !ok || got.ID != rec.ID || got.Role != RoleAnalyst {
		t.Fatalf("verify failed: %+v ok=%v", got, ok)
	}
	if _, ok := s.Verify(full + "x"); ok {
		t.Fatal("verify accepted a tampered secret")
	}
	if _, ok := s.Verify("patdmcp_unknown_secret"); ok {
		t.Fatal("verify accepted an unknown id")
	}
}

func TestTokenStoreExpiredAndDisabled(t *testing.T) {
	s := NewTokenStore("", nil)
	past := time.Now().Add(-time.Hour)
	full, _, _ := s.Issue(RoleLead, "expired", &past)
	if _, ok := s.Verify(full); ok {
		t.Fatal("expired token verified")
	}
	full2, rec2, _ := s.Issue(RoleLead, "live", nil)
	s.setDisabledForTest(rec2.ID, true)
	if _, ok := s.Verify(full2); ok {
		t.Fatal("disabled token verified")
	}
}

func TestTokenStoreListRedactedAndRevoke(t *testing.T) {
	s := NewTokenStore("", nil)
	_, rec, _ := s.Issue(RoleAnalyst, "a", nil)
	for _, info := range s.List() {
		if info.ID == rec.ID && info.Label != "a" {
			t.Fatal("list label mismatch")
		}
	}
	// TokenInfo must never carry the secret hash, even through JSON.
	if blob, _ := json.Marshal(s.List()); strings.Contains(string(blob), "secret_hash") {
		t.Fatal("List output leaked secret_hash")
	}
	if !s.Revoke(rec.ID) {
		t.Fatal("revoke of existing token returned false")
	}
	if s.Revoke(rec.ID) {
		t.Fatal("revoke of missing token returned true")
	}
	if items := s.List(); len(items) != 0 {
		t.Fatalf("expected empty list after revoke, got %d", len(items))
	}
}

func TestParseExpiry(t *testing.T) {
	if got, err := ParseExpiry(""); err != nil || got != nil {
		t.Fatalf("empty: got %v err %v, want nil,nil", got, err)
	}
	if got, err := ParseExpiry("720h"); err != nil || got == nil || !got.After(time.Now()) {
		t.Fatalf("duration: got %v err %v", got, err)
	}
	if got, err := ParseExpiry("2030-01-02T15:04:05Z"); err != nil || got == nil {
		t.Fatalf("rfc3339: got %v err %v", got, err)
	}
	if _, err := ParseExpiry("nonsense"); err == nil {
		t.Fatal("expected error for unparseable expiry")
	}
}

func TestTokenStorePersistReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	s := NewTokenStore(path, nil)
	full, _, _ := s.Issue(RoleLead, "persisted", nil)
	s2, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Verify(full); !ok {
		t.Fatal("token did not survive persist+reload")
	}
}
