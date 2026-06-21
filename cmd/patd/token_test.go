package main

import (
	"path/filepath"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func TestTokenCreateThenVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	full, err := createToken(path, "analyst", "cli-agent", "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := auth.OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Verify(full); !ok {
		t.Fatal("CLI-created token did not verify")
	}
}

func TestTokenRevokeViaHelper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	full, err := createToken(path, "lead", "doomed", "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := auth.OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := store.Verify(full)
	if !ok {
		t.Fatal("freshly created token did not verify")
	}
	if !revokeToken(path, got.ID) {
		t.Fatal("revoke returned false for an existing token")
	}
	store2, _ := auth.OpenTokenStore(path)
	if _, ok := store2.Verify(full); ok {
		t.Fatal("token still verifies after revoke")
	}
}

func TestCreateTokenBadExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	if _, err := createToken(path, "analyst", "x", "not-a-duration"); err == nil {
		t.Fatal("expected an error for an unparseable --expires")
	}
}

func TestCreateTokenBadRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	if _, err := createToken(path, "superuser", "x", ""); err == nil {
		t.Fatal("expected an error for an invalid role")
	}
}
