package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
)

func TestParseEntries(t *testing.T) {
	got, err := parseEntries([]string{"CORP", "c.txt", "u.txt", "OTHER", "c2", "u2"})
	if err != nil || len(got) != 2 {
		t.Fatalf("parseEntries = %+v, err %v", got, err)
	}
	if got[0] != (domainEntry{"CORP", "c.txt", "u.txt"}) || got[1].Domain != "OTHER" {
		t.Fatalf("unexpected entries: %+v", got)
	}
	if _, err := parseEntries(nil); err == nil {
		t.Error("empty args should error")
	}
	if _, err := parseEntries([]string{"CORP", "c.txt"}); err == nil {
		t.Error("non-triple args should error")
	}
}

func TestPostDataset(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ingested":1}`))
	}))
	defer srv.Close()

	if err := postDataset(srv.URL, "tok", []byte(`{"accounts":[]}`), false); err != nil {
		t.Fatalf("postDataset err: %v", err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if string(gotBody) != `{"accounts":[]}` {
		t.Errorf("body = %q", gotBody)
	}

	if err := postDataset(srv.URL, "", nil, false); err == nil {
		t.Error("missing token should error")
	}
}

func TestPostDatasetNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()
	if err := postDataset(srv.URL, "bad", []byte(`{}`), false); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected a 401 error, got %v", err)
	}
}

func TestConfigured(t *testing.T) {
	if configured(bloodhound.Config{TokenID: "your-token-id-here", TokenKey: "k"}) {
		t.Error("placeholder token id should be unconfigured")
	}
	if configured(bloodhound.Config{TokenID: "real-id", TokenKey: "your-token-key-here"}) {
		t.Error("placeholder token key should be unconfigured")
	}
	if !configured(bloodhound.Config{TokenID: "real-id", TokenKey: "real-key"}) {
		t.Error("real creds should be configured")
	}
}
