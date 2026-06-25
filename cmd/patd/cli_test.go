package main

import (
	"strings"
	"testing"
)

func TestReadPassword(t *testing.T) {
	got, err := readPassword(strings.NewReader("hunter2\n"), "")
	if err != nil || got != "hunter2" {
		t.Fatalf("got (%q, %v), want (hunter2, nil)", got, err)
	}
}

func TestReadPassword_NoTrailingNewline(t *testing.T) {
	got, err := readPassword(strings.NewReader("hunter2"), "")
	if err != nil || got != "hunter2" {
		t.Fatalf("got (%q, %v), want (hunter2, nil)", got, err)
	}
}

func TestReadPassword_Empty(t *testing.T) {
	if _, err := readPassword(strings.NewReader("\n"), ""); err == nil {
		t.Fatal("empty input: want error, got nil")
	}
}
