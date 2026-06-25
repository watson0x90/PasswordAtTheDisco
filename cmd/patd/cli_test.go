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

func TestResolveAddr(t *testing.T) {
	cases := []struct {
		name, addrFlag, portFlag, envAddr, want string
		wantErr                                 bool
	}{
		{name: "default", want: "127.0.0.1:8443"},
		{name: "env", envAddr: "0.0.0.0:9000", want: "0.0.0.0:9000"},
		{name: "addr flag beats env", addrFlag: "1.2.3.4:80", envAddr: "9.9.9.9:1", want: "1.2.3.4:80"},
		{name: "port flag beats env", portFlag: "9000", envAddr: "9.9.9.9:1", want: "127.0.0.1:9000"},
		{name: "both flags error", addrFlag: "a:1", portFlag: "9000", wantErr: true},
		{name: "bad port error", portFlag: "notanum", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveAddr(c.addrFlag, c.portFlag, c.envAddr)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, c.want)
			}
		})
	}
}
