package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

// openOrNewTokenStore loads the tokens file, or starts an empty store if absent.
func openOrNewTokenStore(path string) (*auth.TokenStore, error) {
	if st, err := auth.OpenTokenStore(path); err == nil {
		return st, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return auth.NewTokenStore(path, nil), nil
}

// createToken mints a token in the file and returns the full secret string (once).
func createToken(path, role, label, expires string) (string, error) {
	st, err := openOrNewTokenStore(path)
	if err != nil {
		return "", err
	}
	exp, err := auth.ParseExpiry(expires)
	if err != nil {
		return "", err
	}
	full, _, err := st.Issue(auth.Role(role), label, exp)
	return full, err
}

func revokeToken(path, id string) bool {
	st, err := auth.OpenTokenStore(path)
	if err != nil {
		return false
	}
	return st.Revoke(id)
}

// runToken implements `patd token <create|list|revoke> ...`.
func runToken(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: patd token <create|list|revoke> [flags]")
		os.Exit(2)
	}
	defaultPath := env("PATD_MCP_TOKENS_FILE", "mcp_tokens.json")
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		role := fs.String("role", "analyst", "token role: analyst|lead")
		label := fs.String("label", "", "human label (required)")
		expires := fs.String("expires", "", "optional expiry: duration (720h) or RFC3339")
		file := fs.String("file", defaultPath, "tokens file")
		_ = fs.Parse(args[1:])
		if *label == "" {
			fmt.Fprintln(os.Stderr, "--label is required")
			os.Exit(2)
		}
		full, err := createToken(*file, *role, *label, *expires)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create failed:", err)
			os.Exit(1)
		}
		if auth.Role(*role) == auth.RoleLead {
			fmt.Fprintln(os.Stderr, "WARNING: a lead token can reveal AD cleartext via the MCP reveal tool.")
		}
		fmt.Println(full)
		fmt.Fprintln(os.Stderr, "^ copy this now -- it will not be shown again.")
	case "list":
		fs := flag.NewFlagSet("token list", flag.ExitOnError)
		file := fs.String("file", defaultPath, "tokens file")
		_ = fs.Parse(args[1:])
		st, err := openOrNewTokenStore(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read tokens:", err)
			os.Exit(1)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tROLE\tLABEL\tCREATED\tLAST USED\tSTATUS")
		for _, tk := range st.List() {
			status := "active"
			if tk.Disabled {
				status = "disabled"
			} else if tk.Expires != nil && tk.Expires.Before(time.Now()) {
				status = "expired"
			}
			last := "never"
			if tk.LastUsed != nil {
				last = tk.LastUsed.Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", tk.ID, tk.Role, tk.Label, tk.Created.Format("2006-01-02"), last, status)
		}
		_ = tw.Flush()
	case "revoke":
		fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
		file := fs.String("file", defaultPath, "tokens file")
		_ = fs.Parse(args[1:])
		rest := fs.Args()
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: patd token revoke <id>")
			os.Exit(2)
		}
		if !revokeToken(*file, rest[0]) {
			fmt.Fprintln(os.Stderr, "no such token:", rest[0])
			os.Exit(1)
		}
		fmt.Println("revoked", rest[0])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", args[0])
		os.Exit(2)
	}
}
