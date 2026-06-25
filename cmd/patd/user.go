package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

// openOrNewUserStore loads the operators file, or starts an empty store if absent
// (so `user add` can bootstrap the very first operator).
func openOrNewUserStore(path string) (*auth.UserStore, error) {
	if st, err := auth.OpenUserStore(path); err == nil {
		return st, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return auth.NewUserStore(path, nil), nil
}

// addUser creates an operator in the users file (creating the file if needed).
func addUser(file, username, password, role string) error {
	st, err := openOrNewUserStore(file)
	if err != nil {
		return err
	}
	return st.Create(username, password, auth.Role(role))
}

// setUserPassword resets an existing operator's login password. Unlike add, it does
// not bootstrap a missing file — opening a non-existent users file surfaces a clear
// "no such file" error rather than a misleading "no such operator".
func setUserPassword(file, username, password string) error {
	st, err := auth.OpenUserStore(file)
	if err != nil {
		return err
	}
	return st.SetPassword(username, password)
}

// listUsers returns the redacted operator list (no password hashes).
func listUsers(file string) ([]auth.Info, error) {
	st, err := openOrNewUserStore(file)
	if err != nil {
		return nil, err
	}
	return st.List(), nil
}

// serverIsRunning reports whether something is listening at addr. Best-effort: a
// reachable port is the signal that a live server may own the users file.
func serverIsRunning(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// guardServerOrExit refuses a mutating user edit when a server is reachable, unless
// forced. The running server owns users.json in memory; editing the file underneath
// it can be clobbered on its next write — manage operators in the UI instead.
func guardServerOrExit(force bool) {
	if force {
		return
	}
	addr := env("PATD_ADDR", "127.0.0.1:8443")
	if serverIsRunning(addr) {
		fmt.Fprintf(os.Stderr, "a server appears to be running at %s; manage operators in the UI so its in-memory copy of %s is not clobbered.\n", addr, env("PATD_USERS_FILE", "users.json"))
		fmt.Fprintln(os.Stderr, "Re-run with --force to edit the file anyway.")
		os.Exit(1)
	}
}

// splitUserArgs separates a leading <username> positional from the trailing flags,
// so `user add <name> --role lead` works (Go's flag package otherwise stops parsing
// at the first non-flag token). The username must come first; flags follow.
func splitUserArgs(args []string) (username string, flags []string, ok bool) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, false
	}
	return args[0], args[1:], true
}

// runUser implements `patd user <add|passwd|list> ...`.
func runUser(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: patd user <add|passwd|list> [flags]")
		os.Exit(2)
	}
	usersFile := env("PATD_USERS_FILE", "users.json")
	switch args[0] {
	case "add":
		username, flagArgs, ok := splitUserArgs(args[1:])
		if !ok {
			fmt.Fprintln(os.Stderr, "usage: patd user add <username> [--role analyst|lead] [--force]")
			os.Exit(2)
		}
		fs := flag.NewFlagSet("user add", flag.ExitOnError)
		role := fs.String("role", "analyst", "operator role: analyst|lead")
		force := fs.Bool("force", false, "edit the users file even if a server is running")
		file := fs.String("file", usersFile, "users file")
		_ = fs.Parse(flagArgs)
		if fs.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "usage: patd user add <username> [--role analyst|lead] [--force]")
			os.Exit(2)
		}
		guardServerOrExit(*force)
		pw, err := readPassword(os.Stdin, "Password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := addUser(*file, username, pw, *role); err != nil {
			fmt.Fprintln(os.Stderr, "add failed:", err)
			os.Exit(1)
		}
		fmt.Printf("created operator %s (%s)\n", username, *role)
	case "passwd":
		username, flagArgs, ok := splitUserArgs(args[1:])
		if !ok {
			fmt.Fprintln(os.Stderr, "usage: patd user passwd <username> [--force]")
			os.Exit(2)
		}
		fs := flag.NewFlagSet("user passwd", flag.ExitOnError)
		force := fs.Bool("force", false, "edit the users file even if a server is running")
		file := fs.String("file", usersFile, "users file")
		_ = fs.Parse(flagArgs)
		if fs.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "usage: patd user passwd <username> [--force]")
			os.Exit(2)
		}
		guardServerOrExit(*force)
		pw, err := readPassword(os.Stdin, "New password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := setUserPassword(*file, username, pw); err != nil {
			fmt.Fprintln(os.Stderr, "passwd failed:", err)
			os.Exit(1)
		}
		fmt.Printf("password updated for %s\n", username)
	case "list":
		fs := flag.NewFlagSet("user list", flag.ExitOnError)
		file := fs.String("file", usersFile, "users file")
		_ = fs.Parse(args[1:])
		infos, err := listUsers(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read operators:", err)
			os.Exit(1)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tROLE\tSTATUS")
		for _, in := range infos {
			status := "enabled"
			if in.Disabled {
				status = "disabled"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", in.Username, in.Role, status)
		}
		_ = tw.Flush()
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", args[0])
		os.Exit(2)
	}
}
