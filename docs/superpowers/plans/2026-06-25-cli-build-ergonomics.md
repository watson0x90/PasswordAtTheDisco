# CLI & Build Ergonomics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `patd` a help menu and `--version`, server `--addr`/`--port` flags, `patd user add/passwd/list` subcommands, canonical cross-platform build scripts that stamp the version, and a README documenting the full build/run/first-run flow.

**Architecture:** Pure-function cores (`resolveAddr`, `readPassword`, `addUser`/`setUserPassword`/`listUsers`, `serverIsRunning`) are unit-tested in isolation; `main()` and `runUser()` are thin wiring over them (flag parsing, stdin, `os.Exit`, printing). The `user` subcommand reuses the existing `auth.UserStore` (same `users.json` the server owns), mirroring the existing `token` subcommand pattern. Build scripts stamp `main.version/commit/buildDate` via `-ldflags -X` at compile time; nothing at runtime depends on them.

**Tech Stack:** Go 1.26 stdlib (`flag`, `net`, `text/tabwriter`), the existing `internal/auth.UserStore`. Bash + PowerShell build scripts. Gates: `gofmt -l cmd internal`, `go build/vet/test ./...`.

**Spec:** `docs/superpowers/specs/2026-06-25-cli-build-ergonomics-design.md`

**Working directory:** repo root `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\cli-build-ergonomics`. Run `go` commands from there.

**Commit hygiene:** stage explicit paths only — **NEVER `git add -A` / `git add .`** (the tree carries gitignored data and skip-worktree pinned files). Let hooks run (no `--no-verify`).

---

## Reference: existing code these tasks build on (verified)

- `cmd/patd/main.go` — `main()` dispatches `os.Args[1]` (`hashpw`/`audit`/`reindex`/`token`), then runs the server starting at `addr := env("PATD_ADDR", "127.0.0.1:8443")` (line 75). `hashpw()` (line 268) reads a password from stdin (stderr prompt, `bufio` line read, trim, reject empty). Helpers `env(key, def string) string` (line 320) and `envInt` (line 327).
- `cmd/patd/token.go` — `runToken(args []string)` with `flag.NewFlagSet` per verb and an `openOrNewTokenStore(path)` helper (open, or `NewTokenStore` if `os.IsNotExist`). This is the pattern `runUser` mirrors.
- `internal/auth` — `Role` is `RoleAnalyst`/`RoleLead`; `OpenUserStore(path) (*UserStore, error)` (errors if the file is absent — `os.IsNotExist`); `NewUserStore(path string, users Users) *UserStore`; methods `Create(username, password string, role Role) error`, `SetPassword(username, password string) error`, `List() []Info`, `Count() int`. `Info{Username string; Role Role; Disabled bool}`. Errors: `ErrUserExists`, `ErrUserNotFound`, `ErrWeakPassword` (password `< minOperatorPassword`, which is `8`). `Create` validates the role and rejects duplicates/short passwords; `SetPassword` returns `ErrUserNotFound` for an unknown user.

---

## Task 1: `readPassword` helper + refactor `hashpw`

Extract the stdin password read into a reader-injectable helper so `hashpw`, `user add`, and `user passwd` share one implementation and it's unit-testable.

**Files:**
- Modify: `cmd/patd/main.go` (add `readPassword`, refactor `hashpw`)
- Test: `cmd/patd/cli_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `cmd/patd/cli_test.go`:

```go
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/patd/ -run TestReadPassword -v`
Expected: FAIL — `undefined: readPassword`.

- [ ] **Step 3: Add `readPassword` and refactor `hashpw`**

In `cmd/patd/main.go`, add the helper (place it just above `func hashpw()` at line 268). Ensure `bufio`, `errors`, `fmt`, `io`, `os`, `strings` are imported (all but `errors`/`io` already are — add `errors` and `io`):

```go
// readPassword prompts on stderr and reads a single line from in, trimming the
// trailing newline. Shared by hashpw and the `user` subcommands. Reading from a
// reader (not os.Stdin directly) keeps it unit-testable and pipeable for automation.
func readPassword(in io.Reader, prompt string) (string, error) {
	if prompt != "" {
		fmt.Fprint(os.Stderr, prompt)
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", errors.New("empty password")
	}
	return pw, nil
}
```

Then replace the body of `hashpw()` (lines 268-282) with:

```go
func hashpw() {
	pw, err := readPassword(os.Stdin, "Password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(h)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./cmd/patd/ -run TestReadPassword -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Verify the package still builds and gofmt is clean**

Run: `gofmt -l cmd/patd/ && go build ./cmd/patd/`
Expected: no output from gofmt, build succeeds.

- [ ] **Step 6: Commit**

```bash
git add cmd/patd/main.go cmd/patd/cli_test.go
git commit -m "refactor(cli): extract readPassword helper shared by hashpw + user cmds"
```

---

## Task 2: `resolveAddr` + server `--addr`/`--port` flags

Add a pure `resolveAddr` (flag > `PATD_ADDR` env > default) and wire `--addr`/`--port` flags into the server startup path, rejecting unknown args.

**Files:**
- Modify: `cmd/patd/main.go` (`resolveAddr`; server-path flag parsing replacing line 75)
- Test: `cmd/patd/cli_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/patd/cli_test.go`:

```go
func TestResolveAddr(t *testing.T) {
	cases := []struct {
		name, addrFlag, portFlag, envAddr, want string
		wantErr                                  bool
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/patd/ -run TestResolveAddr -v`
Expected: FAIL — `undefined: resolveAddr`.

- [ ] **Step 3: Implement `resolveAddr`**

In `cmd/patd/main.go`, add (near the `env` helper at line 320). Ensure `strconv` is imported:

```go
// resolveAddr picks the server listen address. Precedence: an explicit --addr or
// --port flag, then the PATD_ADDR env value, then the loopback default. --addr and
// --port are mutually exclusive; --port is shorthand for 127.0.0.1:<port>. Empty
// strings mean "unset".
func resolveAddr(addrFlag, portFlag, envAddr string) (string, error) {
	if addrFlag != "" && portFlag != "" {
		return "", errors.New("use --addr or --port, not both")
	}
	if addrFlag != "" {
		return addrFlag, nil
	}
	if portFlag != "" {
		if _, err := strconv.Atoi(portFlag); err != nil {
			return "", fmt.Errorf("invalid --port %q", portFlag)
		}
		return "127.0.0.1:" + portFlag, nil
	}
	if envAddr != "" {
		return envAddr, nil
	}
	return "127.0.0.1:8443", nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./cmd/patd/ -run TestResolveAddr -v`
Expected: PASS (all sub-cases).

- [ ] **Step 5: Wire the flags into the server path**

In `cmd/patd/main.go`, replace the single line (currently line 75):

```go
	addr := env("PATD_ADDR", "127.0.0.1:8443")
```

with the flag-parsing block (this runs only when no subcommand matched — `audit`/`token`/etc. already `return` inside the switch above):

```go
	fs := flag.NewFlagSet("patd", flag.ExitOnError)
	addrFlag := fs.String("addr", "", "listen address host:port (overrides PATD_ADDR)")
	portFlag := fs.String("port", "", "listen port, bound to 127.0.0.1 (overrides PATD_ADDR)")
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unknown command %q (try 'patd --help')\n", fs.Arg(0))
		os.Exit(2)
	}
	addr, err := resolveAddr(*addrFlag, *portFlag, os.Getenv("PATD_ADDR"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
```

Ensure `flag` is imported. This block references no symbols from later tasks, so the package compiles after this task.

NOTE: There is an existing later line `dataDir := env("PATD_DATA", "data")` and similar — do **not** touch those. Only the `PATD_ADDR` line changes. The downstream `addr` usages (`srv.Addr`, `isLoopbackAddr(addr)`) are unchanged.

- [ ] **Step 6: Build + gofmt**

Run: `gofmt -l cmd/patd/ && go build ./cmd/patd/`
Expected: clean (assuming Task 3's `usage` const exists; otherwise do Task 3 first).

- [ ] **Step 7: Commit**

```bash
git add cmd/patd/main.go cmd/patd/cli_test.go
git commit -m "feat(cli): --addr/--port flags for the server listen address"
```

---

## Task 3: `help` + `--version` front door

Add a usage string and a version line, and intercept `help`/`--help`/`-h` and `--version`/`-v`/`version` at the top of the dispatch.

**Files:**
- Modify: `cmd/patd/main.go` (`usage` const, `versionLine()`, switch cases)
- Test: `cmd/patd/cli_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/patd/cli_test.go`:

```go
func TestUsageMentionsCommandsAndFlags(t *testing.T) {
	for _, want := range []string{"user", "token", "audit", "reindex", "hashpw", "--addr", "--port", "--version", "PATD_DATA", "PATD_USERS_FILE"} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestVersionLine(t *testing.T) {
	// version/commit/buildDate default to dev/none/unknown in an unstamped test build.
	got := versionLine()
	for _, want := range []string{"patd", version, commit, buildDate} {
		if !strings.Contains(got, want) {
			t.Errorf("versionLine %q missing %q", got, want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/patd/ -run 'TestUsage|TestVersionLine' -v`
Expected: FAIL — `undefined: usage` / `undefined: versionLine`.

- [ ] **Step 3: Add the usage const and versionLine**

In `cmd/patd/main.go`, add near the top-level declarations (after the `var ( version … )` block at line ~54):

```go
const usage = `patd — Password!AtTheDisco: AD password-exposure auditing console.

Usage:
  patd [--addr host:port | --port N]   Run the server (default; 127.0.0.1:8443).
  patd user <add|passwd|list> ...      Manage operators (see 'patd user').
  patd token <create|list|revoke> ...  Manage MCP API tokens.
  patd audit ...                       Run an audit from the CLI.
  patd reindex                         Rebuild the encrypted index from audit blobs.
  patd hashpw                          Hash a password from stdin (prints the PHC string).
  patd --version | -v                  Print version and exit.
  patd help | --help | -h              Print this help.

Server flags:
  --addr host:port   Full bind address (overrides PATD_ADDR).
  --port N           Bind 127.0.0.1:N (overrides PATD_ADDR).

Key environment variables (see README.md for the full list):
  PATD_DATA          Encrypted store directory (default: data).
  PATD_USERS_FILE    Operators file (default: users.json).
  PATD_ADDR          Listen address (default: 127.0.0.1:8443).
  PATD_BHE           BloodHound enrichment config (default: config/bloodhound.json).
  PATD_TLS_CERT/_KEY TLS cert+key; required to bind a non-loopback address.
  PATD_AUDIT_LOG     Audit log file (default: stdout).`

// versionLine renders the stamped build identity (set via -ldflags -X at build time).
func versionLine() string {
	return fmt.Sprintf("patd %s (%s, built %s)", version, commit, buildDate)
}
```

- [ ] **Step 4: Add the dispatch cases**

In `cmd/patd/main.go`, inside the `switch os.Args[1]` (starting line 59), add these cases (alongside the existing `hashpw`/`audit`/`reindex`/`token` cases). Do NOT add the `user` case here — it is added in Task 4 when `runUser` exists, so the package keeps compiling after this task:

```go
		case "help", "--help", "-h":
			fmt.Println(usage)
			return
		case "--version", "-v", "version":
			fmt.Println(versionLine())
			return
```

- [ ] **Step 5: Run the tests**

Run: `go test ./cmd/patd/ -run 'TestUsage|TestVersionLine' -v`
Expected: PASS.

- [ ] **Step 6: Build + gofmt**

Run: `gofmt -l cmd/patd/ && go build ./cmd/patd/`
Expected: clean — this task references no later-task symbols (the `user` dispatch case is added in Task 4).

- [ ] **Step 7: Commit**

```bash
git add cmd/patd/main.go cmd/patd/cli_test.go
git commit -m "feat(cli): help menu + --version"
```

---

## Task 4: `patd user add/passwd/list` + running-server guard

Add the `user` subcommand with testable core functions and a best-effort running-server guard.

**Files:**
- Create: `cmd/patd/user.go`
- Test: `cmd/patd/user_test.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/patd/user_test.go`:

```go
package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func tempUsersFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "users.json")
}

func TestAddUser_CreatesOperator(t *testing.T) {
	f := tempUsersFile(t)
	if err := addUser(f, "alice", "longpassword", "lead"); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	st, err := auth.OpenUserStore(f)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := st.Authenticate("alice", "longpassword"); !ok {
		t.Fatal("alice cannot authenticate with the set password")
	}
	got := st.List()
	if len(got) != 1 || got[0].Username != "alice" || got[0].Role != auth.RoleLead {
		t.Fatalf("List = %+v, want one alice/lead", got)
	}
}

func TestAddUser_DuplicateAndWeak(t *testing.T) {
	f := tempUsersFile(t)
	if err := addUser(f, "ana", "longpassword", "analyst"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := addUser(f, "ana", "longpassword", "analyst"); err != auth.ErrUserExists {
		t.Fatalf("duplicate = %v, want ErrUserExists", err)
	}
	if err := addUser(f, "bob", "short", "analyst"); err != auth.ErrWeakPassword {
		t.Fatalf("weak = %v, want ErrWeakPassword", err)
	}
	if err := addUser(f, "bad", "longpassword", "wizard"); err == nil {
		t.Fatal("invalid role: want error, got nil")
	}
}

func TestSetUserPassword(t *testing.T) {
	f := tempUsersFile(t)
	if err := addUser(f, "alice", "oldpassword", "lead"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := setUserPassword(f, "alice", "newpassword"); err != nil {
		t.Fatalf("setUserPassword: %v", err)
	}
	st, _ := auth.OpenUserStore(f)
	if _, ok := st.Authenticate("alice", "newpassword"); !ok {
		t.Fatal("new password does not authenticate")
	}
	if _, ok := st.Authenticate("alice", "oldpassword"); ok {
		t.Fatal("old password still authenticates")
	}
	if err := setUserPassword(f, "ghost", "longpassword"); err != auth.ErrUserNotFound {
		t.Fatalf("unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestListUsers(t *testing.T) {
	f := tempUsersFile(t)
	_ = addUser(f, "alice", "longpassword", "lead")
	_ = addUser(f, "bob", "longpassword", "analyst")
	got, err := listUsers(f)
	if err != nil {
		t.Fatalf("listUsers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listUsers len = %d, want 2", len(got))
	}
}

func TestServerIsRunning(t *testing.T) {
	// A free, unbound port is not running.
	if serverIsRunning("127.0.0.1:1") {
		t.Error("127.0.0.1:1 should not be reachable")
	}
	// A live listener is detected.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if !serverIsRunning(ln.Addr().String()) {
		t.Errorf("live listener %s should be detected", ln.Addr())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/patd/ -run 'TestAddUser|TestSetUserPassword|TestListUsers|TestServerIsRunning' -v`
Expected: FAIL — `undefined: addUser` / `setUserPassword` / `listUsers` / `serverIsRunning`.

- [ ] **Step 3: Implement `cmd/patd/user.go`**

Create `cmd/patd/user.go`:

```go
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
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

// setUserPassword resets an existing operator's login password.
func setUserPassword(file, username, password string) error {
	st, err := openOrNewUserStore(file)
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
		fmt.Fprintf(os.Stderr, "a server appears to be running at %s; manage operators in the UI so its in-memory copy of %s is not clobbered. Re-run with --force to edit the file anyway.\n", addr, env("PATD_USERS_FILE", "users.json"))
		os.Exit(1)
	}
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
		fs := flag.NewFlagSet("user add", flag.ExitOnError)
		role := fs.String("role", "analyst", "operator role: analyst|lead")
		force := fs.Bool("force", false, "edit the users file even if a server is running")
		file := fs.String("file", usersFile, "users file")
		_ = fs.Parse(args[1:])
		rest := fs.Args()
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: patd user add <username> [--role analyst|lead] [--force]")
			os.Exit(2)
		}
		guardServerOrExit(*force)
		pw, err := readPassword(os.Stdin, "Password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := addUser(*file, rest[0], pw, *role); err != nil {
			fmt.Fprintln(os.Stderr, "add failed:", err)
			os.Exit(1)
		}
		fmt.Printf("created operator %s (%s)\n", rest[0], *role)
	case "passwd":
		fs := flag.NewFlagSet("user passwd", flag.ExitOnError)
		force := fs.Bool("force", false, "edit the users file even if a server is running")
		file := fs.String("file", usersFile, "users file")
		_ = fs.Parse(args[1:])
		rest := fs.Args()
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: patd user passwd <username> [--force]")
			os.Exit(2)
		}
		guardServerOrExit(*force)
		pw, err := readPassword(os.Stdin, "New password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := setUserPassword(*file, rest[0], pw); err != nil {
			fmt.Fprintln(os.Stderr, "passwd failed:", err)
			os.Exit(1)
		}
		fmt.Printf("password updated for %s\n", rest[0])
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
```

- [ ] **Step 4: Ensure the `user` dispatch case exists in main.go**

If not already added in Task 3, add to the `switch os.Args[1]` in `cmd/patd/main.go`:

```go
		case "user":
			runUser(os.Args[2:])
			return
```

- [ ] **Step 5: Run the tests**

Run: `go test ./cmd/patd/ -run 'TestAddUser|TestSetUserPassword|TestListUsers|TestServerIsRunning' -v`
Expected: PASS (all).

- [ ] **Step 6: Full package gates**

Run: `gofmt -l cmd/patd/ && go vet ./cmd/patd/ && go test ./cmd/patd/`
Expected: gofmt clean, vet clean, all tests pass.

- [ ] **Step 7: Commit**

```bash
git add cmd/patd/user.go cmd/patd/user_test.go cmd/patd/main.go
git commit -m "feat(cli): patd user add/passwd/list with running-server guard"
```

---

## Task 5: Cross-platform build scripts

Create `scripts/build.sh` and `scripts/build.ps1` — behavior-identical stamped embed builds.

**Files:**
- Create: `scripts/build.sh`
- Create: `scripts/build.ps1`

- [ ] **Step 1: Create `scripts/build.sh`**

```bash
#!/usr/bin/env bash
# Build a stamped, self-contained patd binary (Go API + embedded React SPA).
# Cross-platform: Linux, macOS, and Windows via Git Bash. Never runs `npm install`.
#
#   scripts/build.sh                 # build SPA + embed + stamped binary
#   scripts/build.sh --skip-web      # reuse existing web/dist
#   scripts/build.sh --output bin/patd
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKIP_WEB=0
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-web) SKIP_WEB=1; shift ;;
    --output) OUT="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Default output name: patd.exe on Windows (Git Bash), patd elsewhere.
if [ -z "$OUT" ]; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) OUT="patd.exe" ;;
    *) OUT="patd" ;;
  esac
fi

if [ "$SKIP_WEB" -eq 0 ]; then
  if [ ! -d web/node_modules ]; then
    echo "ERROR: web/node_modules missing — run 'cd web && npm install' once first." >&2
    exit 1
  fi
  echo "==> building SPA (npm run build)"
  ( cd web && npm run build )
fi

if [ ! -d web/dist ]; then
  echo "ERROR: web/dist missing — run without --skip-web to build the SPA first." >&2
  exit 1
fi

echo "==> embedding SPA (internal/webui/dist <- web/dist)"
rm -rf internal/webui/dist
cp -r web/dist internal/webui/dist

VERSION="$(git describe --tags --always)"
COMMIT="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==> stamping version=$VERSION commit=$COMMIT date=$BUILD_DATE"

CGO_ENABLED=0 go build -tags embed -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
  -o "$OUT" ./cmd/patd

echo "==> built $OUT ($VERSION / $COMMIT)"
```

- [ ] **Step 2: Create `scripts/build.ps1`**

```powershell
# Build a stamped, self-contained patd.exe (Go API + embedded React SPA) on Windows.
# Never runs `npm install`.
#
#   scripts\build.ps1                  # build SPA + embed + stamped binary
#   scripts\build.ps1 -SkipWeb         # reuse existing web\dist
#   scripts\build.ps1 -Output bin\patd.exe
param(
  [switch]$SkipWeb,
  [string]$Output = "patd.exe"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $root

if (-not $SkipWeb) {
  if (-not (Test-Path "web\node_modules")) {
    Write-Error "web\node_modules missing — run 'cd web; npm install' once first."
  }
  Write-Host "==> building SPA (npm run build)"
  Push-Location web; npm run build; if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Error "npm run build failed" }; Pop-Location
}

if (-not (Test-Path "web\dist")) {
  Write-Error "web\dist missing — run without -SkipWeb to build the SPA first."
}

Write-Host "==> embedding SPA (internal\webui\dist <- web\dist)"
Remove-Item -Recurse -Force "internal\webui\dist" -ErrorAction SilentlyContinue
Copy-Item -Recurse "web\dist" "internal\webui\dist"

$version = (git describe --tags --always)
$commit  = (git rev-parse --short HEAD)
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "==> stamping version=$version commit=$commit date=$buildDate"

$env:CGO_ENABLED = "0"
$ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.buildDate=$buildDate"
go build -tags embed -trimpath -ldflags="$ldflags" -o $Output ./cmd/patd
if ($LASTEXITCODE -ne 0) { Write-Error "go build failed" }

Write-Host "==> built $Output ($version / $commit)"
```

- [ ] **Step 3: Verify `build.sh` runs and stamps the version**

Run (from repo root, in Git Bash): `bash scripts/build.sh --skip-web`
Expected: it embeds the existing `web/dist`, prints `==> built patd.exe (<version> / <commit>)` where `<version>` is the `git describe` output (e.g. `v2.30.0-...`). If `web/dist` is missing, first run `bash scripts/build.sh` (which builds the SPA — requires `web/node_modules` present; this repo has it junctioned).

Note: if a server is already running from `patd.exe`, the build will fail to overwrite the locked file on Windows — pass `--output patd-new.exe` or stop the server first.

- [ ] **Step 4: Confirm the stamp landed**

Run (Git Bash): `./patd.exe --version`
Expected: `patd v2.30.0-... (<commit>, built <date>)` — NOT `patd dev (none, built unknown)`.

- [ ] **Step 5: Commit**

```bash
git add scripts/build.sh scripts/build.ps1
git commit -m "build: cross-platform stamped build scripts (build.sh + build.ps1)"
```

---

## Task 6: README build/run/first-run documentation

Document the full build, run, and first-run flow. Read the current `README.md` first and insert these sections where they fit the existing structure (likely after an intro/quickstart; keep the existing headings' style).

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the current README to find the insertion point**

Run: `sed -n '1,40p' README.md` (and skim for an existing "Build"/"Quickstart"/"Running" heading to replace or extend).

- [ ] **Step 2: Add/replace the Build, Run, First-run, and Help sections**

Insert this Markdown (adapt the heading level to match the file; if a "Build" section already exists, replace its body):

````markdown
## Build

**Prerequisites:** Go 1.26+, and Node 20+ for the web UI.

```bash
# one-time: install the SPA's dependencies
cd web && npm install && cd ..

# build a stamped, self-contained binary (Go API + embedded React SPA)
scripts/build.sh            # Linux / macOS / Windows (Git Bash)
# or, on Windows PowerShell:
scripts\build.ps1
```

This builds the SPA, embeds it, stamps the version from `git describe`, and produces
`patd` (`patd.exe` on Windows). Flags: `--skip-web` (reuse the existing `web/dist`),
`--output <path>` (`-SkipWeb` / `-Output` in PowerShell).

Confirm the stamp:

```bash
./patd --version          # patd v2.30.0 (abc1234, built 2026-06-25T...Z)
```

**Dev build (no version stamp, SPA served from disk):** `go run ./cmd/patd` serves
`web/dist` from disk and reports `version=dev`. Use the build scripts for a real,
embedded, versioned binary.

## Run

```bash
patd                       # 127.0.0.1:8443 (default)
patd --port 9000           # 127.0.0.1:9000
patd --addr 0.0.0.0:8443   # bind all interfaces (requires TLS, see below)
PATD_ADDR=127.0.0.1:9000 patd
```

Precedence is `--addr`/`--port` flag → `PATD_ADDR` → default `127.0.0.1:8443`. Binding a
non-loopback address requires TLS — set `PATD_TLS_CERT` and `PATD_TLS_KEY`, or the server
refuses to serve plaintext off loopback. `patd --help` lists all flags and key env vars.

## First run — operators

Bootstrap the first lead operator, then start the server and log in:

```bash
patd user add admin --role lead     # prompts for a password (stdin)
patd user list                      # USERNAME  ROLE  STATUS
patd user passwd admin              # reset a password
```

While the server is running it owns `users.json` — add or edit operators in the **UI**
(Admin → Operators), not the CLI. The CLI refuses to edit the file when it detects a
running server; pass `--force` to override (last resort; can clobber the server's copy).
````

- [ ] **Step 3: Verify the README renders / has no broken fences**

Run: `grep -c '```' README.md`
Expected: an even number (all code fences balanced).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README build/run/first-run + operator CLI"
```

---

## Task 7: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Full gates**

Run (repo root):
```
gofmt -l cmd internal
go build ./...
go vet ./...
go test ./...
```
Expected: gofmt prints nothing; build/vet succeed; all tests pass (including the new `cmd/patd` tests).

- [ ] **Step 2: Smoke-test the CLI on the freshly built binary**

Run (Git Bash):
```
./patd.exe --version
./patd.exe --help
./patd.exe user add smoketest --role analyst   # type a >=8-char password at the prompt
./patd.exe user list
```
Expected: version line shows the git-described version; help prints the usage block; `user add` prints `created operator smoketest (analyst)`; `user list` shows `smoketest analyst enabled`. (Use a throwaway `PATD_USERS_FILE`, e.g. `PATD_USERS_FILE=/tmp/smoke-users.json`, so you don't touch the real `users.json`.)

- [ ] **Step 3: Verify the port flag binds**

Run (Git Bash), against a throwaway data dir so nothing real is touched:
```
PATD_DATA=/tmp/smoke-data PATD_USERS_FILE=/tmp/smoke-users.json ./patd.exe --port 8600 &
sleep 1
curl -s http://127.0.0.1:8600/api/version
kill %1
```
Expected: the `/api/version` JSON responds on port 8600 (proving `--port` took effect), then the server stops.

- [ ] **Step 4: Confirm the guard refuses an edit while the server is up**

With a server still running on the default `PATD_ADDR` (start one on `127.0.0.1:8443` if needed), run:
```
./patd.exe user add blocked --role analyst
```
Expected: exits non-zero with the "a server appears to be running … Re-run with --force" message, and does NOT prompt for a password.

---

## Self-Review

**1. Spec coverage:**
- `help` + `--version` → Task 3. ✅
- `--addr` / `--port` (flag > env > default, mutually exclusive) → Task 2. ✅
- `patd user add/passwd/list` + running-server guard + `--force` → Task 4. ✅
- `scripts/build.sh` + `scripts/build.ps1` (web build, embed, stamp, never auto-install) → Task 5. ✅
- README Build/Run/First-run/Help → Task 6. ✅
- `readPassword` shared by `hashpw` + `user` (stdin, no new dep) → Task 1. ✅
- Testing (resolveAddr, user verbs, serverIsRunning, version/help, readPassword) → Tasks 1–4 + Task 7 gates. ✅

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to Task N" — every code step is complete. There are **no cross-task forward references**: Task 2's unknown-arg branch prints a literal message (no `usage`), Task 3 adds `help`/`--version` only (the `user` dispatch case is deferred to Task 4 where `runUser` exists), so the package compiles after every task. ✅

**3. Type consistency:** `resolveAddr(addrFlag, portFlag, envAddr string) (string, error)`, `readPassword(in io.Reader, prompt string) (string, error)`, `addUser(file, username, password, role string) error`, `setUserPassword(file, username, password string) error`, `listUsers(file string) ([]auth.Info, error)`, `serverIsRunning(addr string) bool`, `versionLine() string`, `usage` (const) — names/signatures consistent across all tasks. Roles passed as strings to `auth.Role(...)`; `auth.UserStore` methods (`Create`/`SetPassword`/`List`) and errors (`ErrUserExists`/`ErrUserNotFound`/`ErrWeakPassword`) match the verified API. ✅
