# CLI & build ergonomics — design

**Date:** 2026-06-25
**Owner:** watson0x90
**Status:** approved (brainstorm) → ready for implementation plan

## Goal

Make `patd` pleasant to build and operate from a terminal: a real help menu and
`--version`, a `--port`/`--addr` flag for the listen address, CLI subcommands to
bootstrap and manage operators (`patd user add` / `passwd` / `list`), canonical
cross-platform build scripts that stamp the version into the binary, and a README
that documents the full build + run + first-run flow.

## Why

Today the only way to discover how to run `patd` is to read the source: there is no
`help`, no `--version`, and the listen address is reachable only via the `PATD_ADDR`
env var. Bootstrapping the first operator means hand-running `patd hashpw` and editing
`users.json` by hand. A correctly-versioned binary requires remembering a long
`-ldflags` incantation, and there is no committed, cross-platform build script. This
work closes those ergonomics gaps without changing the server's behavior or security
model.

## Scope (settled in brainstorm)

Five parts, one cohesive feature:

1. **`help` + `--version`** front door on the CLI.
2. **`--addr` / `--port`** flags for the server listen address.
3. **`patd user` subcommands** — `add`, `passwd`, `list` — with running-server detection.
4. **Cross-platform build scripts** — `scripts/build.sh` (Linux/Mac) + `scripts/build.ps1` (Windows).
5. **README.md** — full build / run / first-run documentation.

Out of scope: a `patd build-web` subcommand (the build scripts own the web build; the
binary stays Node-free at runtime); changing the auth/session/redaction model; changing
the existing `audit` / `reindex` / `token` / `hashpw` subcommands beyond wiring them into
the new help text.

## Current state (what we build on)

- `cmd/patd/main.go` dispatches on `os.Args[1]` (`hashpw`, `audit`, `reindex`, `token`);
  any other invocation runs the server. There is no `help`, no `--version`, no flags.
- Build identity lives in `cmd/patd/main.go` as `var ( version = "dev"; commit = "none";
  buildDate = "unknown" )`, injected via `-ldflags -X main.version/commit/buildDate`.
- The server reads config from env: `PATD_ADDR` (default `127.0.0.1:8443`), `PATD_DATA`,
  `PATD_USERS_FILE` (default `users.json`), `PATD_BHE`, `PATD_TLS_CERT`/`_KEY`, etc.
  `isLoopbackAddr` refuses plain HTTP on a non-loopback address without TLS certs.
- Operators: `auth.OpenUserStore(path)` opens a persistent `UserStore` over `users.json`;
  the server calls `s.Users.Create(username, password, role)`, `s.Users.SetPassword(user,
  pw)`, `s.Users.SetRole`, `s.Users.SetDisabled`, `s.Users.Count`, and lists users for the
  UI. Roles are `auth.RoleAnalyst` / `auth.RoleLead` (`validRole`). The UI/API already does
  live user management with no restart, so the running server owns `users.json` in memory.
- `hashpw` reads a password from **stdin** (prompt on stderr, `bufio` line read, trim),
  which is pipeable (`tools/dev_seed.sh` pipes into it). `reindex` reads the store
  passphrase from stdin the same way.
- `token.go` implements `token create|list|revoke` via `flag.NewFlagSet` per subcommand —
  the pattern the new `user` subcommands mirror.
- The existing `.claude/skills/build-and-run/scripts/build.sh` (+ `restart.ps1`) is the
  agent-loop helper and stays as-is; the new `scripts/` are the canonical project scripts.

## Architecture

### 1. `help` + `--version`

In `cmd/patd/main.go`, before the existing `os.Args[1]` switch, intercept the front-door
tokens:

- `help`, `--help`, `-h` → print usage to stdout and exit 0.
- `--version`, `-v`, `version` → print `patd <version> (<commit>, built <buildDate>)` and exit 0.

Usage text (a single `const usage` string) covers: synopsis, the subcommands (`[run]`
default, `user`, `token`, `audit`, `reindex`, `hashpw`), the server flags (`--addr`,
`--port`, `--version`, `--help`), and the most-used env vars (`PATD_DATA`,
`PATD_USERS_FILE`, `PATD_ADDR`, `PATD_BHE`, `PATD_TLS_CERT`/`_KEY`, `PATD_AUDIT_LOG`) with
a one-line pointer to the README for the complete list. Each subcommand's own
`flag.FlagSet` already prints its usage on `-h` / bad flags; the `user` subcommand adds a
short usage for its verbs.

### 2. Server `--addr` / `--port` flags

When no subcommand matches (server path), parse server flags with a `flag.FlagSet`:

- `--addr string` — full `host:port` bind address.
- `--port int` — shorthand; binds `127.0.0.1:<port>`.

Resolution (in `resolveAddr`):

```
if --addr and --port both set        -> error "use --addr or --port, not both", exit 2
else if --addr set                   -> addr = --addr
else if --port set                   -> addr = "127.0.0.1:" + port
else                                 -> addr = env("PATD_ADDR", "127.0.0.1:8443")
```

So precedence is **explicit flag > `PATD_ADDR` env > default**. The result feeds the
existing listen path unchanged, so the `isLoopbackAddr`-without-TLS guard still refuses an
unsafe non-loopback bind — no new exposure. `resolveAddr(addrFlag, portFlag, envAddr)` is a
small pure function (unit-testable in isolation).

### 3. `patd user` subcommands

New file `cmd/patd/user.go`, dispatched by adding `case "user": runUser(os.Args[2:])` to the
`main.go` switch. `runUser` switches on the verb (mirrors `runToken`):

- **`user add <username> --role analyst|lead [--force]`** — validates the role, runs the
  running-server guard, prompts for a password on stdin (stderr prompt like `hashpw`;
  pipeable), then `auth.OpenUserStore(usersFile).Create(username, password, role)`. Prints
  `created operator <username> (<role>)`. `Create` already rejects duplicates / invalid input.
- **`user passwd <username> [--force]`** — running-server guard, prompts for a new password
  on stdin, `SetPassword(username, pw)`. Prints `password updated for <username>`.
- **`user list`** — `auth.OpenUserStore(usersFile)`, prints one line per operator
  `username  role  enabled|disabled`. Never prints hashes. (Read-only; no server guard.)

The `usersFile` path comes from `env("PATD_USERS_FILE", "users.json")` — identical to the
server, so the CLI and server operate on the same file.

**Running-server guard** (`serverIsRunning(addr) bool`): the mutating verbs (`add`,
`passwd`) probe the server's configured address — `env("PATD_ADDR", "127.0.0.1:8443")`
(the `user` subcommand does not take its own `--addr`/`--port`) — with a short (~300ms)
TCP dial / `GET /api/version`. If something answers, print:

```
a server appears to be running at <addr>; manage operators in the UI so its in-memory
copy of users.json is not clobbered. Re-run with --force to edit the file anyway.
```

and exit 1 unless `--force` is set. When nothing answers, proceed to the file edit. This
is best-effort (a reachable port is the signal); `--force` is the documented escape hatch.
Mirrors the known MCP-token "running server owns the file" caveat.

Password input reuses a shared `readPassword(prompt string) (string, error)` helper
extracted from `hashpw` (stderr prompt, stdin line read, trim, reject empty) so `hashpw`,
`user add`, and `user passwd` share one implementation. Passwords are never accepted as a
CLI argument (no shell-history / process-list leak) — stdin only.

### 4. Cross-platform build scripts

`scripts/build.sh` (bash; Linux/Mac, and Windows via Git Bash) and `scripts/build.ps1`
(PowerShell; Windows) — behavior-identical:

1. Resolve repo root from the script location; `cd` there.
2. Frontend: unless `--skip-web`, run `npm run build` in `web/`. **Never `npm install`** —
   if `web/node_modules` is missing, error with `run 'cd web && npm install' first` and exit.
3. Refresh embedded assets: remove `internal/webui/dist`, copy `web/dist` → `internal/webui/dist`.
4. Stamp: `VERSION=$(git describe --tags --always)`, `COMMIT=$(git rev-parse --short HEAD)`,
   `BUILD_DATE` = UTC `YYYY-MM-DDTHH:MM:SSZ`.
5. Build: `CGO_ENABLED=0 go build -tags embed -trimpath -ldflags "-s -w -X main.version=$VERSION
   -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" -o <out> ./cmd/patd`.
   Default `<out>` = `patd.exe` on Windows, `patd` elsewhere.
6. Print `built <out> (<VERSION> / <COMMIT>)`.

Flags: `--skip-web` (reuse existing `web/dist`), `--output <path>` (override binary path).
The scripts deliberately do not auto-install npm deps (honors the "never npm install on
this box" constraint; fresh clones run `npm install` once per the README).

### 5. README.md

Add/refresh these sections:

- **Build** — prerequisites (Go 1.26, Node 20+ for the SPA); one-time `cd web && npm install`;
  `./scripts/build.sh` (Linux/Mac/Git-Bash) or `./scripts/build.ps1` (Windows); the produced
  binary; `patd --version` to confirm the stamp; the dev (`go run`, disk-served `web/dist`,
  `version=dev`) vs. embedded-release (`-tags embed`, single binary) distinction.
- **Run** — `patd` (defaults `127.0.0.1:8443`), `patd --port 9000`, `patd --addr host:port`,
  `PATD_ADDR`; TLS note (`PATD_TLS_CERT`/`_KEY` required for a non-loopback bind).
- **First run / operators** — `patd user add <name> --role lead` to bootstrap the first lead,
  `patd user passwd <name>`, `patd user list`; the "manage users in the UI while the server is
  running" caveat.
- **Help** — `patd --help`, `patd --version`.

## Data flow

```
patd <args>
  ├─ help/-h/--help            -> print usage, exit
  ├─ --version/-v/version      -> print version line, exit
  ├─ user <verb> ...           -> runUser: [guard: serverIsRunning(resolveAddr) unless --force]
  │                                -> auth.OpenUserStore(PATD_USERS_FILE).{Create|SetPassword|list}
  ├─ token | audit | reindex | hashpw   -> existing handlers (unchanged)
  └─ (default) server          -> resolveAddr(--addr,--port,PATD_ADDR) -> existing listen path
```

Build scripts are independent of the binary: they stamp `main.version/commit/buildDate` at
compile time; nothing at runtime depends on them.

## Error handling

- `--addr` + `--port` together → `exit 2` with a one-line message.
- `user add` duplicate / invalid role / empty password → surfaced from `UserStore.Create` /
  `validRole` / `readPassword`, non-zero exit.
- `user add`/`passwd` with a server up and no `--force` → guard message, `exit 1`.
- Build scripts: missing `web/node_modules` (and not `--skip-web`) → clear error, non-zero exit;
  missing `web/dist` with `--skip-web` → error telling the user to drop `--skip-web`.

## Testing

- **Go unit tests** (`cmd/patd`, mirroring `token_test.go`):
  - `resolveAddr`: flag-only, port-only, env fallback, default, and the both-set error.
  - `user add` / `passwd` / `list` against a temp `PATD_USERS_FILE`: created user is present
    with the right role; `passwd` changes the stored hash; `list` output shows username/role/
    enabled and never a hash; duplicate-add and empty-password are rejected.
  - `serverIsRunning` against a closed port (false) and a live `httptest`-style listener (true);
    the `--force` bypass path.
  - `--version` / `help` output contains the stamped fields / the subcommand names.
  - `readPassword` reads + trims a piped line and rejects empty.
- **Build scripts**: verified by running each on its platform and confirming `patd --version`
  reports the git-described version (manual, documented in the plan's verification step).
- **Gates**: `gofmt -l cmd internal`, `go build/vet/test ./...`; the web build is unchanged
  (the scripts call the existing `npm run build`), so `tsc`/`vitest`/`vite build` remain green.

## File summary

| Action | Path | Responsibility |
|---|---|---|
| Modify | `cmd/patd/main.go` | front-door `help`/`--version`; `case "user"`; server `--addr`/`--port` via `resolveAddr`; extract `readPassword` |
| Create | `cmd/patd/user.go` | `runUser` (`add`/`passwd`/`list`) + `serverIsRunning` guard |
| Create | `cmd/patd/user_test.go` | unit tests for `user` verbs + guard |
| Create | `cmd/patd/cli_test.go` | unit tests for `resolveAddr` + version/help output (or fold into existing test files) |
| Create | `scripts/build.sh` | canonical Linux/Mac/Git-Bash stamped build |
| Create | `scripts/build.ps1` | canonical Windows stamped build |
| Modify | `README.md` | Build / Run / First-run / Help sections |

## Decisions / notes

- `--port` binds loopback only (`127.0.0.1:N`); a non-loopback bind uses `--addr` + TLS.
- Passwords are stdin-only (pipeable, no shell-history leak); `readPassword` mirrors the
  existing echoed `hashpw` prompt — no new `x/term` dependency, no hidden-input mode.
- The running-server guard is best-effort (port reachability) with a `--force` override; it
  is not a lock. Documented as such.
- `user list` is read-only and skips the server guard.
- The build scripts never auto-install npm deps; the README covers the one-time `npm install`.
