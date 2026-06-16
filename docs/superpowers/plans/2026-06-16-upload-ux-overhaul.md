# Upload UX Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the console Upload page give real progress feedback, track a per-audit ingest history, and stream large uploads without spilling cleartext to a temp file.

**Architecture:** Backend records an `IngestEvent` (filename/kind/domain/counts/time/operator) in each audit's encrypted dataset and serves it at `GET /api/ingests`; the upload handlers are rewritten to stream multipart parts via `r.MultipartReader()` (no temp spill, 512 MiB cap). Frontend uploads switch from `fetch` to `XMLHttpRequest` for a two-phase progress bar (uploading → processing) and show a "This audit" history panel.

**Tech Stack:** Go (stdlib `mime/multipart`), React + Vite (TypeScript), vitest, Playwright. Gates: `gofmt -l cmd internal` empty, `go build ./... && go vet ./... && go test ./...`, `cd web && npx tsc --noEmit && npm run build && npx vitest run`, `govulncheck ./...`.

**Spec:** `docs/superpowers/specs/2026-06-16-upload-ux-overhaul-design.md`

---

## File Structure
- `internal/model/model.go` — `IngestEvent` type; `Dataset.Ingests` field.
- `internal/store/store.go` — `RecordIngest`, `Ingests`; preserve `Ingests` in `ReplaceDomain`/`Replace`.
- `internal/httpapi/server.go` — `GET /api/ingests` handler+route; streaming `handleAudit`/`handleApplyCracks`; remove `optionalUpload`.
- `web/src/api.ts` — `uploadForm` (XHR), progress on `audit`/`applyCracks`, `ingests()` + `IngestEvent`.
- `web/src/components/Ingest.tsx` — upload phases + progress bar + history panel; `web/src/styles.css`.

---

## Task 1: Ingest history — model + store

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/store/store.go` (`ReplaceDomain` ~470, `Replace` ~488; add `RecordIngest`/`Ingests`)
- Test: `internal/store/store_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/store/store_test.go`:

```go
func TestIngestHistoryRecordedAndPreserved(t *testing.T) {
	s := New() // in-memory store is enough for the history logic
	m, _ := s.CreateAudit("A", "")

	// load a domain, then record a dump ingest
	if err := s.ReplaceDomain(m.ID, "CORP", []model.Account{{Username: "u1", Domain: "CORP", NTHash: "AA"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIngest(m.ID, model.IngestEvent{Filename: "ntds.pwdump", Kind: "dump", Domain: "CORP", AccountsLoaded: 1, By: "watson"}); err != nil {
		t.Fatal(err)
	}
	// a second domain load must NOT wipe the first ingest
	if err := s.ReplaceDomain(m.ID, "SUB", []model.Account{{Username: "u2", Domain: "SUB", NTHash: "BB"}}); err != nil {
		t.Fatal(err)
	}
	// a full Replace (the apply-cracks re-score path) must also preserve history
	cur, _ := s.Accounts(m.ID, true)
	if err := s.Replace(m.ID, model.Dataset{Accounts: cur}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIngest(m.ID, model.IngestEvent{Filename: "crack.potfile", Kind: "cracks", HashesMatched: 1, NewlyCracked: 1, By: "watson"}); err != nil {
		t.Fatal(err)
	}

	evs, err := s.Ingests(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 ingest events, got %d: %+v", len(evs), evs)
	}
	if evs[0].Filename != "ntds.pwdump" || evs[0].Kind != "dump" || evs[0].AccountsLoaded != 1 {
		t.Fatalf("first event wrong: %+v", evs[0])
	}
	if evs[1].Filename != "crack.potfile" || evs[1].Kind != "cracks" || evs[1].NewlyCracked != 1 {
		t.Fatalf("second event wrong: %+v", evs[1])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run TestIngestHistoryRecordedAndPreserved`
Expected: FAIL — `model.IngestEvent` / `RecordIngest` / `Ingests` undefined (compile error).

- [ ] **Step 3: Add the model type + Dataset field**

In `internal/model/model.go`, add near `Dataset`:

```go
// IngestEvent records one upload into an audit (a dump load or a crack-apply).
// Metadata only -- no password or NT hash. Stored in the audit's encrypted dataset.
type IngestEvent struct {
	Filename       string    `json:"filename"`
	Kind           string    `json:"kind"` // "dump" | "cracks"
	Domain         string    `json:"domain,omitempty"`
	AccountsLoaded int       `json:"accounts_loaded,omitempty"` // dump
	HashesMatched  int       `json:"hashes_matched,omitempty"`  // cracks
	NewlyCracked   int       `json:"newly_cracked,omitempty"`   // cracks
	At             time.Time `json:"at"`
	By             string    `json:"by"` // operator username
}
```

Add the field to the `Dataset` struct (after `Accounts`):

```go
	Ingests []IngestEvent `json:"ingests,omitempty"`
```

- [ ] **Step 4: Preserve Ingests in ReplaceDomain + Replace**

In `internal/store/store.go`, `ReplaceDomain` ends with:
```go
	return s.swap(id, &audit{meta: meta, ds: model.Dataset{Name: cur.ds.Name, GeneratedAt: now, Accounts: merged}})
```
Add `Ingests: cur.ds.Ingests` so it reads:
```go
	return s.swap(id, &audit{meta: meta, ds: model.Dataset{Name: cur.ds.Name, GeneratedAt: now, Accounts: merged, Ingests: cur.ds.Ingests}})
```

In `Replace`, after `cur, err := s.ensureLoaded(id)` succeeds and before the `swap`, preserve the existing history (callers never set it):
```go
	ds.Ingests = cur.ds.Ingests
```
(Place it right after the `RecomputeSharing`/`EscalateSharedWithDA` lines, before `meta := cur.meta`.)

- [ ] **Step 5: Add RecordIngest + Ingests**

In `internal/store/store.go`, after `Replace` (before `swap`), add:

```go
// RecordIngest appends an ingest event to the audit's history (copy-on-write) and
// persists. The accounts are untouched.
func (s *Store) RecordIngest(id string, ev model.IngestEvent) error {
	unlock := s.mutate.lock(id)
	defer unlock()
	cur, err := s.ensureLoaded(id)
	if err != nil {
		return err
	}
	if ev.At.IsZero() {
		ev.At = s.now()
	}
	ingests := append(append([]model.IngestEvent(nil), cur.ds.Ingests...), ev)
	ds := cur.ds
	ds.Ingests = ingests
	meta := cur.meta
	meta.UpdatedAt = s.now()
	return s.swap(id, &audit{meta: meta, ds: ds})
}

// Ingests returns the audit's ingest history (oldest first).
func (s *Store) Ingests(id string) ([]model.IngestEvent, error) {
	a, err := s.ensureLoaded(id)
	if err != nil {
		return nil, err
	}
	return a.ds.Ingests, nil
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/store/ -run TestIngestHistoryRecordedAndPreserved` → PASS
Then: `go test ./internal/store/ ./internal/model/` → ok

- [ ] **Step 7: gofmt + commit**

```bash
gofmt -w internal/model/model.go internal/store/store.go internal/store/store_test.go
git add internal/model/model.go internal/store/store.go internal/store/store_test.go
git commit -m "feat(store): per-audit ingest history (IngestEvent + RecordIngest/Ingests)"
```
(Add the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.)

---

## Task 2: `GET /api/ingests` endpoint

**Files:**
- Modify: `internal/httpapi/server.go` (route block near `GET /api/report`; handler near `handleListAudits`)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing test**

Using the existing httpapi test harness (mirror an existing lead-gated test — e.g. how `TestReportTermsLeadGatedAndAudited` builds a server, logs in, opens an audit, seeds data, and issues requests), add `TestIngestsEndpoint` that:
1. seeds an audit and records an ingest event (via the store, like `srv.Store.RecordIngest(id, model.IngestEvent{Filename:"x.pwdump", Kind:"dump", Domain:"CORP", AccountsLoaded:3, By:"watson"})`),
2. asserts a **lead** `GET /api/ingests` returns 200 with `x.pwdump` in the body,
3. asserts a **non-lead** gets 403,
4. asserts the body contains no password/NT-hash field.

Adapt names to the real harness helpers.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/httpapi/ -run TestIngestsEndpoint`
Expected: FAIL — route 404.

- [ ] **Step 3: Add the handler**

In `internal/httpapi/server.go`, add near `handleListAudits`:

```go
// handleIngests returns the active audit's ingest history (lead only -- it mirrors
// the lead-only Upload surface). Metadata only; no password or hash.
func (s *Server) handleIngests(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	evs, err := s.Store.Ingests(id)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return
	}
	if evs == nil {
		evs = []model.IngestEvent{} // emit [] not null
	}
	writeJSON(w, http.StatusOK, evs)
}
```

- [ ] **Step 4: Register the route**

Next to the `GET /api/report` route registration, add:
```go
	mux.Handle("GET /api/ingests", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleIngests))))
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/httpapi/ -run TestIngestsEndpoint` → PASS
Then: `go test ./internal/httpapi/`

- [ ] **Step 6: gofmt + commit**

```bash
gofmt -w internal/httpapi/server.go internal/httpapi/server_test.go
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): GET /api/ingests (lead-only audit ingest history)"
```
(trailer)

---

## Task 3: Stream `handleAudit` + record the ingest

**Files:**
- Modify: `internal/httpapi/server.go` (`handleAudit`; remove `optionalUpload`)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing test**

Add `TestUploadStreamsAndRecordsIngest` (adapt to the harness): build a multipart body with the `domain` field FIRST then an `uncracked` file part (`user:rid:lm:nt:::` lines) using `mime/multipart.Writer`, POST it to `/api/upload` as a lead with an open audit, and assert: 200 with `accounts` > 0; `GET /api/ingests` then lists an event with `kind == "dump"` and the filename you set on the part. Also add a case where a file part is sent BEFORE the domain field and assert HTTP 400. (Use `CreateFormField("domain")` then `CreateFormFile("uncracked", "ntds.pwdump")`.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run TestUploadStreamsAndRecordsIngest`
Expected: FAIL (no ingest recorded / filename absent).

- [ ] **Step 3: Rewrite handleAudit to stream**

Replace the body of `handleAudit` from the `r.Body = http.MaxBytesReader(...)` line through the final `writeJSON` with:

```go
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20) // 512 MiB cap, streamed (no temp spill)
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload: " + err.Error()})
		return
	}
	var domain, dumpName string
	var cracked, uncracked []secretsdump.ParsedAccount
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload: " + err.Error()})
			return
		}
		switch part.FormName() {
		case "domain":
			b, _ := io.ReadAll(part)
			domain = strings.TrimSpace(string(b))
		case "cracked", "uncracked":
			if domain == "" {
				part.Close()
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the domain field must be sent before the file"})
				return
			}
			parse := secretsdump.ParseUncracked
			if part.FormName() == "cracked" {
				parse = secretsdump.ParseCracked
			}
			accts, perr := parse(part, domain)
			dumpName = part.FileName()
			part.Close()
			if perr != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": part.FormName() + " file: " + perr.Error()})
				return
			}
			if part.FormName() == "cracked" {
				cracked = accts
			} else {
				uncracked = accts
			}
		default:
			part.Close()
		}
	}
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	if len(cracked) == 0 && len(uncracked) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upload a cracked and/or uncracked (pwdump) file"})
		return
	}

	accts := s.Engine.ProcessDomain(domain, cracked, uncracked)
	if err := s.Store.ReplaceDomain(auditID, domain, accts); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	_ = s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: dumpName, Kind: "dump", Domain: domain,
		AccountsLoaded: len(accts), At: time.Now().UTC(), By: sess.Username,
	})
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "audit_upload", Target: domain, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]int{"accounts": len(accts), "cracked": len(cracked), "uncracked": len(uncracked)})
```

(Keep the lead/engine/activeAudit guards and the 10-minute deadline block above this. `io`, `strings`, `time`, `model`, `secretsdump`, `audit` are already imported.)

Note on `dumpName`: when both file parts are present (legacy), it ends up the last part's name; the web sends only `uncracked`, so it captures the pwdump filename — acceptable.

- [ ] **Step 4: Remove the now-unused `optionalUpload`**

Delete the `optionalUpload` function (handleAudit was its only caller). Run `go build ./...` — if the compiler reports it unused/undefined elsewhere, fix accordingly (handleApplyCracks does NOT use it).

- [ ] **Step 5: Run tests**

Run: `go test ./internal/httpapi/ -run TestUploadStreamsAndRecordsIngest` → PASS
Then: `go test ./internal/httpapi/` (the existing upload tests should still pass — they post multipart bodies; ensure they send `domain` before the file. If an existing test sends the file first and now fails, update that test to append the domain field first, matching the real client.)

- [ ] **Step 6: gofmt + commit**

```bash
gofmt -w internal/httpapi/server.go internal/httpapi/server_test.go
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): stream /api/upload (no temp spill, 512 MiB) + record dump ingest"
```
(trailer)

---

## Task 4: Stream `handleApplyCracks` + record the ingest

**Files:**
- Modify: `internal/httpapi/server.go` (`handleApplyCracks`)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing test**

Add `TestApplyCracksRecordsIngest`: with an audit holding an uncracked account whose NT hash matches a line in the posted `crackfile`, POST a multipart body (`crackfile` part) to `/api/upload/cracks`, assert 200 with `newly_cracked >= 1`, then `GET /api/ingests` lists an event with `kind == "cracks"` and the crackfile's filename. (Adapt to the harness.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run TestApplyCracksRecordsIngest`
Expected: FAIL (no cracks ingest event).

- [ ] **Step 3: Rewrite handleApplyCracks to stream + record**

Replace the body from `r.Body = http.MaxBytesReader(...)` through the final `writeJSON` with:

```go
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse upload"})
		return
	}
	var cracks map[string]string
	var crackName string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse upload"})
			return
		}
		if part.FormName() == "crackfile" {
			crackName = part.FileName()
			cracks, err = secretsdump.CrackMap(part)
			part.Close()
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse crack file"})
				return
			}
		} else {
			part.Close()
		}
	}
	if cracks == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a 'crackfile' (user:hash:password lines) is required"})
		return
	}
	accounts, err := s.Store.Accounts(auditID, true) // need NT hashes + any existing cleartext
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return
	}
	matched := map[string]bool{}
	newly := 0
	for i := range accounts {
		if accounts[i].Password != "" {
			continue
		}
		h := strings.ToUpper(strings.TrimSpace(accounts[i].NTHash))
		if pw, ok := cracks[h]; ok {
			accounts[i].Password = pw
			matched[h] = true
			newly++
		}
	}
	rescored := s.Engine.Rescore(accounts)
	meta, _ := s.Store.Meta(auditID)
	if err := s.Store.Replace(auditID, model.Dataset{Name: meta.Name, Accounts: rescored}); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	_ = s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: crackName, Kind: "cracks",
		HashesMatched: len(matched), NewlyCracked: newly, At: time.Now().UTC(), By: sess.Username,
	})
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "apply_cracks", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]int{"crack_entries": len(cracks), "hashes_matched": len(matched), "newly_cracked": newly})
```

(Keep the lead/engine/activeAudit guards + deadline block above.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/httpapi/ -run TestApplyCracksRecordsIngest` → PASS
Then: `go test ./...` (all 17+ packages) → ok

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/httpapi/server.go internal/httpapi/server_test.go
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): stream /api/upload/cracks + record cracks ingest"
```
(trailer)

---

## Task 5: Frontend API — XHR upload progress + ingests

**Files:**
- Modify: `web/src/api.ts`
- Test: `web/src/upload.test.ts` (new)

- [ ] **Step 1: Write the failing test**

Create `web/src/upload.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { uploadForm } from "./api"

class FakeXHR {
  upload = { onprogress: null as null | ((e: any) => void) }
  status = 0
  responseText = ""
  onload: null | (() => void) = null
  onerror: null | (() => void) = null
  _headers: Record<string, string> = {}
  withCredentials = false
  open() {}
  setRequestHeader(k: string, v: string) { this._headers[k] = v }
  send() {
    this.upload.onprogress?.({ lengthComputable: true, loaded: 5, total: 10 })
    this.status = 200
    this.responseText = JSON.stringify({ accounts: 3 })
    this.onload?.()
  }
}

beforeEach(() => { vi.stubGlobal("XMLHttpRequest", FakeXHR as unknown as typeof XMLHttpRequest) })
afterEach(() => { vi.unstubAllGlobals() })

describe("uploadForm", () => {
  it("reports progress and resolves the parsed body", async () => {
    const seen: number[] = []
    const body = await uploadForm<{ accounts: number }>("/upload", new FormData(), "csrf", (loaded, total) => seen.push(loaded / total))
    expect(seen).toEqual([0.5])
    expect(body.accounts).toBe(3)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run upload`
Expected: FAIL — `uploadForm` not exported.

- [ ] **Step 3: Implement `uploadForm` + wire progress**

In `web/src/api.ts`, add (near `request`, reusing `ApiError`/`safeParse`):

```ts
// uploadForm POSTs multipart FormData via XMLHttpRequest so upload progress is observable
// (fetch can't report it). Mirrors request()'s error handling.
export function uploadForm<T>(
  path: string,
  form: FormData,
  csrf: string,
  onProgress?: (loaded: number, total: number) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open("POST", `/api${path}`)
    xhr.withCredentials = true
    xhr.setRequestHeader("X-CSRF-Token", csrf)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(e.loaded, e.total)
    }
    xhr.onload = () => {
      const body = xhr.responseText ? safeParse(xhr.responseText) : null
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as T)
        return
      }
      if (xhr.status === 423) window.dispatchEvent(new CustomEvent("patd:locked"))
      let msg = `request failed (${xhr.status})`
      if (body && typeof body === "object" && "error" in body) {
        const e = (body as { error?: unknown }).error
        if (typeof e === "string" && e) msg = e
      }
      reject(new ApiError(xhr.status, msg, body))
    }
    xhr.onerror = () => reject(new ApiError(0, "network error — is the server reachable?"))
    xhr.send(form)
  })
}
```

Rewrite `audit` and `applyCracks` in the `api` object to use it (note: append `domain` FIRST):

```ts
  audit: (domain: string, cracked: File | null, uncracked: File | null, csrf: string, onProgress?: (l: number, t: number) => void) => {
    const fd = new FormData()
    fd.append("domain", domain) // must precede files (server streams parts in order)
    if (cracked) fd.append("cracked", cracked)
    if (uncracked) fd.append("uncracked", uncracked)
    return uploadForm<AuditResult>("/upload", fd, csrf, onProgress)
  },

  applyCracks: (crackfile: File, csrf: string, onProgress?: (l: number, t: number) => void) => {
    const fd = new FormData()
    fd.append("crackfile", crackfile)
    return uploadForm<ApplyCracksResult>("/upload/cracks", fd, csrf, onProgress)
  },

  ingests: () => request<IngestEvent[]>("/ingests"),
```

Add the `IngestEvent` interface near the other types:

```ts
export interface IngestEvent {
  filename: string
  kind: "dump" | "cracks"
  domain?: string
  accounts_loaded?: number
  hashes_matched?: number
  newly_cracked?: number
  at: string
  by: string
}
```

(Ensure `safeParse` and `ApiError` are defined above `uploadForm`; both already exist in the file.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run upload` → PASS
Then: `cd web && npx tsc --noEmit` → clean (the `Ingest.tsx` calls `api.audit(domain, null, dump, csrf)` — the new optional `onProgress` keeps that call valid).

- [ ] **Step 5: Commit**

```bash
git add web/src/api.ts web/src/upload.test.ts
git commit -m "feat(web): XHR uploadForm with progress + api.ingests + IngestEvent"
```
(trailer)

---

## Task 6: Ingest page — progress bar + history panel

**Files:**
- Modify: `web/src/components/Ingest.tsx`
- Modify: `web/src/styles.css`

- [ ] **Step 1: Add progress + history state and the fetch**

In `Ingest.tsx`, add imports + state. Replace the `busy`/`applyBusy` booleans with phase + progress, and add ingest history:

```tsx
import { useCallback } from "react" // add to the existing react import
import { type IngestEvent } from "../api" // add to the existing api import
import { fmtWhen, fmtBytes } from "../format"
```

Inside `Ingest`, add:
```tsx
  const [phase, setPhase] = useState<"idle" | "uploading" | "processing">("idle")
  const [pct, setPct] = useState(0)
  const [applyPhase, setApplyPhase] = useState<"idle" | "uploading" | "processing">("idle")
  const [applyPct, setApplyPct] = useState(0)
  const [history, setHistory] = useState<IngestEvent[]>([])

  const loadHistory = useCallback(async () => {
    try { setHistory(await api.ingests()) } catch { /* panel just stays empty */ }
  }, [])
  useEffect(() => { void loadHistory() }, [activeId, loadHistory])
```
Add `setPhase("idle"); setPct(0); setApplyPhase("idle"); setApplyPct(0)` to the existing `activeId` reset effect.

Define a progress handler used by both uploads:
```tsx
  function onUp(setPctFn: (n: number) => void, setPhaseFn: (p: "uploading" | "processing") => void) {
    return (loaded: number, total: number) => {
      setPctFn(total ? Math.round((loaded / total) * 100) : 0)
      if (loaded >= total) setPhaseFn("processing")
    }
  }
```

- [ ] **Step 2: Use phases in the submit handlers**

Rewrite `onSubmit`:
```tsx
  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim() || !dump || !me || phase !== "idle") return
    setPhase("uploading"); setPct(0); setError(""); setResult(null)
    try {
      const r = await api.audit(domain.trim(), null, dump, me.csrf_token, onUp(setPct, setPhase))
      setResult(r)
      void loadHistory()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "upload failed")
    } finally {
      setPhase("idle"); setPct(0)
    }
  }
```
Rewrite `onApply` the same way (using `applyPhase`/`applyPct`, `api.applyCracks(crackfile, me.csrf_token, onUp(setApplyPct, setApplyPhase))`, `setApplyResult`, `void loadHistory()`).

- [ ] **Step 3: Render the progress bar + update the buttons**

Replace each form's submit button with a progress-aware block. For Step 1 (before `</form>`):
```tsx
        {phase !== "idle" && (
          <div className="upload-progress">
            <div className="bar"><div className="fill" style={{ width: phase === "processing" ? "100%" : `${pct}%` }} /></div>
            <div className="hint">{phase === "uploading" ? `Uploading… ${pct}%` : "Processing on server…"}</div>
          </div>
        )}
        <button className="btn btn-primary" type="submit" disabled={phase !== "idle" || !domain.trim() || !dump}>
          {phase === "idle" ? "Load dump" : phase === "uploading" ? "Uploading…" : "Processing…"}
        </button>
```
Do the equivalent for Step 2 with `applyPhase`/`applyPct` and the "Apply cracked hashes" label. Also show the selected file size next to the file input using `fmtBytes(file.size)` when a file is chosen (e.g. under the file input: `{dump && <div className="hint">{dump.name} · {fmtBytes(dump.size)}</div>}`).

- [ ] **Step 4: Add the "This audit" history panel**

After both forms (before the closing `</>`), add:
```tsx
      <div className="section-label">This audit — ingest history</div>
      <div className="panel">
        {history.length === 0 ? (
          <div className="muted">No uploads yet for this audit.</div>
        ) : (
          <div className="table-wrap">
            <table className="accounts">
              <thead>
                <tr><th>When</th><th>File</th><th>Kind</th><th>Domain</th><th>Result</th><th>By</th></tr>
              </thead>
              <tbody>
                {[...history].reverse().map((ev, i) => (
                  <tr key={i}>
                    <td className="muted">{fmtWhen(ev.at)}</td>
                    <td>{ev.filename || <span className="muted">—</span>}</td>
                    <td>{ev.kind}</td>
                    <td className="muted">{ev.domain || "—"}</td>
                    <td>
                      {ev.kind === "dump"
                        ? `+${(ev.accounts_loaded ?? 0).toLocaleString()} accounts`
                        : `${(ev.hashes_matched ?? 0).toLocaleString()} matched · ${(ev.newly_cracked ?? 0).toLocaleString()} cracked`}
                    </td>
                    <td className="muted">{ev.by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
```

- [ ] **Step 5: Add CSS**

In `web/src/styles.css`, near the ingest styles, add:
```css
.upload-progress { margin: 10px 0; }
.upload-progress .bar { height: 8px; background: #11182b; border-radius: 4px; overflow: hidden; }
.upload-progress .fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #0e7490, #22d3ee); transition: width 0.2s ease; }
```

- [ ] **Step 6: Verify**

Run: `cd web && npx tsc --noEmit && npm run build && npx vitest run`
Expected: clean tsc; build ok; vitest green. (Confirm `fmtBytes`/`fmtWhen` exist in `web/src/format.ts`; both were extracted earlier. If `fmtBytes` is absent, format the size inline as `${(file.size/1024/1024).toFixed(1)} MB`.)

- [ ] **Step 7: Commit**

```bash
git add web/src/components/Ingest.tsx web/src/styles.css
git commit -m "feat(web): upload progress (uploading/processing) + per-audit ingest history panel"
```
(trailer)

---

## Task 7: Full gate + embedded rebuild + live verification

**Files:** none (verification + release)

- [ ] **Step 1: Backend + frontend gate**

```bash
gofmt -l cmd internal
go build ./... && go vet ./... && go test ./...
govulncheck ./...
cd web && npx tsc --noEmit && npm run build && npx vitest run && cd ..
```
Expected: gofmt empty; all packages ok; "No vulnerabilities found."; tsc clean; build ok; vitest green.

- [ ] **Step 2: Rebuild embedded binary + restart**

```bash
taskkill //F //IM patd.exe 2>/dev/null; sleep 1
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o patd.exe ./cmd/patd
PATD_ADDR=127.0.0.1:8443 PATD_INGEST_TOKEN=tok PATD_USERS_FILE=users.json PATD_AUDIT_LOG=audit.log \
  PATD_HIBP=PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt PATD_LISTS=lists \
  PATD_BHE=config/bloodhound.json PATD_DATA=data ./patd.exe > server.log 2>&1 &
sleep 3
```

- [ ] **Step 3: Live checks (Playwright, lead session)**

Log in (`watson`/`discotime`), unlock (`disco-vault-2026`), open/create an audit, go to **Upload**:
- Load a dump (e.g. a `sample_data/*_uncracked.txt`, with the domain filled): confirm the progress bar shows **Uploading… %** then **Processing on server…**, then the ✓ result.
- Confirm the **"This audit — ingest history"** panel gains a row: the filename, kind `dump`, domain, `+N accounts`, operator.
- Apply a crack file: confirm a second history row (kind `cracks`, `N matched · M cracked`).
Screenshot the page with the history panel populated.

- [ ] **Step 4: Verify no temp spill / streaming + ingests API**

```bash
# /api/ingests reflects the uploads (run inside an authenticated session jar)
curl -s -b $JAR http://127.0.0.1:8443/api/ingests | python -m json.tool | head -30
```
Confirm the events are present with filenames + counts, and contain no password/hash. (Streaming is covered by the Go test; this confirms the end-to-end history.)

- [ ] **Step 5: README + commit**

Add a short "What's new in 2.5" (or 2.4.2) note to `README.md`: upload progress feedback, per-audit ingest history, streamed large-file uploads (no cleartext temp spill, 512 MiB). Commit:
```bash
git add README.md
git commit -m "docs: note upload progress + ingest history + streaming uploads"
```

- [ ] **Step 6: Hand back to the controller** for the final whole-branch review + finishing-a-development-branch.

---

## Self-Review notes
- **Spec coverage:** ingest model+store+preservation (T1), `GET /api/ingests` (T2), streaming `handleAudit`+record (T3), streaming `handleApplyCracks`+record (T4), XHR progress + `ingests()` + `IngestEvent` (T5), page progress bar + history panel (T6), gate+live (T7). All four spec parts mapped.
- **Type consistency:** Go `IngestEvent{Filename,Kind,Domain,AccountsLoaded,HashesMatched,NewlyCracked,At,By}` ↔ TS `IngestEvent{filename,kind,domain,accounts_loaded,hashes_matched,newly_cracked,at,by}`; `Store.RecordIngest`/`Store.Ingests` used by T2/T3/T4 exactly as defined in T1; `uploadForm` signature in T5 matches its callers; `api.audit`/`applyCracks` keep their existing positional args + a trailing optional `onProgress`, so existing callers compile.
- **Streaming order:** the client appends `domain` before files (T5); the server errors on a file-before-domain body (T3) — covered by a test.
- **No secret in history:** `IngestEvent` is metadata only; T2 asserts the endpoint body carries no password/hash.
