# Upload UX overhaul — design

- **Date:** 2026-06-16
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90

## Problem

The console Upload page (`Ingest.tsx`) has three weaknesses:

1. **No processing feedback** — uploads use `fetch` (which can't report upload progress); the only signal is a button label ("Loading…"). The operator can't tell whether a large file is uploading or the server is working.
2. **No record of what's been uploaded** — the page shows a one-shot ✓ result; there's no per-audit history of which files/domains were ingested.
3. **Large-file handling is weak** — a single multipart POST capped at 128 MiB; `ParseMultipartForm(32 MiB)` **spills larger parts to a cleartext temp file** in the OS temp dir before parsing (a real concern for a "no cleartext on disk" product), buffering rather than streaming.

The flow itself (dump first, then apply cracks) is correct but under-communicated.

## Decisions (from brainstorm)

- **Structure:** keep the two operations as **guided steps** (Step 1 Load dump · Step 2 Apply cracks "now or later") — not a locking wizard. Add a **"This audit" ingest-history** side panel.
- **Progress:** two-phase — a determinate upload bar, then an indeterminate "Processing…" state.
- **History:** record **real ingest events** (filename, kind, domain, counts, timestamp, operator) per audit.
- **Large files:** **stream** server-side (no temp spill), raise the cap to 512 MiB. **No** resumable/chunked protocol; **no** content auto-detection.

## Part 1 — Frontend: page + progress

### `web/src/api.ts`
- Add `uploadForm<T>(path: string, form: FormData, csrf: string, onProgress?: (loaded: number, total: number) => void): Promise<T>` built on `XMLHttpRequest`:
  - `xhr.open("POST", "/api"+path)`; `xhr.withCredentials = true`; `setRequestHeader("X-CSRF-Token", csrf)`; `xhr.upload.onprogress = e => e.lengthComputable && onProgress?.(e.loaded, e.total)`.
  - On `load`: parse the response text (reuse `safeParse`); 2xx → resolve `body as T`; non-2xx → reject `new ApiError(status, msg, body)` with the same error-message extraction as `request` (and dispatch the `patd:locked` event on 423).
  - On `error`: reject `new ApiError(0, "network error — is the server reachable?")`.
- Rewrite `api.audit(domain, cracked, uncracked, csrf, onProgress?)` and `api.applyCracks(crackfile, csrf, onProgress?)` to build the `FormData` and call `uploadForm` (instead of `fetch`). **Append `domain` to the FormData first** (before the file parts) — the streaming server reads parts in order.
- Add `api.ingests(): Promise<IngestEvent[]>` → `request<IngestEvent[]>("/ingests")`, and a TS `IngestEvent` interface mirroring the Go type (filename, kind, domain, accounts_loaded, hashes_matched, newly_cracked, at, by).

### `web/src/components/Ingest.tsx`
- Per-step upload state: `phase: "idle" | "uploading" | "processing"` and `progress: number` (0–100). The `onProgress` callback sets `progress` and, when `loaded === total`, flips `phase` to `"processing"` (the server is still parsing/scoring until the promise resolves).
- Render a **progress bar** under the active step: determinate (`width: progress%`) while uploading, an indeterminate/pulsing bar labeled "Processing on server…" while processing. Disable the inputs + button during a transfer.
- Keep the two-step layout with clearer headers; keep the existing ✓ result lines.
- **History panel** ("This audit"): fetch `api.ingests()` on mount and re-fetch after each successful upload/apply; render the events (time · filename · kind · domain · `+N accounts` or `N matched` · by). A small inline list or a `IngestHistory` sub-component.

## Part 2 — Ingest history (model + store + endpoint)

### Types — `internal/model/model.go`
```go
type IngestEvent struct {
    Filename      string    `json:"filename"`
    Kind          string    `json:"kind"`            // "dump" | "cracks"
    Domain        string    `json:"domain,omitempty"`
    AccountsLoaded int      `json:"accounts_loaded,omitempty"` // dump
    HashesMatched int       `json:"hashes_matched,omitempty"`  // cracks
    NewlyCracked  int       `json:"newly_cracked,omitempty"`   // cracks
    At            time.Time `json:"at"`
    By            string    `json:"by"`              // operator username
}
```
- `model.Dataset` gains `Ingests []IngestEvent json:"ingests,omitempty"` (stored inside the audit's encrypted blob).
- All fields are redacted-safe metadata — no password, no NT hash. (The filename is the operator's own; shown only on the lead-only Upload page.)

### Store — `internal/store/store.go`
- `RecordIngest(id string, ev model.IngestEvent) error` — loads the audit's dataset, appends `ev` to `Ingests`, persists (cache + blob).
- `Ingests(id string) ([]model.IngestEvent, error)` — returns the dataset's `Ingests` (newest-last; the UI can reverse).
- **Preservation:** `ReplaceDomain` and `Replace` must **carry forward the existing audit's `Ingests`** (they replace accounts only — they must not wipe the history). The handlers call `Replace`/`ReplaceDomain` (preserves history) and then `RecordIngest` (appends the new event).

### Endpoint — `internal/httpapi/server.go`
- `GET /api/ingests` — `requireAuth` + `requireUnlocked`, **lead-only** (matches the lead-only Upload surface). Returns `s.Store.Ingests(activeAudit)`.

## Part 3 — Streaming uploads (backend)

Rewrite `handleAudit` and `handleApplyCracks` to stream via `r.MultipartReader()` instead of `ParseMultipartForm` + `FormFile`:

- `r.Body = http.MaxBytesReader(w, r.Body, 512<<20)` (raised from 128 MiB); keep the 10-minute read/write deadlines.
- `mr, err := r.MultipartReader()`; loop `part, err := mr.NextPart()`:
  - **`handleAudit`:** a `domain` field part (FormName "domain", read via `io.ReadAll`, must arrive **before** files — error clearly if a file part precedes it), then `cracked` / `uncracked` file parts streamed straight into `secretsdump.ParseCracked` / `ParseUncracked` (which read an `io.Reader` — the `*multipart.Part` is one, so **no temp file**). Capture each part's `FileName()`. Require ≥1 file part.
  - **`handleApplyCracks`:** a single `crackfile` part streamed into `secretsdump.CrackMap`; capture the filename.
- After `ProcessDomain` + `ReplaceDomain` (audit) or `Rescore` + `Replace` (cracks), call `Store.RecordIngest` with the captured filename, domain, counts, `By: sess.Username`, `At: time.Now().UTC()`.
- Remove the now-unused `optionalUpload` helper.
- Note: do not call `r.FormValue`/`ParseForm` on these routes (incompatible with `MultipartReader`); the `domain` comes from the streamed part.

## Part 4 — Testing

- **Store** (`internal/store`): `RecordIngest` + `Ingests` round-trip; `Ingests` preserved across `ReplaceDomain` and `Replace`; the event carries no secret.
- **httpapi:** build a multipart body (domain field + a file part) and POST it through the streaming handler — assert accounts loaded and an ingest event recorded with the filename; assert a file-part-before-`domain` body errors cleanly; assert `GET /api/ingests` returns the events for a lead and 403 for a non-lead; assert the ingest history contains no password/hash.
- **Frontend:** vitest for `uploadForm` with a mocked `XMLHttpRequest` (fires `upload.onprogress` then `load`) — asserts `onProgress` is called and the parsed body resolves; `tsc`. Playwright: an upload shows the **uploading → processing** transition and the **history panel** gains the new entry.

## Non-goals
- No resumable/chunked upload protocol (single POST per file, now streamed).
- No content auto-detection — Step 1 = dump, Step 2 = cracks stays explicit.
- The CLI `POST /api/ingest` JSON path (256 MiB `MaxBytesReader`) is unchanged.
- No change to the redaction/security model; `IngestEvent` is metadata only.

## Rough file touch-list
- `web/src/api.ts` (`uploadForm`, `audit`/`applyCracks` progress, `ingests` + `IngestEvent`),
  `web/src/components/Ingest.tsx` (phases, progress bar, history panel), `web/src/styles.css`.
- `internal/model/model.go` (`IngestEvent`, `Dataset.Ingests`), `internal/store/store.go`
  (`RecordIngest`, `Ingests`, preserve on Replace/ReplaceDomain), `internal/httpapi/server.go`
  (streaming `handleAudit`/`handleApplyCracks`, `GET /api/ingests`, remove `optionalUpload`),
  plus the matching `_test.go` files.
