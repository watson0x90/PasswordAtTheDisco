# Sample-Data Refresh for the New Features — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich the synthetic sample-data generator so one loaded audit deliberately exercises the new Password Similarity Clusters (graph + click-to-explain + lead reveal) and the password-in-use probe (including finding uncracked accounts).

**Architecture:** Add per-domain near-duplicate password families (tight similarity clusters) and a banned-password-in-use-on-uncracked-accounts scenario to `tools/gen_synthetic.py`, keep all existing scenarios, document the new ones in the generated README, and make `tools/dev_seed.sh` always regenerate.

**Tech Stack:** Python (the generator is pure-Python, deterministic, self-contained NTLM). No app/Go/web changes. `sample_data/` is gitignored — only the generator + dev_seed + spec/plan are committed.

**Spec:** `docs/superpowers/specs/2026-06-20-sample-data-refresh-design.md`

**Conventions that bite:**
- Run python via the dev's working interpreter (`py -3` works here; `python3` may be a Windows Store stub). Verify it runs Python 3.
- The crack file matches NT hashes GLOBALLY — a password in `cracks.txt` flips every account with that hash. The banned-in-use password must therefore be assigned only to uncracked accounts and kept OUT of `cracks.txt`.
- The generator is seeded (`random.seed(20260617)`) — output is deterministic; don't change the seed.

---

## Task 1: Enrich `gen_synthetic.py`

**Files:**
- Modify: `tools/gen_synthetic.py`

**Context:** Current per-domain loop assigns `i<3 → REUSED_CRACKED`, `3≤i<5 → REUSED_UNCRACKED`, else random PWNED/WEAK/MODERATE/strong. Pools are module-level constants; `counts` dict tracks scenario totals; the README + final `print` are built from `counts`. `PER_DOMAIN = {"CORP.LOCAL":30, "EU.CORP.LOCAL":22, "LAB.LOCAL":16}` — ample room.

- [ ] **Step 1: Add the new constants**

After the existing `REUSED_CRACKED` / `REUSED_UNCRACKED` lines (around line 97), add:

```python
# Near-duplicate families: each member goes to a distinct CRACKED account in the
# SAME domain (similarity is computed per-domain), forming a tight cluster whose
# reveal makes the shared pattern obvious. Overlap with PWNED is intentional.
SIMILAR_FAMILIES = {
    "CORP.LOCAL":    ["Summer2024!", "Summer2023!", "Summer2025!", "Summer2022!"],
    "EU.CORP.LOCAL": ["Welcome1", "Welcome2", "Welcome3"],
    "LAB.LOCAL":     ["CompanyName1", "CompanyName2", "CompanyName2024"],
}
# A known-leaked password in use but NOT cracked: kept OUT of cracks.txt, so the
# probe finds the accounts by NT hash even though they never cracked.
BANNED_IN_USE = "Br3ach3d!2024"
```

- [ ] **Step 2: Track the new counts**

In the `counts = {...}` initializer (around line 120), add the two keys:

```python
    counts = {"accounts": 0, "cracked": 0, "uncracked": 0, "reused_cracked": 0,
              "reused_uncracked": 0, "pwned": 0, "similar": 0, "banned_uncracked": 0}
```

- [ ] **Step 3: Assign families + banned in the per-domain loop**

Replace the per-domain loop header and the password-selection `if/elif` chain (the block from `for dom in DOMAINS:` through the `else: pw = strong(); cracked = random.random() < 0.5`) with:

```python
    for dom in DOMAINS:
        n = PER_DOMAIN[dom]
        fam = SIMILAR_FAMILIES[dom]
        fam_end = 5 + len(fam)  # family members occupy indices [5, fam_end)
        lines = []
        for i in range(n):
            upn = uname(dom)
            # decide this account's password + whether it's "cracked"
            roll = random.random()
            cracked = True
            if i < 3:
                # first few in each domain reuse the SAME cracked password (cross-domain cluster)
                pw = REUSED_CRACKED
                counts["reused_cracked"] += 1
            elif i < 5:
                # a couple reuse the same UNCRACKED hash (lateral risk, no cleartext revealed)
                pw = REUSED_UNCRACKED
                cracked = False
                counts["reused_uncracked"] += 1
            elif i < fam_end:
                # near-duplicate family member -> per-domain similarity cluster (cracked)
                pw = fam[i - 5]
                counts["similar"] += 1
            elif i == fam_end:
                # a known-leaked password in use but never cracked -> probe finds it by NT hash
                pw = BANNED_IN_USE
                cracked = False
                counts["banned_uncracked"] += 1
            elif roll < 0.32:
                pw = random.choice(PWNED)
                counts["pwned"] += 1
            elif roll < 0.62:
                pw = random.choice(WEAK)
            elif roll < 0.78:
                pw = random.choice(MODERATE)
            else:
                pw = strong()
                # ~half the strong ones stay uncracked (realistic: not everything cracks)
                cracked = random.random() < 0.5

            h = ntlm(pw)
            # dump line: every account loads by NT hash, uncracked at upload time
            lines.append(f"{upn}:{rid}:{LM}:{h}:::")
            rid += 1
            counts["accounts"] += 1
            if cracked:
                cracks[h] = pw
                counts["cracked"] += 1
            else:
                counts["uncracked"] += 1
```

(Leave the CORP-only CSV-injection probe block, the dump-file write, and the `cracks.txt` write exactly as they are — they follow this loop. `BANNED_IN_USE` is never added to `cracks` because its account has `cracked=False`.)

- [ ] **Step 4: Document the new scenarios in the README**

Replace the README f-string body (the `readme = f"""..."""` block, lines ~188-206) with one that adds the similarity + banned counts and the new tester guidance:

```python
    readme = f"""Synthetic test data for Password!AtTheDisco (generated by gen_synthetic.py)

Accounts: {counts['accounts']} across {len(DOMAINS)} domains
  cracked (in cracks.txt): {counts['cracked']}   uncracked: {counts['uncracked']}
  reused-cracked cluster:  {counts['reused_cracked']} accounts share "{REUSED_CRACKED}"
  reused-UNCRACKED cluster:{counts['reused_uncracked']} accounts share one NT hash (no cleartext)
  similarity families:     {counts['similar']} accounts on per-domain near-duplicate families
  banned-in-use (uncracked):{counts['banned_uncracked']} accounts use "{BANNED_IN_USE}" (NOT in cracks.txt)
  likely HIBP hits:        ~{counts['pwned']} accounts use commonly-pwned passwords

HOW TO USE (in the console, as a lead):
  1. Setup -> Upload. For EACH domain, Step 1: set Domain = the file's domain
     (e.g. CORP.LOCAL) and upload <DOMAIN>_dump.txt. Repeat for all 3 dumps.
  2. After all dumps are loaded, Step 2: apply cracks.txt ONCE. It matches by NT
     hash across every domain, so the reused passwords flip everywhere at once.
  3. Watch the BloodHound enrichment job auto-start (Upload page status line);
     re-run it any time from Setup -> Integrations -> BloodHound.

EXERCISE THE NEW FEATURES:
  - Similarity clusters + reveal: Overview -> "Password Similarity Clusters".
    CORP has {len(SIMILAR_FAMILIES['CORP.LOCAL'])} accounts on the Summer####! family, EU has
    {len(SIMILAR_FAMILIES['EU.CORP.LOCAL'])} on Welcome#, LAB has {len(SIMILAR_FAMILIES['LAB.LOCAL'])} on CompanyName#.
    Click a node to see its closest matches; as a lead, reveal it and a peer to
    see the shared pattern. Use Expand for the full-screen graph.
  - Password-in-use probe: Search -> "Password in use?".
      probe "{REUSED_CRACKED}"  -> the cracked reuse cluster
      probe "{BANNED_IN_USE}"   -> accounts still using a leaked password, found by
                                   NT hash even though they were NEVER cracked
      probe "{REUSED_UNCRACKED}" -> the uncracked-reuse cluster

Distinct cracked NT hashes in cracks.txt: {len(cracks)}
(Reuse means fewer distinct hashes than cracked accounts -- that's the point.)
"""
```

- [ ] **Step 5: Add the new counts to the final print**

Replace the closing `print(...)` lines (around 210-214) so the run summary surfaces the new scenarios:

```python
    print(f"Wrote {counts['accounts']} accounts across {len(DOMAINS)} domains to {OUT}")
    print(f"  cracked={counts['cracked']} uncracked={counts['uncracked']} "
          f"distinct-cracked-hashes={len(cracks)}")
    print(f"  reuse: {counts['reused_cracked']} share a cracked pw, "
          f"{counts['reused_uncracked']} share an uncracked hash; ~{counts['pwned']} pwned")
    print(f"  similarity-family accounts={counts['similar']} "
          f"banned-in-use(uncracked)={counts['banned_uncracked']}")
```

- [ ] **Step 6: Run the generator and spot-check the output**

Run (use the dev's working Python 3; here `py -3`):
```bash
py -3 tools/gen_synthetic.py
```
Expected: the NTLM self-tests pass (no AssertionError), it prints non-zero `similarity-family accounts` and `banned-in-use(uncracked)` counts.

Spot-check (bash):
```bash
# cracks.txt contains the families but NOT the banned-in-use password
grep -c "Summer2024!\|Welcome2\|CompanyName2024" sample_data/synthetic/cracks.txt   # >= 3
grep -c "Br3ach3d!2024" sample_data/synthetic/cracks.txt                            # 0 (must be absent)
# the banned-in-use NT hash IS present in a dump (uncracked load)
python_hash=$(py -3 -c "import sys; sys.path.insert(0,'tools'); import gen_synthetic as g; print(g.ntlm('Br3ach3d!2024'))")
grep -rl "$python_hash" sample_data/synthetic/*_dump.txt   # at least one dump
```
Expected: families present in cracks (count ≥ 3), `Br3ach3d!2024` absent from cracks (count 0), and its NT hash present in at least one dump file.

- [ ] **Step 7: Commit**

```bash
git add tools/gen_synthetic.py
git commit -m "feat(tools): synthetic data — per-domain similarity families + banned-in-use (uncracked) for probe"
```

---

## Task 2: `dev_seed.sh` always-regenerate + live verification + finish

**Files:**
- Modify: `tools/dev_seed.sh`

**Context:** `dev_seed.sh` step 1/6 currently skips generation when `sample_data/synthetic/cracks.txt` already exists, so an updated generator is ignored for devs with stale files.

- [ ] **Step 1: Always regenerate in dev_seed.sh**

Replace the step-1 block:
```sh
echo "==> 1/6 synthetic data"
if [ ! -f "$SYN/cracks.txt" ]; then "$PY" tools/gen_synthetic.py; else echo "    present ($SYN)"; fi
```
with:
```sh
echo "==> 1/6 synthetic data"
"$PY" tools/gen_synthetic.py
```
(`$PY` is the runtime-verified Python 3 the script already resolves; `$SYN` may now be unused — if `gofmt`-style "unused var" isn't a concern for shell, leave it; if `$SYN` is referenced elsewhere in the script, keep its assignment.)

- [ ] **Step 2: Commit**

```bash
git add tools/dev_seed.sh
git commit -m "chore(tools): dev_seed always regenerates synthetic data so generator updates take effect"
```

- [ ] **Step 3: Regenerate + load a fresh audit**

Stop is not required (no binary change). Regenerate and load into a fresh audit (server already running on :8443):
```bash
py -3 tools/gen_synthetic.py
PATD_OP=watson PATD_PW=discotime PATD_PASSPHRASE=disco-vault-2026 \
  bash tools/load_sample.sh sample_data/synthetic http://127.0.0.1:8443
```
Expected: login → (unlock) → create+open audit → upload 3 dumps → apply cracks → summary with cracked/uncracked counts.

- [ ] **Step 4: Live Playwright verification (as lead `watson`)**

Login (`watson`/`discotime`), unlock (`disco-vault-2026`), switch to the new "Sample data (synthetic)" audit:
- **Overview → Password Similarity Clusters**: clusters render with edges. Click a CORP node on the Summer family → its peers are the other Summer-year accounts; reveal the node and a peer → cleartext shows `Summer2024!` / `Summer2023!` (visibly the same stem). Expand opens the modal.
- **Search → Password in use?**: probe `Br3ach3d!2024` → returns the uncracked accounts using it (found by NT hash, never cracked); probe `Autumn#Service24` → the cracked reuse cluster. (Reveal stays lead-gated.)
- Assert the browser console has no 4xx/error noise.

- [ ] **Step 5: Finish the branch**

Use **superpowers:finishing-a-development-branch**: this is tooling-only (no app code), so the Go/web suites are unaffected — still run `go build ./... && go test ./...` and `(cd web && npx tsc --noEmit && npm run build)` as a sanity check that nothing was disturbed, then merge to `main`. No version tag is needed for a dev-tooling change (the running binary is unchanged); if the user prefers a tag, use a patch bump. (Pushing stays deferred per the user's standing preference.)

---

## Self-Review notes (for the controller)
- **Spec coverage:** similarity families (T1 S1/S3), banned-in-use uncracked (T1 S1/S3), README doc (T1 S4), counts (T1 S2/S5), dev_seed always-regen (T2 S1), verify (T1 S6 + T2 S3/S4). ✓
- **Consistency:** `SIMILAR_FAMILIES` keys match `DOMAINS`; index bands (`i<3`, `<5`, `<fam_end`, `==fam_end`, else) are contiguous and within `PER_DOMAIN`; `BANNED_IN_USE` only on `cracked=False` accounts → never in `cracks`; README/print read the same `counts` keys added in S2. ✓
- **Crack-global constraint honored:** banned-in-use excluded from `cracks.txt` (T1 S6 asserts count 0). ✓
- **No app code changed** — no Go/web gate required beyond the sanity build in T2 S5.
