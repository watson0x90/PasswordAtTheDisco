# Sample-Data Refresh for the New Features — Design

**Date:** 2026-06-20
**Topic:** Enrich the synthetic sample-data generator so one loaded audit deliberately exercises the recently shipped features — the Password Similarity Clusters graph + click-to-explain + lead reveal, and the password-in-use probe (incl. finding *uncracked* accounts) — on top of the existing reuse / HIBP / weak-password scenarios.

## Problem

`tools/gen_synthetic.py` produces a good multi-domain dataset (reuse clusters, HIBP hits, weak/strong mix, an uncracked-hash cluster, a CSV-injection probe), but it predates the v2.16/v2.17 features:
- **Similarity clusters + reveal** only fire on *accidental* near-duplicates today; there are no deliberate same-domain near-duplicate *families*, so clusters are sparse and the reveal shows no clear pattern.
- **Password-in-use probe** is exercisable via the existing reuse clusters, but nothing is documented for it, and there's no crisp "banned password used by *uncracked* accounts" case that showcases the probe finding accounts by NT-hash without a crack.

`sample_data/` is **gitignored** (`.gitignore:192`), so the committed artifact is the generator. Devs (and `tools/dev_seed.sh`) regenerate locally.

## Decision

Enrich `gen_synthetic.py` with (1) deliberate per-domain similarity families and (2) a banned-password-in-use scenario on uncracked accounts, keep all existing scenarios, regenerate the README to document what to click/probe, and make `dev_seed.sh` always regenerate so updates take effect. Approved via brainstorming. Single enriched dataset (no second audit / Compare seed). `gen_bh_sample.py` is out of scope (needs a live BloodHound lab to regenerate).

**Key constraint (verified):** the crack file matches by NT hash **globally** (one `hash:password` line flips every account with that hash). So a password is either cracked (in `cracks.txt`) or not — it can't be "cracked for some, uncracked for others." The probe-finds-uncracked demo therefore uses a banned password assigned only to **uncracked** accounts and deliberately **omitted** from `cracks.txt`; the probe still finds them because it hashes the candidate and matches stored NT hashes.

## A. `tools/gen_synthetic.py` — deliberate similarity families

Add a per-domain family map (each member a near-duplicate of the others so the per-domain similarity pass scores them ≥ 0.7 and they cluster tightly; revealing shows the increment pattern):

```python
# Near-duplicate families: members assigned to several CRACKED accounts in the
# SAME domain (similarity is computed per-domain), so they form a tight cluster
# whose reveal makes the shared pattern obvious.
SIMILAR_FAMILIES = {
    "CORP.LOCAL":    ["Summer2024!", "Summer2023!", "Summer2025!", "Summer2022!"],
    "EU.CORP.LOCAL": ["Welcome1", "Welcome2", "Welcome3"],
    "LAB.LOCAL":     ["CompanyName1", "CompanyName2", "CompanyName2024"],
}
```
In the per-domain account loop, after the existing reuse slots (i 0-2 = `REUSED_CRACKED`, i 3-4 = `REUSED_UNCRACKED`), assign the next `len(family)` accounts each one distinct family member (cracked → added to `cracks` like any cracked pw). Track a `counts["similar"]` total. Overlap with `PWNED` (`Summer2024!`, `Welcome1`) is fine and intentional (an account can be both pwned and in a similarity cluster). The remaining accounts keep the existing random PWNED/WEAK/MODERATE/strong logic.

## B. `tools/gen_synthetic.py` — banned-password-in-use (uncracked)

Add a recognizable "known-leaked" password used only by uncracked accounts and never cracked:

```python
# A "known-leaked" password in use but NOT cracked. The probe finds these by NT
# hash even though they never appear in cracks.txt -- the probe's superpower.
BANNED_IN_USE = "Br3ach3d!2024"
```
Assign it to a small fixed number of accounts (e.g. 3) across domains, loaded **uncracked** (dump line carries `ntlm(BANNED_IN_USE)`; do **not** add it to `cracks`). Track `counts["banned_uncracked"]`. Place these after the family slots in the loop (e.g. the next 1 account in each of the 3 domains → 3 total), so they're spread but bounded. `PER_DOMAIN` (30/22/16) has ample room.

(The existing `REUSED_UNCRACKED` = `Q9x!Lateral$Move7` cluster also remains probe-findable; `BANNED_IN_USE` is the headline "leaked credential" demo.)

## C. `tools/gen_synthetic.py` — README regeneration

Extend the generated `README.txt` to document the new scenarios and the exact tester actions:
- "Similarity clusters: CORP has 4 accounts on the Summer####! family, EU has 3 on Welcome#, LAB has 3 on CompanyName#. Overview → Password Similarity Clusters → click a node; as a lead, reveal it and a peer to see the shared pattern."
- "Password-in-use probe (Search → Password in use?): probe `Autumn#Service24` → the cracked reuse cluster; probe `Br3ach3d!2024` → 3 accounts still using a leaked password even though they were never cracked (found by NT hash); probe `Q9x!Lateral$Move7` → the uncracked-reuse cluster."
- Keep the existing upload/apply-cracks instructions and counts; add `similar` and `banned_uncracked` to the printed counts.

## D. `tools/dev_seed.sh` — always regenerate

Currently: `if [ ! -f "$SYN/cracks.txt" ]; then "$PY" tools/gen_synthetic.py; else echo "    present"; fi`. Change to **always** run the generator (it's deterministic and fast), so an updated generator actually refreshes a dev's local data instead of being skipped when stale files exist:
```sh
echo "==> 1/6 synthetic data"
"$PY" tools/gen_synthetic.py
```

## Out of scope
- `gen_bh_sample.py` (the BloodHound-lab dataset) — needs a live BHE to regenerate; can get the same families later when regenerated against a lab. Noted, not changed here.
- A second audit / Compare seed (the diff-cohort demo) — deferred per the brainstorm.
- Any app/engine change — this is data-tooling only; the features themselves are unchanged.

## Testing
- **Generator runs:** `py -3 tools/gen_synthetic.py` (or the dev's working python) succeeds, its NTLM self-tests pass, and it prints non-zero `similar` and `banned_uncracked` counts. Spot-check the output: each `<DOMAIN>_dump.txt` contains the family hashes; `cracks.txt` contains the family passwords but **not** `Br3ach3d!2024`; the dump for the banned accounts carries `ntlm("Br3ach3d!2024")`.
- **Determinism:** the seed (`random.seed(20260617)`) is unchanged, so output is reproducible. (No unit test framework for this script; the in-script NTLM self-tests + a manual count check suffice — consistent with it being a dev tool.)
- **Live (load + verify):** regenerate, load via `tools/load_sample.sh sample_data/synthetic` (or `dev_seed.sh`), then in the console (lead): Overview → Password Similarity Clusters shows clusters with edges; clicking a Summer-family node lists same-family peers; reveal shows `Summer2024!`/`Summer2023!`/… (visibly similar). Search → Password in use?: `Br3ach3d!2024` returns the 3 uncracked accounts; `Autumn#Service24` returns the cracked cluster. No console errors.
- No Go/web gates needed (no app code changes); `gofmt`/`go build`/`tsc` remain green because nothing in `cmd`/`internal`/`web` changes.
