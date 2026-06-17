"""Self-contained synthetic test-data generator for Password!AtTheDisco.

No BloodHound, no legacy `core/`, no network. Produces realistic multi-domain
secretsdump-style dumps + a hashcat-style crack file with REAL NTLM hashes
(MD4 of UTF-16LE), so reuse correlation and HIBP matching behave like production.

Output (under sample_data/synthetic/):
  <DOMAIN>_dump.txt   -- upload as the Step 1 "Dump file" for that domain
  cracks.txt          -- after loading every domain, apply as the Step 2 crack file
  README.txt          -- the upload order + what each scenario exercises

What it exercises:
  - multi-domain ingest (3 domains)
  - cross-domain password reuse (shared NTLM -> reuse clusters + lateral risk)
  - shared *uncracked* NTLM (lateral movement risk with no cleartext)
  - weak / wordlist passwords (common, dictionary, keyboard, forbidden-term)
  - known-pwned passwords (HIBP hits if the NTLM index is built)
  - strong unique passwords (low-risk control)
  - a mix of cracked vs uncracked accounts

NOTE on BloodHound DA-pathway enrichment: these usernames are synthetic, so a
live BHE will return no DA data for them (the enrichment job still runs end-to-end
and completes -- it just finds no privileged paths). To exercise real DA pathways,
use generate.py instead (it pulls real BHE users), or map a few of these names to
real users in your lab.
"""
import os
import random
import struct

random.seed(20260617)
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_data", "synthetic")
LM = "aad3b435b51404eeaad3b435b51404ee"  # empty-LM placeholder (as secretsdump emits)


# --- pure-Python MD4 (NTLM = MD4(UTF-16LE(password))) -----------------------
def _md4(message: bytes) -> bytes:
    h0, h1, h2, h3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def lr(v, s):
        v &= 0xFFFFFFFF
        return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF

    msg = bytearray(message)
    ml = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)
    for i in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[i:i + 64])
        A, B, C, D = h0, h1, h2, h3
        for r in (0, 4, 8, 12):
            A = lr(A + F(B, C, D) + X[r], 3)
            D = lr(D + F(A, B, C) + X[r + 1], 7)
            C = lr(C + F(D, A, B) + X[r + 2], 11)
            B = lr(B + F(C, D, A) + X[r + 3], 19)
        for r in (0, 1, 2, 3):
            A = lr(A + G(B, C, D) + X[r] + 0x5A827999, 3)
            D = lr(D + G(A, B, C) + X[r + 4] + 0x5A827999, 5)
            C = lr(C + G(D, A, B) + X[r + 8] + 0x5A827999, 9)
            B = lr(B + G(C, D, A) + X[r + 12] + 0x5A827999, 13)
        for r in (0, 2, 1, 3):
            A = lr(A + H(B, C, D) + X[r] + 0x6ED9EBA1, 3)
            D = lr(D + H(A, B, C) + X[r + 8] + 0x6ED9EBA1, 9)
            C = lr(C + H(D, A, B) + X[r + 4] + 0x6ED9EBA1, 11)
            B = lr(B + H(C, D, A) + X[r + 12] + 0x6ED9EBA1, 15)
        h0 = (h0 + A) & 0xFFFFFFFF
        h1 = (h1 + B) & 0xFFFFFFFF
        h2 = (h2 + C) & 0xFFFFFFFF
        h3 = (h3 + D) & 0xFFFFFFFF
    return struct.pack("<4I", h0, h1, h2, h3)


def ntlm(pw: str) -> str:
    return _md4(pw.encode("utf-16-le")).hex().upper()


# self-test against known NTLM vectors before generating anything
assert ntlm("") == "31D6CFE0D16AE931B73C59D7E0C089C0", "MD4 self-test failed (empty)"
assert ntlm("password") == "8846F7EAEE8FB117AD06BDD830B7586C", "MD4 self-test failed (password)"


# --- password pools ---------------------------------------------------------
# Commonly-pwned (very likely present in the HIBP NTLM corpus):
PWNED = ["Password1", "Welcome1", "P@ssw0rd", "Summer2024!", "Letmein1",
         "Football1", "Monkey123", "Qwerty123", "Passw0rd!", "Dragon123"]
# Wordlist-weak (common/dictionary/keyboard/forbidden-term flavors):
WEAK = ["Spring2024!", "Winter2023!", "Changeme123", "Admin@123",
        "Qwertyuiop1", "Zxcvbnm123!", "CompanyName1", "Helpdesk2024"]
MODERATE = ["Hannah2021!", "BlueOcean77", "Maple$yrup9", "Th1stle#Down", "Gr4nite!Peak"]
# Deliberately reused across many accounts / domains (lateral movement):
REUSED_CRACKED = "Autumn#Service24"     # appears cracked in several domains
REUSED_UNCRACKED = "Q9x!Lateral$Move7"  # appears UNCRACKED in several domains (shared NT, no cleartext)

FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "mallory", "olivia", "peggy", "trent", "victor", "wendy",
         "sybil", "craig", "dan", "faythe", "nadia", "oscar", "rita", "walter"]
LAST = ["smith", "jones", "patel", "garcia", "kim", "nguyen", "khan", "rossi",
        "novak", "haas", "ford", "stone", "vance", "irwin", "blair", "munoz"]

DOMAINS = ["CORP.LOCAL", "EU.CORP.LOCAL", "LAB.LOCAL"]
PER_DOMAIN = {"CORP.LOCAL": 30, "EU.CORP.LOCAL": 22, "LAB.LOCAL": 16}


def strong():
    chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(random.choice([15, 16, 18])))


def main():
    os.makedirs(OUT, exist_ok=True)
    rid = 1100
    used_names = set()
    # crack map: NT hash -> cleartext (deduped; NTLM is unsalted so one line/hash flips all)
    cracks = {}
    counts = {"accounts": 0, "cracked": 0, "uncracked": 0, "reused_cracked": 0,
              "reused_uncracked": 0, "pwned": 0}

    def uname(dom):
        while True:
            n = f"{random.choice(FIRST)}.{random.choice(LAST)}"
            if (n, dom) not in used_names:
                used_names.add((n, dom))
                return f"{n}@{dom}"

    for dom in DOMAINS:
        n = PER_DOMAIN[dom]
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

        with open(os.path.join(OUT, f"{dom}_dump.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    # one crack file covering all domains (matched globally by NT hash)
    with open(os.path.join(OUT, "cracks.txt"), "w", encoding="utf-8") as f:
        for h, pw in sorted(cracks.items()):
            f.write(f"{h}:{pw}\n")

    readme = f"""Synthetic test data for Password!AtTheDisco (generated by gen_synthetic.py)

Accounts: {counts['accounts']} across {len(DOMAINS)} domains
  cracked (in cracks.txt): {counts['cracked']}   uncracked: {counts['uncracked']}
  reused-cracked cluster:  {counts['reused_cracked']} accounts share "{REUSED_CRACKED}"
  reused-UNCRACKED cluster:{counts['reused_uncracked']} accounts share one NT hash (no cleartext)
  likely HIBP hits:        ~{counts['pwned']} accounts use commonly-pwned passwords

HOW TO USE (in the console, as a lead):
  1. Setup -> Upload. For EACH domain, Step 1: set Domain = the file's domain
     (e.g. CORP.LOCAL) and upload <DOMAIN>_dump.txt. Repeat for all 3 dumps.
  2. After all dumps are loaded, Step 2: apply cracks.txt ONCE. It matches by NT
     hash across every domain, so the reused passwords flip everywhere at once.
  3. Watch the BloodHound enrichment job auto-start (Upload page status line);
     re-run it any time from Setup -> Integrations -> BloodHound.

Distinct cracked NT hashes in cracks.txt: {len(cracks)}
(Reuse means fewer distinct hashes than cracked accounts -- that's the point.)
"""
    with open(os.path.join(OUT, "README.txt"), "w", encoding="utf-8") as f:
        f.write(readme)

    print(f"Wrote {counts['accounts']} accounts across {len(DOMAINS)} domains to {OUT}")
    print(f"  cracked={counts['cracked']} uncracked={counts['uncracked']} "
          f"distinct-cracked-hashes={len(cracks)}")
    print(f"  reuse: {counts['reused_cracked']} share a cracked pw, "
          f"{counts['reused_uncracked']} share an uncracked hash; ~{counts['pwned']} pwned")


if __name__ == "__main__":
    main()
