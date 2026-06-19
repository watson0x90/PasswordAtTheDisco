"""Large, realistic sample-data generator seeded from the real BloodHound DB.

Reads the real user list dumped by `tools/bhdump` (sample_data/bloodhound/users.json)
and produces a large multi-domain dataset for exercising EVERY report and dashboard
at scale:

  - the REAL BHE users (kept verbatim) -> live BHE enrichment populates their
    DA pathways / kerberoastable / AS-REP / controlled-objects / pwd-age, so the
    BloodHound-specific dashboards show real graph data;
  - a large SYNTHETIC population modelled on the same domains/name patterns ->
    volume for the count / reuse / HIBP / complexity / length / risk dashboards,
    the cross-domain bridge matrix, and the network graph;
  - a `bheusers.json` export (synthetic users only) giving them realistic
    pwd-last-set / never-expires / controlled-object distributions.

Credentials are 100% SYNTHETIC (real MD4/NTLM of generated passwords) — no real
hashes or cracked passwords ever. Output lives under gitignored sample_data/.

Output (sample_data/bhsample/):
  <DOMAIN>_dump.txt   secretsdump dumps (real + synthetic), one per domain
  cracks.txt          hashcat-style crack file (matched globally by NT hash)
  bheusers.json       BloodHound users export for the synthetic accounts only
  README.txt          load order + what each scenario exercises

Load order (the disposable instance must have BHE enabled):
  1. upload each <DOMAIN>_dump.txt
  2. apply cracks.txt once
  3. run BloodHound enrichment (real users get DA/SPN/controlled)
  4. upload bheusers.json (synthetic users get pwd-age/never-expires/controlled)
"""
import json
import os
import random
import struct

random.seed(20260618)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BH_USERS = os.path.join(ROOT, "sample_data", "bloodhound", "users.json")
OUT = os.path.join(ROOT, "sample_data", "bhsample")
LM = "aad3b435b51404eeaad3b435b51404ee"

TARGET_TOTAL = 2000  # real (~96) + synthetic to reach ~this many


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


assert ntlm("") == "31D6CFE0D16AE931B73C59D7E0C089C0"
assert ntlm("password") == "8846F7EAEE8FB117AD06BDD830B7586C"


# --- password pools ---------------------------------------------------------
PWNED = ["Password1", "Welcome1", "P@ssw0rd", "Summer2024!", "Letmein1",
         "Football1", "Monkey123", "Qwerty123", "Passw0rd!", "Dragon123",
         "Winter2024!", "Baseball1", "Trustno1!", "Iloveyou1", "Sunshine1",
         "Master123", "Shadow123", "Superman1", "Princess1", "Welcome123"]
WEAK = ["Spring2024!", "Winter2023!", "Changeme123", "Admin@123", "Qwertyuiop1",
        "Zxcvbnm123!", "Helpdesk2024", "Company1!", "Password2024", "Asdfghjkl1"]
MODERATE = ["Hannah2021!", "BlueOcean77", "Maple$yrup9", "Th1stle#Down",
            "Gr4nite!Peak", "Cobalt$Fern42", "Amber*Quartz8", "Vivid#Harbor5"]
# Reuse clusters: (password, cracked) shared by many accounts across domains ->
# reuse groups, cross-domain bridges, network-graph edges, shared-DA escalation.
REUSE = [
    ("Autumn#Service24", True), ("Helpdesk!Reset24", True), ("Backup$vc2023!", False),
    ("Q9x!Lateral$Move7", False), ("ChangeMe!Now2024", True), ("Svc#Account#22", True),
    ("LegacyApp$Pass1", True), ("Domain!Shared99", False), ("Team#Vault2024", True),
    ("Old$Migration07", False),
]
# Similarity families: near-duplicate cracked passwords within a domain ->
# the password-similarity network + similarity buckets.
SIMFAM = [
    ["Spring2024!", "Spring2025!", "Spring2023!", "Spring2024@", "Spring2024#"],
    ["Liverpool99", "Liverpool98", "Liverpool97", "Liverpool00"],
    ["Marketing#1", "Marketing#2", "Marketing#3", "Marketing#4"],
    ["Falcon$2024", "Falcon$2023", "Falcon$2022", "Falcon$2025"],
]

FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "mallory", "olivia", "peggy", "trent", "victor", "wendy",
         "sybil", "craig", "dan", "faythe", "nadia", "oscar", "rita", "walter",
         "henry", "isla", "jack", "kate", "liam", "mia", "noah", "ava", "ethan",
         "lucas", "emma", "owen", "ruby", "sean", "tara", "umar", "vera", "will",
         "xena", "yuri", "zoe", "amir", "bella", "cody", "dina", "elias"]
LAST = ["smith", "jones", "patel", "garcia", "kim", "nguyen", "khan", "rossi",
        "novak", "haas", "ford", "stone", "vance", "irwin", "blair", "munoz",
        "park", "reed", "shah", "tran", "ali", "bauer", "cole", "diaz", "evans",
        "frost", "gupta", "hill", "ito", "jain", "klein", "lopez", "meyer",
        "owens", "price", "quinn", "ramos", "scott", "tucker", "ueda", "vogel"]
SVC = ["svc-backup", "svc-sql", "svc-web", "svc-app", "svc-scan", "svc-task",
       "svc-monitor", "svc-exchange", "svc-sharepoint", "svc-jenkins", "svc-ftp",
       "sql-agent", "iis-apppool", "backup-agent", "task-runner", "veeam-svc"]


def strong():
    chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(random.choice([15, 16, 18, 20])))


def synth_sid(domain, n):
    base = 1000000 + (abs(hash(domain)) % 9000000)
    return f"S-1-5-21-{base}-{base + 13}-{base + 99}-{1100 + n}"


def main():
    os.makedirs(OUT, exist_ok=True)
    with open(BH_USERS, encoding="utf-8") as f:
        real_users = json.load(f)

    domains = sorted({u["domain"] for u in real_users})
    real_by_dom = {d: [u for u in real_users if u["domain"] == d] for d in domains}
    da_keys = {f"{u['username'].lower()}@{u['domain']}" for u in real_users if u.get("da_domains")}

    # distribute the synthetic remainder across the real domains, weighted by size
    n_real = len(real_users)
    n_synth = max(0, TARGET_TOTAL - n_real)
    weights = {d: max(1, len(real_by_dom[d])) for d in domains}
    wsum = sum(weights.values())
    synth_per = {d: int(round(n_synth * weights[d] / wsum)) for d in domains}

    used = {(u["username"].lower(), u["domain"]) for u in real_users}
    cracks = {}          # NT hash -> cleartext
    da_hashes = set()     # NT hashes used by any DA account (for shared-DA escalation)
    rid = 5000
    dump_lines = {d: [] for d in domains}
    bheusers = []
    counts = {"real": 0, "synth": 0, "cracked": 0, "uncracked": 0, "reuse": 0,
              "pwned": 0, "sim": 0, "da_cracked": 0}

    def emit(upn, domain, pw, cracked, is_da):
        nonlocal rid
        h = ntlm(pw)
        dump_lines[domain].append(f"{upn}:{rid}:{LM}:{h}:::")
        rid += 1
        if is_da:
            da_hashes.add(h)
            if cracked:
                counts["da_cracked"] += 1
        if cracked:
            cracks[h] = pw
            counts["cracked"] += 1
        else:
            counts["uncracked"] += 1
        return h

    def pick_password(i):
        """Return (pw, cracked, kind) using a realistic distribution + reuse."""
        roll = random.random()
        if roll < 0.18:
            pw, cr = random.choice(REUSE)
            counts["reuse"] += 1
            return pw, cr, "reuse"
        if roll < 0.26:
            pw = random.choice(random.choice(SIMFAM))
            counts["sim"] += 1
            return pw, True, "sim"
        if roll < 0.48:
            counts["pwned"] += 1
            return random.choice(PWNED), True, "pwned"
        if roll < 0.66:
            return random.choice(WEAK), True, "weak"
        if roll < 0.80:
            return random.choice(MODERATE), True, "moderate"
        pw = strong()
        return pw, random.random() < 0.45, "strong"

    # --- REAL users: verbatim names (live enrichment will match them in BHE) ---
    for d in domains:
        for i, u in enumerate(real_by_dom[d]):
            upn = f"{u['username']}@{d}"
            key = f"{u['username'].lower()}@{d}"
            is_da = key in da_keys
            # bias: crack most DA + kerberoastable accounts (high-value, realistic)
            pw, cracked, kind = pick_password(i)
            if (is_da or u.get("hasspn")) and random.random() < 0.7:
                cracked = True
            emit(upn, d, pw, cracked, is_da)
            counts["real"] += 1

    # --- SYNTHETIC users: realistic names + properties, volume ---
    def synth_name(d):
        while True:
            r = random.random()
            if r < 0.15:
                n = random.choice(SVC) + str(random.randint(1, 40))
            elif r < 0.45:
                n = random.choice(FIRST)
            else:
                n = f"{random.choice(FIRST)}.{random.choice(LAST)}"
            if (n.lower(), d) not in used:
                used.add((n.lower(), d))
                return n

    sid_n = 0
    for d in domains:
        for i in range(synth_per[d]):
            sam = synth_name(d)
            upn = f"{sam}@{d}"
            pw, cracked, kind = pick_password(i)
            # a slice of synthetic accounts share a hash with a DA account -> shared-DA escalation
            if random.random() < 0.04 and da_hashes:
                # reuse an existing DA hash by reusing the SAME cluster password set;
                # approximate by forcing a known reuse password that a DA user also has
                pw, cracked = random.choice(REUSE)
            emit(upn, d, pw, cracked, is_da=False)
            counts["synth"] += 1

            # bheusers export entry (synthetic only): pwd-age / never-expires / controlled
            sid_n += 1
            pwd_age_days = random.choice([5, 30, 90, 200, 400, 800, 1500])  # some stale
            pwd_last_set = 1750000000 - pwd_age_days * 86400
            never = random.random() < 0.35
            controllables = 0
            cr = random.random()
            if cr < 0.04:
                controllables = random.randint(101, 400)   # high-privilege
            elif cr < 0.14:
                controllables = random.randint(1, 60)
            bheusers.append({
                "username": upn, "domain": d,
                "enabled": random.random() < 0.92,
                "pwdlastset": pwd_last_set,
                "pwdneverexpires": never,
                "lastlogon": 1750000000 - random.randint(0, 200) * 86400,
                "controllables": controllables,
                "objectid": synth_sid(d, sid_n),
            })

    # CSV/formula-injection probe (CWE-1236) in the first domain
    probe_dom = domains[0]
    dump_lines[probe_dom].append(f"=injection.test@{probe_dom}:{rid}:{LM}:{ntlm('Probe!Inject1')}:::")
    rid += 1
    counts["uncracked"] += 1

    # --- write outputs ---
    for d in domains:
        with open(os.path.join(OUT, f"{d}_dump.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(dump_lines[d]) + "\n")
    with open(os.path.join(OUT, "cracks.txt"), "w", encoding="utf-8") as f:
        for h, pw in sorted(cracks.items()):
            f.write(f"{h}:{pw}\n")
    with open(os.path.join(OUT, "bheusers.json"), "w", encoding="utf-8") as f:
        json.dump(bheusers, f, indent=1)

    total = counts["real"] + counts["synth"] + 1
    readme = f"""Large BHE-seeded sample data for Password!AtTheDisco (gen_bh_sample.py)

Accounts: {total} across {len(domains)} domains ({', '.join(domains)})
  real BHE users (live-enrichable): {counts['real']}
  synthetic (volume + bheusers.json): {counts['synth']}
  cracked: {counts['cracked']}   uncracked: {counts['uncracked']}
  distinct cracked NT hashes: {len(cracks)}   reuse-cluster uses: {counts['reuse']}
  similarity-family uses: {counts['sim']}   likely-HIBP: ~{counts['pwned']}
  DA accounts cracked: {counts['da_cracked']}

LOAD ORDER (instance must have BHE enabled so the real users enrich):
  1. upload each <DOMAIN>_dump.txt (Setup -> Upload, Domain = the file's domain)
  2. apply cracks.txt once (matched globally by NT hash)
  3. run BloodHound enrichment (real users get DA / kerberoastable / AS-REP /
     controlled-objects / pwd-age from the live graph)
  4. upload bheusers.json (synthetic users get pwd-last-set / never-expires /
     controlled-object volume) via POST /api/upload/bheusers

Credentials are 100% synthetic (MD4/NTLM of generated passwords). Real usernames
come from the BloodHound lab; this whole tree is gitignored.
"""
    with open(os.path.join(OUT, "README.txt"), "w", encoding="utf-8") as f:
        f.write(readme)

    print(f"Wrote {total} accounts across {len(domains)} domains to {OUT}")
    print(f"  real={counts['real']} synth={counts['synth']} cracked={counts['cracked']} "
          f"uncracked={counts['uncracked']} distinct-hashes={len(cracks)}")
    print(f"  reuse-uses={counts['reuse']} sim-uses={counts['sim']} ~pwned={counts['pwned']} "
          f"DA-cracked={counts['da_cracked']} bheusers={len(bheusers)}")


if __name__ == "__main__":
    main()
