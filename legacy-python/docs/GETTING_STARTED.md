# Getting Started with Password!AtTheDisco

Get up and running with Password!AtTheDisco in under 10 minutes.

## What You'll Need

Before starting, ensure you have:

- **Python 3.9+** installed
- **Password files** from hashcat (cracked and uncracked)
- **BloodHound Enterprise** instance with collected data (optional but recommended)
- **Have I Been Pwned NTLM database** (optional, ~2GB download)

## Quick Start

### Step 1: Install Dependencies

```bash
cd PasswordAtTheDisco
pip install -r requirements.txt
```

This installs all required Python packages including Flask, plotly, openpyxl, and more.

### Step 2: Configure BloodHound (Optional)

Copy the example configuration and add your credentials:

```bash
cp config/bloodhound.json.example config/bloodhound.json
```

Edit `config/bloodhound.json`:

```json
{
  "domain": "your-bloodhound-server.com",
  "port": 8080,
  "scheme": "https",
  "token_id": "your-token-id",
  "token_key": "your-token-key",
  "search_limit": 1,
  "controllables_limit": 10
}
```

**Test the connection:**

```bash
python main.py --test-bh
```

If successful, you'll see:
```
✓ BloodHound connection successful
✓ API version: 5.x.x
✓ Found N domains
```

### Step 3: Prepare Your Password Files

You need two files per domain in **hashcat format**:

**Cracked file** (`domain_cracked.txt`):
```
john@CORP.INT:1001:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::Password123
admin@CORP.INT:500:aad3b435b51404eeaad3b435b51404ee:5F4DCC3B5AA765D61D8327DEB882CF99:::Welcome1!
```

**Uncracked file** (`domain_uncracked.txt`):
```
guest@CORP.INT:501:aad3b435b51404eeaad3b435b51404ee:2B576ACBE6BCFDA7294D6BD18041B8FE:::
service@CORP.INT:1002:aad3b435b51404eeaad3b435b51404ee:3F8D129FB98D6C2AE5BC47A10BF95E1D:::
```

**How to generate these files with hashcat:**

```bash
# Extract cracked passwords
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > domain_cracked.txt

# Extract uncracked hashes
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > domain_uncracked.txt
```

### Step 4: Run Your First Audit

Analyze a single domain:

```bash
python main.py -d "CORP.INT:domain_cracked.txt:domain_uncracked.txt"
```

**What happens:**
1. ⏳ Loads word lists (forbidden words, dictionary, etc.)
2. 🔍 Analyzes each password for complexity, patterns, similarities
3. 🌐 Queries BloodHound for privilege data (if configured)
4. 🔐 Checks passwords against HIBP breach database (if configured)
5. 📊 Calculates risk scores (CVSS-style)
6. 📁 Generates reports in multiple formats

**Output location:**
```
reports/CORP-2025-10-21-143022/
├── csv/                  # Data export
├── excel/                # Actionable remediation reports
├── html/                 # Interactive dashboards
├── markdown/             # Detailed analysis
└── pdf/                  # PDF versions
```

### Step 5: View Your Reports

**Start the built-in web server:**

```bash
python main.py -s
```

Open your browser to: `http://localhost:8008`

You'll see an interactive menu with:
- **Combined Dashboard** - Overview of all domains
- **Domain-Specific Reports** - Detailed per-domain analysis
- **Search Interface** - Find accounts by username, password, risk level
- **Executive Summary** - Security posture scoring and ROI analysis

### Step 6: Understand Your Results

#### Risk Levels

| Risk Level | Score Range | Color | Action Required |
|------------|-------------|-------|-----------------|
| **Critical** | 8.0-10.0 | 🔴 Red | Immediate reset |
| **High** | 6.0-7.9 | 🟠 Orange | Priority remediation |
| **Medium** | 4.0-5.9 | 🟡 Yellow | Scheduled reset |
| **Low** | 0.0-3.9 | 🟢 Green | Monitor |

#### Risk Factors

Your risk score is calculated from:

- **Base Score**: Password complexity, length, dictionary checks, HIBP exposure
- **Temporal Score**: Password age, compliance with policy, expiration settings
- **Environmental Score**: BloodHound privileges, password sharing, domain risk

**Example high-risk account:**
```
Username: admin@CORP.INT
Password: Password123!
Risk Score: 10.0 (CRITICAL)
Reasons:
  ✗ HIBP: 2.4 million breach occurrences
  ✗ DA Pathway: Yes
  ✗ Common password
  ✗ 189 days past policy expiration
```

## Next Steps

### Enable HIBP Breach Checking

Download the Have I Been Pwned NTLM database (~2GB):

```bash
# Clone the downloader
git submodule add https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader.git

# Follow their instructions to download pwnedpasswords_ntlm.txt
```

Configure HIBP:

```bash
cp config/hibp.json.example config/hibp.json
```

Edit `config/hibp.json`:

```json
{
  "ntlm_hash_file": "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt",
  "enable_lookup": true,
  "cache_size": 1000000,
  "prefix_length": 5
}
```

**First run builds an index** (5-10 minutes), subsequent runs are instant.

### Analyze Multiple Domains

```bash
python main.py \
  -d "CORP.INT:corp_cracked.txt:corp_uncracked.txt" \
     "SUBSIDIARY.COM:sub_cracked.txt:sub_uncracked.txt"
```

This enables **cross-domain analysis** showing:
- Passwords shared between domains
- Lateral movement risks
- Combined security posture

### Customize Password Policy

Edit `lists/password_policy.json` to match your organizational requirements:

```json
{
  "CORP.INT": {
    "policy": {
      "min_length": 14,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_password_age_days": 90
    }
  }
}
```

Accounts will be scored against their domain-specific policy.

### Export Actionable Reports

The Excel report (`excel/DOMAIN-actionable.xlsx`) provides:
- **Risk Summary** sheet - High-level metrics
- **DA Pathways** - Accounts with paths to Domain Admin
- **Top Controllables** - Accounts controlling many objects
- **Non-Expiring** - Passwords set to never expire
- **Out of Compliance** - Aged passwords
- **Similar Passwords** - Reuse patterns
- **HIBP Breached** - Known exposed passwords

Each sheet includes **recommended actions** for remediation.

## Common Issues

### "Configuration file not found"

Ensure you've copied the example files:

```bash
cp config/bloodhound.json.example config/bloodhound.json
cp config/hibp.json.example config/hibp.json
cp config/hashcat.json.example config/hashcat.json
```

### "BloodHound connection failed"

Test your connection:

```bash
python main.py --test-bh
```

Verify:
- Server is accessible (ping/curl)
- Token ID and key are correct
- Scheme matches (http vs https)

### "No matching accounts found"

Ensure username format matches BloodHound:
- Should be: `user@DOMAIN.INT`
- Not: `DOMAIN\user` or `user`

### "File not in hashcat format"

Check file structure:
```
username@DOMAIN:RID:LMhash:NTLMhash:::password
```

Verify fields are separated by colons.

## Getting Help

- **Documentation**: See `docs/` directory for comprehensive guides
- **Issues**: Report bugs at [GitHub Issues](https://github.com/your-repo/issues)
- **Configuration**: See `docs/CONFIGURATION.md` for all settings
- **Troubleshooting**: See `docs/TROUBLESHOOTING.md` for common problems

## What's Next?

1. **Read the User Guide** - `docs/USER_GUIDE.md` for detailed usage
2. **Understand Reports** - `docs/REPORTS.md` for report format details
3. **Configure Integrations** - `docs/INTEGRATIONS.md` for BloodHound/HIBP setup
4. **Learn Scoring** - `docs/SCORING_SYSTEM.md` for risk calculation details

---

**You're ready to start auditing!** 🎉

Run your first analysis and explore the interactive reports. The tool will guide you through identifying high-risk passwords and prioritizing remediation efforts.
