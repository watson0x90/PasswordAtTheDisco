# Password!AtTheDisco User Guide

Complete end-to-end guide for using Password!AtTheDisco to audit and improve password security.

## Table of Contents

- [Overview](#overview)
- [Basic Workflow](#basic-workflow)
- [Single Domain Audit](#single-domain-audit)
- [Multi-Domain Audit](#multi-domain-audit)
- [Understanding Results](#understanding-results)
- [Remediation Workflow](#remediation-workflow)
- [Advanced Usage](#advanced-usage)
- [Best Practices](#best-practices)
- [Common Scenarios](#common-scenarios)

## Overview

Password!AtTheDisco is a comprehensive password auditing tool that combines password complexity analysis with Active Directory privilege data to provide risk-based security insights.

### What It Does

**Analyzes**:
- Password complexity and patterns
- Policy compliance
- Data breach exposure (HIBP)
- Active Directory privileges (BloodHound)
- Password sharing and reuse

**Produces**:
- Risk scores (CVSS-style 0-10 scale)
- Prioritized remediation lists
- Interactive reports and dashboards
- Actionable Excel spreadsheets
- Data exports for SIEM/automation

**Helps You**:
- Identify highest-risk accounts
- Prioritize remediation efforts
- Measure security posture
- Track improvement over time
- Comply with password policies

### Typical Workflow

```
1. Extract NTLM hashes from AD → SharpHound/ntdsutil
2. Crack passwords → Hashcat
3. Analyze with Password!AtTheDisco → Risk scores + Reports
4. Remediate high-risk accounts → Force resets, MFA
5. Re-audit periodically → Track improvement
```

## Basic Workflow

### Step 1: Collect NTLM Hashes

Extract NTLM hashes from Active Directory.

**Option A: Using SharpHound** (Recommended)
```powershell
# Collect AD data (includes hashes if you have DCSync rights)
.\SharpHound.exe -c All --outputdirectory C:\temp

# Extract hashes from BloodHound database
# (Requires additional tooling)
```

**Option B: Using ntdsutil**
```powershell
# On Domain Controller
ntdsutil "ac i ntds" "ifm" "create full C:\temp\dump" q q

# Extract hashes using secretsdump
secretsdump.py -ntds C:\temp\dump\Active Directory\ntds.dit \
  -system C:\temp\dump\registry\SYSTEM LOCAL > hashes.txt
```

**Option C: Using DSInternals** (PowerShell)
```powershell
# Requires DCSync rights
Get-ADReplAccount -All -Server DC01 | Format-Custom -View HashcatNT | Out-File hashes.txt
```

**Output Format**:
```
john:1001:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::
admin:500:aad3b435b51404eeaad3b435b51404ee:5F4DCC3B5AA765D61D8327DEB882CF99:::
```

### Step 2: Crack Passwords with Hashcat

Use hashcat to crack the NTLM hashes.

**Prepare hash file**:
```bash
# Ensure format is: username:hash
# If you have full format, extract just username:ntlm
awk -F: '{print $1":"$4}' hashes.txt > ntlm_only.txt
```

**Basic Cracking**:
```bash
# Wordlist attack
hashcat -m 1000 -a 0 ntlm_only.txt /usr/share/wordlists/rockyou.txt

# Wordlist with rules
hashcat -m 1000 -a 0 ntlm_only.txt wordlist.txt -r rules/best64.rule

# Mask attack (brute force)
hashcat -m 1000 -a 3 ntlm_only.txt ?u?l?l?l?l?l?d?d?s
```

**Advanced Cracking**:
```bash
# Combinator attack
hashcat -m 1000 -a 1 ntlm_only.txt wordlist1.txt wordlist2.txt

# Hybrid attack
hashcat -m 1000 -a 6 ntlm_only.txt wordlist.txt ?d?d?d?d

# With optimized kernel (faster)
hashcat -m 1000 -a 0 -O ntlm_only.txt rockyou.txt
```

**Check Progress**:
```bash
# View status
hashcat -m 1000 ntlm_only.txt --status

# Show cracked hashes
hashcat -m 1000 ntlm_only.txt --show
```

### Step 3: Generate Input Files

Create cracked and uncracked files for Password!AtTheDisco.

**Important**: Files must be in **hashcat format with usernames**:
```
user@DOMAIN.INT:RID:LMhash:NTLMhash:::password
```

**Generate Files**:
```bash
# Cracked passwords (includes plaintext)
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > domain_cracked.txt

# Uncracked hashes (no plaintext)
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > domain_uncracked.txt
```

**Verify Format**:
```bash
# Check cracked file
head -3 domain_cracked.txt
# Expected: john@CORP.INT:1001:aad3...:8846F7...::: Password123

# Check uncracked file
head -3 domain_uncracked.txt
# Expected: admin@CORP.INT:500:aad3...:5F4DCC...:::
```

### Step 4: Run Password!AtTheDisco

Analyze the password files.

```bash
python main.py -d "CORP.INT:domain_cracked.txt:domain_uncracked.txt"
```

**Expected Output**:
```
Password!AtTheDisco - Password Auditing Tool
============================================

Loading word lists...
✓ Forbidden words: 234 entries
✓ Dictionary words: 479,829 entries
✓ Common passwords: 10,000 entries
✓ Keyboard patterns: 45 entries

Processing domain: CORP.INT
  ✓ Loaded 1,234 accounts (891 cracked, 343 uncracked)
  ✓ Analyzing passwords...
  ✓ Querying BloodHound...
  ✓ Checking HIBP database...
  ✓ Calculating risk scores...
  ✓ Generating visualizations...

Generating reports...
  ✓ CSV reports
  ✓ Excel actionable report
  ✓ HTML interactive dashboard
  ✓ Markdown report
  ✓ PDF report

✓ Audit complete!
Reports saved to: reports/CORP-2025-10-21-143022/
```

### Step 5: View Reports

Open the interactive dashboard.

```bash
# Start built-in web server
python main.py -s

# Opens browser to http://localhost:8008
```

**Or open directly**:
```bash
firefox reports/latest/html/main.html
```

## Single Domain Audit

Detailed walkthrough of analyzing a single domain.

### Preparation

**1. Verify Prerequisites**:
```bash
# Check Python version (3.9+)
python3 --version

# Check dependencies
pip list | grep -E 'Flask|plotly|openpyxl'

# Test BloodHound connection
python main.py --test-bh
```

**2. Prepare Input Files**:
- `domain_cracked.txt` - Hashcat output with passwords
- `domain_uncracked.txt` - Remaining hashes without passwords

**3. Verify File Format**:
```bash
# Files should have format: user@DOMAIN:RID:LM:NTLM:::password
# Check username format (must be UPN)
head domain_cracked.txt | cut -d: -f1
# Expected: user@DOMAIN.INT (not DOMAIN\user)
```

### Running the Audit

**Basic Command**:
```bash
python main.py -d "CORP.INT:domain_cracked.txt:domain_uncracked.txt"
```

**With Custom Report Location**:
```bash
# Modify output directory in core/config.py
# REPORTS_DIR = Path("custom/path")
```

### Analysis Process

**Phase 1: Data Loading** (~10 seconds)
- Parses input files
- Validates format
- Loads word lists

**Phase 2: Password Analysis** (~1-2 min per 1000 accounts)
- Complexity assessment
- Pattern detection
- Dictionary checks
- Similarity analysis

**Phase 3: BloodHound Integration** (~30 sec per 1000 accounts)
- Account searches
- DA pathway queries
- Controlled object counts
- Property extraction

**Phase 4: HIBP Correlation** (~10-30 sec per 1000 accounts)
- Hash lookups (cache/index/file)
- Breach count extraction
- Tier assignment

**Phase 5: Scoring** (~5 seconds)
- Base score calculation
- Temporal scoring
- Environmental scoring
- Risk level assignment

**Phase 6: Report Generation** (~20-30 seconds)
- CSV export
- Excel creation
- HTML rendering
- Markdown writing
- PDF conversion (if pandoc installed)

### Interpreting Results

**Dashboard Quick View**:
1. **Security Posture Score**: Overall rating (0-100)
   - 80-100: Good
   - 60-79: Fair
   - 40-59: Poor
   - 0-39: Critical

2. **Risk Distribution**: Pie chart
   - Critical (red): Immediate action required
   - High (orange): Priority remediation
   - Medium (yellow): Scheduled resets
   - Low (green): Monitor

3. **Top Risk Accounts**: Focus here first
   - DA pathways = highest priority
   - HIBP breached = immediate reset
   - High controlled objects = review privileges

**Excel Actionable Report**:
1. Open `reports/latest/excel/CORP_actionable.xlsx`
2. Start with **DA Pathways** sheet
3. Then **HIBP Breached** sheet
4. Then **Top 100 Risks** sheet

## Multi-Domain Audit

Analyzing multiple domains simultaneously for cross-domain insights.

### Preparation

**For each domain**, prepare:
- `domain1_cracked.txt`
- `domain1_uncracked.txt`
- `domain2_cracked.txt`
- `domain2_uncracked.txt`
- etc.

**Ensure**:
- All domains collected in BloodHound
- Username formats match BloodHound (UPN)
- Sufficient resources (parallel processing)

### Running Multi-Domain Audit

**Command Format**:
```bash
python main.py \
  -d "DOMAIN1.INT:domain1_cracked.txt:domain1_uncracked.txt" \
     "DOMAIN2.COM:domain2_cracked.txt:domain2_uncracked.txt" \
     "DOMAIN3.NET:domain3_cracked.txt:domain3_uncracked.txt"
```

**Real Example**:
```bash
python main.py \
  -d "PROD.CORP.INT:prod_cracked.txt:prod_uncracked.txt" \
     "DEV.CORP.INT:dev_cracked.txt:dev_uncracked.txt" \
     "DMZ.CORP.INT:dmz_cracked.txt:dmz_uncracked.txt"
```

### Parallel Processing

Domains are processed in **parallel** for performance:

**With Animation** (default):
- Max 4 workers
- Live progress display
- Recommended for interactive use

**Without Animation**:
- Max workers = CPU count
- Faster for large audits
- Set in `config/application.json`:
  ```json
  {
    "ui": {
      "enable_animation": false
    }
  }
  ```

### Cross-Domain Analysis

Multi-domain audits enable additional insights:

**1. Shared Password Analysis**:
- Identifies identical passwords across domains
- Highlights lateral movement risks
- Shows password reuse patterns

**2. Shared Hash Analysis**:
- Finds accounts with same hash (even if uncracked)
- Indicates weak password policies
- Reveals synchronized passwords

**3. Cross-Domain Attack Paths**:
- Accounts with DA in multiple domains
- Trust relationship exploitation risks
- Combined privilege escalation paths

**4. Comparative Statistics**:
- Domain-by-domain risk comparison
- Policy compliance comparison
- Complexity distribution comparison

### Multi-Domain Reports

**Combined Reports**:
- `combined_report.csv` - All domains in one CSV
- `combined_actionable.xlsx` - Unified Excel report
- `combined_report.md` - Comprehensive Markdown
- `main.html` - Dashboard with domain selector

**Per-Domain Reports**:
- Still generated for each domain
- Accessible from main dashboard
- Independent analysis available

## Understanding Results

### Risk Scores Explained

**Risk Score Range**: 0.0 to 10.0

**Risk Levels**:
| Score | Level | Color | Priority | Action Timeline |
|-------|-------|-------|----------|-----------------|
| 8.0-10.0 | Critical | Red | P0 | Immediate (24 hours) |
| 6.0-7.9 | High | Orange | P1 | Priority (1 week) |
| 4.0-5.9 | Medium | Yellow | P2 | Scheduled (1 month) |
| 0.0-3.9 | Low | Green | P3 | Monitor |

**Score Components**:

**Base Score** (0-10): Password intrinsic qualities
- Complexity: Character sets used
- Length: Password length vs. minimum
- Dictionary: Known words detected
- Common: Appears in common password lists
- Patterns: Keyboard patterns, sequences
- HIBP: Breach tier (0-6)

**Temporal Score**: Time-based factors
- Password Age: Days since last change
- Policy Compliance: Meets organizational policy
- Expiration: Never-expiring passwords

**Environmental Score**: Organizational context
- DA Pathway: Path to Domain Admin
- Controlled Objects: Number of AD objects controlled
- Sharing: Same password/hash count
- Domain Risk: Inherent domain risk level
- HIBP Factor: Breach count multiplier

**Final Score**:
```
Base → Temporal → Environmental → Final
7.0  →   8.1    →      8.5       → 8.5 (Critical)
```

### Risk Vectors

Risk vectors provide **standardized risk representation**:

**Format**: `C:C5/L:M/D:CO+BW/SM:N/CM:H/EX:N/DA:Y/CO:VH/S:2/DR:H/HIBP:E`

**Components**:
- `C:C5` - Complexity: Char sets (0-5)
- `L:M` - Length: S/M/L/VL
- `D:CO+BW` - Detections: Common, Banned Word
- `SM:N` - Similarity: None/Low/Med/High
- `CM:H` - Compromise: HIBP tier
- `EX:N` - Expiration: Never/Normal
- `DA:Y` - Domain Admin: Yes/No
- `CO:VH` - Controlled Objects: N/L/M/H/VH
- `S:2` - Sharing: Count
- `DR:H` - Domain Risk: L/M/H
- `HIBP:E` - HIBP Level: N/L/M/H/VH/E/C

**Example Interpretation**:
```
Vector: C:C2/L:M/D:CO+DI/SM:H/CM:E/EX:N/DA:Y/CO:VH/S:5/DR:H/HIBP:E

Breakdown:
- C:C2 = Only 2 char sets (low complexity)
- L:M = Medium length
- D:CO+DI = Common password + Dictionary word
- SM:H = High similarity to other passwords
- CM:E = Extreme HIBP tier (10k-99k breaches)
- EX:N = Password never expires
- DA:Y = Has Domain Admin pathway
- CO:VH = Very high controlled objects
- S:5 = Shared by 5 accounts
- DR:H = High risk domain
- HIBP:E = Extreme breach count

Result: CRITICAL risk (score 9.5+)
```

### Common Risk Patterns

**Pattern 1: High Privilege + Weak Password**
```
Username: svc_backup@CORP.INT
Password: Backup2024!
Risk Score: 9.8 (Critical)
Why: DA pathway + common pattern + HIBP breached
Action: Immediate reset + 25-char random + MFA
```

**Pattern 2: Breach Exposure**
```
Username: jsmith@CORP.INT
Password: Password123!
Risk Score: 9.5 (Critical)
Why: HIBP 2.4M occurrences + dictionary word
Action: Immediate reset + user education
```

**Pattern 3: Password Reuse**
```
Username: admin_prod@CORP.INT
Same hash as: admin_dev@DEV.INT, admin_test@TEST.INT
Risk Score: 8.7 (Critical)
Why: Shared across 3 domains + admin accounts
Action: Unique passwords per domain
```

**Pattern 4: Policy Non-Compliance**
```
Username: user@CORP.INT
Password Age: 456 days (policy: 90 days)
Risk Score: 7.2 (High)
Why: Severely aged + expiration disabled
Action: Enforce policy compliance
```

## Remediation Workflow

### Priority-Based Remediation

**Priority 0: Immediate (Within 24 Hours)**

Criteria:
- Domain Admin pathways
- HIBP Tier 5-6 (10,000+ breaches)
- Critical risk score (8.0+)

Actions:
1. Force password reset
2. Enable MFA if not present
3. Review account necessity
4. Audit recent activity
5. Consider temporary disable

**Excel Sheet**: DA Pathways, Top 100 Risks

**Priority 1: Urgent (Within 1 Week)**

Criteria:
- High risk score (6.0-7.9)
- HIBP Tier 3-4 (100-9,999 breaches)
- High controlled objects
- Shared passwords

Actions:
1. Scheduled password reset
2. Enable MFA
3. Review privilege levels
4. Security awareness training

**Excel Sheet**: HIBP Breached, Top Controllables

**Priority 2: Scheduled (Within 1 Month)**

Criteria:
- Medium risk score (4.0-5.9)
- Policy violations (age, complexity)
- Password reuse patterns

Actions:
1. Policy enforcement
2. User notifications
3. Password rotation
4. Update policy if needed

**Excel Sheet**: Out of Compliance, Similar Passwords

**Priority 3: Monitor (Ongoing)**

Criteria:
- Low risk score (0.0-3.9)
- Compliant passwords
- Disabled accounts

Actions:
1. Regular re-audits
2. Policy review
3. Continuous monitoring

**Excel Sheet**: All Accounts (filter by Low risk)

### Remediation Tracking

**Create Remediation Plan**:
```bash
# Export critical accounts
python3 -c "
import csv
with open('reports/latest/csv/combined_report.csv') as f:
    reader = csv.DictReader(f, delimiter='\t')
    critical = [r for r in reader if r['Risk Level'] == 'Critical']

with open('remediation_plan.csv', 'w') as f:
    if critical:
        writer = csv.DictWriter(f, fieldnames=critical[0].keys())
        writer.writeheader()
        writer.writerows(critical)
"
```

**Track Progress**:
1. Initial audit → Baseline metrics
2. Remediation actions → Document changes
3. Re-audit (weekly/monthly) → Measure improvement
4. Compare metrics → Track progress

**Metrics to Track**:
- Critical account count (goal: 0)
- High risk account count (goal: <5%)
- Average risk score (goal: <4.0)
- Policy compliance % (goal: >95%)
- HIBP breach % (goal: 0%)

### Remediation Templates

**Email Template (Critical Accounts)**:
```
Subject: URGENT: Password Reset Required - Security Risk

Dear [Name],

Your account [username] has been identified as a critical security
risk due to:

[X] Weak password exposed in data breaches
[X] Password does not meet security requirements
[X] Account has elevated privileges

REQUIRED ACTION: Reset your password within 24 hours using the
following guidelines:

- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, symbols
- No dictionary words or common patterns
- Do not reuse old passwords

Password reset link: [URL]

Contact IT Security if you have questions.

Security Team
```

**Policy Update Notification**:
```
Subject: Updated Password Policy - Action Required

Effective [Date], our password policy has been updated:

NEW REQUIREMENTS:
- Minimum length: 14 → 16 characters
- Maximum age: 90 → 60 days
- Complexity: All character types required
- No banned words (company name, product names)

WHAT TO DO:
1. Update your password at next logon
2. Use a password manager (recommended tools: [list])
3. Enable MFA on all accounts

Questions? Contact: security@company.com
```

## Advanced Usage

### Custom Word Lists

Add organization-specific terms to enhance detection.

**Forbidden Words** (`lists/forbidden_words.txt`):
```
# Company names
CompanyName
ProductName
DivisionName

# Locations
HeadquartersCity
OfficeLocation

# Common terms
ServiceAccount
Administrator
```

**Common Passwords** (`lists/common_passwords.txt`):
```
# Organization-specific weak passwords
CompanyName123
Welcome2024
Summer2024
```

**Usage**:
- Tool automatically loads on startup
- No restart required after editing
- Case-insensitive matching

### Custom Password Policies

Define domain-specific policies in `lists/password_policy.json`:

```json
{
  "default": {
    "policy": {
      "min_length": 14,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_password_age_days": 90
    }
  },
  "PRODUCTION.CORP": {
    "policy": {
      "min_length": 16,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_password_age_days": 60
    }
  },
  "DEV.CORP": {
    "policy": {
      "min_length": 12,
      "max_password_age_days": 180
    }
  }
}
```

**Policy Application**:
- Domain-specific policy used if defined
- Falls back to `default` if domain not specified
- Affects temporal scoring and compliance reporting

### Periodic Audits

**Recommended Frequency**:
- **Weekly**: High-security environments
- **Monthly**: Standard corporate environments
- **Quarterly**: Low-risk environments
- **After incidents**: Breach response

**Automation Script**:
```bash
#!/bin/bash
# weekly_audit.sh

DATE=$(date +%Y-%m-%d)
REPORT_DIR="/var/audits/password_audits/$DATE"

# Run audit
cd /opt/PasswordAtTheDisco
python main.py -d "CORP.INT:$CRACKED_FILE:$UNCRACKED_FILE"

# Copy reports
cp -r reports/latest "$REPORT_DIR"

# Alert if critical accounts found
CRITICAL_COUNT=$(grep -c '"Critical"' "$REPORT_DIR/csv/CORP_report.csv")
if [ "$CRITICAL_COUNT" -gt 0 ]; then
    mail -s "Password Audit: $CRITICAL_COUNT Critical Accounts" \
         security@company.com < "$REPORT_DIR/summary.txt"
fi
```

**Cron Schedule**:
```cron
# Run every Monday at 2 AM
0 2 * * 1 /opt/scripts/weekly_audit.sh
```

### Integration with Ticketing Systems

**Create Jira Issues**:
```python
import csv
import requests

# Load critical accounts
with open('reports/latest/csv/combined_report.csv') as f:
    reader = csv.DictReader(f, delimiter='\t')
    critical = [r for r in reader if r['Risk Level'] == 'Critical']

# Create Jira issue for each
for account in critical:
    issue = {
        'fields': {
            'project': {'key': 'SEC'},
            'summary': f"Password Reset Required: {account['Username']}",
            'description': f"""
Critical password risk identified:
- Username: {account['Username']}
- Risk Score: {account['Risk Score']}
- Issues: {account['Risk Vector']}

Action Required: Force password reset within 24 hours
            """,
            'issuetype': {'name': 'Task'},
            'priority': {'name': 'Critical'}
        }
    }

    requests.post(
        'https://jira.company.com/rest/api/2/issue',
        auth=('user', 'token'),
        json=issue
    )
```

## Best Practices

### Security Best Practices

**1. Protect Credentials**:
```bash
# Secure configuration files
chmod 600 config/*.json

# Encrypt at rest
gpg -c config/bloodhound.json

# Use environment variables
export BH_TOKEN_KEY="..."
# Modify config loader to use env vars
```

**2. Secure Reports**:
```bash
# Restrict report access
chmod 700 reports/
chown security:security reports/

# Encrypt sensitive exports
gpg -c reports/latest/csv/combined_report.csv

# Secure deletion when done
shred -vfz old_reports/*
```

**3. Audit Trail**:
```bash
# Log all audit runs
echo "$(date): Audit run by $(whoami)" >> /var/log/password_audits.log

# Version control policies
git add lists/password_policy.json
git commit -m "Updated policy: min_length 14→16"
```

**4. Access Control**:
- Run tool from dedicated system
- Limit access to audit outputs
- Use service accounts with minimal privileges
- Rotate BloodHound API tokens quarterly

### Performance Best Practices

**1. Optimize HIBP**:
```json
{
  "cache_size": 10000000,  // More cache = faster (if RAM available)
  "enable_lookup": true
}
```

**2. Disable Animation** (for large audits):
```json
{
  "ui": {
    "enable_animation": false  // Enables max parallelism
  }
}
```

**3. Use SSD**:
- Store HIBP database on SSD (10x faster than HDD)
- Store reports on SSD during generation

**4. Local BloodHound**:
- Use local BloodHound instance if possible
- Reduces network latency
- Faster privilege queries

### Operational Best Practices

**1. Document Everything**:
- Keep audit run logs
- Document remediation actions
- Track metrics over time
- Version control configurations

**2. Regular Reviews**:
- Review password policy quarterly
- Update forbidden words list
- Re-evaluate risk thresholds
- Audit the auditor (validate results)

**3. User Education**:
- Share high-level statistics (not individual passwords)
- Conduct security awareness training
- Provide password manager recommendations
- Explain password requirements

**4. Continuous Improvement**:
- Track trends over time
- Measure remediation effectiveness
- Adjust policies based on results
- Share lessons learned

## Common Scenarios

### Scenario 1: First-Time Audit

**Goal**: Establish baseline security posture

**Steps**:
1. Complete installation and setup
2. Run initial audit on all domains
3. Generate baseline metrics
4. Identify quick wins (P0/P1 accounts)
5. Create remediation plan
6. Document findings for management

**Expected Results**:
- High critical account count (normal for first audit)
- Many policy violations (if policy not enforced)
- Baseline for future comparison

**Actions**:
- Focus on DA pathways first
- Don't try to fix everything at once
- Set realistic remediation timeline

### Scenario 2: Post-Breach Analysis

**Goal**: Assess damage and identify compromised accounts

**Steps**:
1. Run emergency audit with latest HIBP data
2. Focus on HIBP breached accounts
3. Check for password reuse patterns
4. Identify lateral movement risks
5. Force resets on affected accounts

**Filters**:
```bash
# Export only HIBP breached accounts
grep "Yes" reports/latest/csv/DOMAIN_report.csv | grep "HIBP Breached"
```

**Actions**:
- Immediate resets for HIBP matches
- MFA enforcement
- Account activity review
- Incident response procedures

### Scenario 3: Merger/Acquisition Integration

**Goal**: Assess acquired company's password security

**Steps**:
1. Obtain NTLM hashes from acquired domain
2. Run separate audit for acquired domain
3. Compare security posture to parent company
4. Identify integration risks
5. Plan policy alignment

**Multi-Domain Command**:
```bash
python main.py \
  -d "PARENT.CORP:parent_cracked.txt:parent_uncracked.txt" \
     "ACQUIRED.COM:acquired_cracked.txt:acquired_uncracked.txt"
```

**Focus Areas**:
- Shared passwords between domains
- Policy gaps
- Privilege escalation paths
- Trust relationship risks

### Scenario 4: Compliance Audit Preparation

**Goal**: Demonstrate password security controls for auditors

**Steps**:
1. Run comprehensive audit
2. Generate all report formats
3. Export compliance statistics
4. Document remediation efforts
5. Show improvement trend over time

**Reports for Auditors**:
- PDF executive summary
- Excel actionable report (shows remediation priority)
- Compliance statistics (policy adherence %)
- Trend analysis (compare to previous audits)

**Key Metrics**:
- Policy compliance percentage
- Average risk score
- Critical account count
- Remediation timeline

### Scenario 5: Password Policy Update

**Goal**: Enforce new password requirements

**Steps**:
1. Update `lists/password_policy.json`
2. Run audit with new policy
3. Identify non-compliant accounts
4. Plan phased rollout
5. Monitor compliance over time

**New Policy Example**:
```json
{
  "CORP.INT": {
    "policy": {
      "min_length": 16,        // Increased from 14
      "max_password_age_days": 60  // Reduced from 90
    }
  }
}
```

**Actions**:
- Notify users of policy changes
- Provide password manager recommendations
- Phase enforcement (start with privileged accounts)
- Re-audit monthly to track compliance

## Related Documentation

- [Getting Started](GETTING_STARTED.md) - Quick setup guide
- [Installation](INSTALLATION.md) - Detailed installation
- [Configuration](CONFIGURATION.md) - All configuration options
- [Integrations](INTEGRATIONS.md) - BloodHound, HIBP, Hashcat
- [Reports](REPORTS.md) - Understanding report formats
- [Scoring System](SCORING_SYSTEM.md) - Risk calculation details
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues

---

**Questions?** Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open an issue on GitHub.
