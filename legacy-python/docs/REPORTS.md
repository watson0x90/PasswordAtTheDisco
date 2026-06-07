# Report Formats Guide

Complete guide to understanding Password!AtTheDisco report formats and outputs.

## Table of Contents

- [Report Overview](#report-overview)
- [Output Structure](#output-structure)
- [HTML Interactive Reports](#html-interactive-reports)
- [Excel Actionable Reports](#excel-actionable-reports)
- [CSV Data Exports](#csv-data-exports)
- [Markdown Reports](#markdown-reports)
- [PDF Reports](#pdf-reports)
- [Report Fields Reference](#report-fields-reference)

## Report Overview

Password!AtTheDisco generates reports in **five formats**, each designed for different audiences and use cases:

| Format | Primary Use Case | Key Features | Best For |
|--------|------------------|--------------|----------|
| **HTML** | Interactive analysis | Search, filtering, visualizations, dark mode | Security teams, daily use |
| **Excel** | Actionable remediation | Prioritized sheets, formulas, recommended actions | IT admins, remediation |
| **CSV** | Data export | Raw data, SIEM integration | Automation, analysis |
| **Markdown** | Documentation | Detailed analysis, readable format | Reports, documentation |
| **PDF** | Executive reports | Professional formatting, printable | Management, compliance |

### Report Generation Process

Reports are automatically generated at the end of each audit run:

```bash
python main.py -d "CORP.INT:cracked.txt:uncracked.txt"
```

**Generation Flow**:
1. Domain analysis completes
2. Cross-domain analysis (if multiple domains)
3. Visualizations created
4. All report formats generated in parallel
5. `reports/latest` symlink updated

**Selective Generation**:
```bash
# Generate only PDFs from existing Markdown reports
python main.py --pdf

# Serve existing HTML reports without re-analysis
python main.py -s
```

## Output Structure

All reports are saved in timestamped directories:

```
reports/
├── DOMAIN1-DOMAIN2-2025-10-21-143022/    # Timestamped directory
│   ├── csv/                              # CSV data exports
│   │   ├── DOMAIN1_report.csv            # Per-domain CSV
│   │   ├── DOMAIN2_report.csv
│   │   ├── combined_report.csv           # Combined CSV
│   │   ├── DOMAIN1_detailed_report.json  # Detailed JSON
│   │   └── DOMAIN2_detailed_report.json
│   ├── excel/                            # Excel actionable reports
│   │   ├── DOMAIN1_actionable.xlsx       # Per-domain Excel
│   │   ├── DOMAIN2_actionable.xlsx
│   │   └── combined_actionable.xlsx      # Combined Excel
│   ├── html/                             # Interactive HTML reports
│   │   ├── main.html                     # Dashboard/index
│   │   ├── search.html                   # Global search interface
│   │   ├── DOMAIN1_report.html           # Per-domain HTML
│   │   ├── DOMAIN2_report.html
│   │   └── password_data.json            # Search index data
│   ├── markdown/                         # Markdown reports
│   │   ├── DOMAIN1_report.md             # Per-domain Markdown
│   │   ├── DOMAIN2_report.md
│   │   └── combined_report.md            # Combined Markdown
│   ├── pdf/                              # PDF reports
│   │   ├── DOMAIN1_report.pdf            # Per-domain PDF
│   │   ├── DOMAIN2_report.pdf
│   │   └── combined_report.pdf           # Combined PDF
│   └── metadata.json                     # Audit run metadata
└── latest -> DOMAIN1-DOMAIN2-2025-10-21-143022/  # Symlink to latest

```

**Metadata File** (`metadata.json`):
```json
{
  "timestamp": "2025-10-21T14:30:22",
  "domains": ["DOMAIN1.INT", "DOMAIN2.COM"],
  "total_accounts": 5432,
  "cracked_accounts": 3821,
  "risk_distribution": {
    "Critical": 234,
    "High": 892,
    "Medium": 1456,
    "Low": 1239
  },
  "version": "1.0"
}
```

## HTML Interactive Reports

The HTML report format provides an interactive web-based dashboard for exploring password audit results.

### Features

**Main Dashboard** (`main.html`):
- Executive summary with security posture score
- Risk distribution charts
- Domain overview cards
- Cross-domain analysis (if multiple domains)
- Quick links to detailed reports

**Domain Reports** (`DOMAIN_report.html`):
- Interactive data tables with sorting/filtering
- Password complexity visualizations
- Risk score distributions
- Top risk accounts
- Policy compliance statistics
- Shared password analysis

**Search Interface** (`search.html`):
- FlexSearch-powered global search (<100ms)
- Multi-field search (username, password, risk factors)
- Advanced filtering (risk level, domain, status)
- Real-time highlighting
- Export filtered results

**Universal Features**:
- Dark mode toggle
- Responsive design (mobile-friendly)
- Client-side only (no server required after generation)
- Embedded visualizations (Plotly charts)
- Printable layouts

### Viewing HTML Reports

**Option 1: Built-in Server**
```bash
python main.py -s
```
Opens browser to `http://localhost:8008` with report menu.

**Option 2: Direct File Access**
```bash
# Open in default browser
firefox reports/latest/html/main.html
open reports/latest/html/main.html      # macOS
start reports/latest/html/main.html     # Windows

# Or navigate manually
cd reports/latest/html
python3 -m http.server 8008
```

**Option 3: Web Server Deployment**
```bash
# Copy HTML directory to web server
cp -r reports/latest/html /var/www/password-audit

# Configure nginx/apache to serve directory
# Ensure MIME types configured for .json files
```

### Dashboard Components

**Security Posture Score**:
- Overall security rating (0-100)
- Color-coded gauge (red/yellow/green)
- Breakdown by component:
  - Risk distribution (40%)
  - Password strength (30%)
  - Privilege risk (15%)
  - Policy compliance (15%)

**Risk Distribution Chart**:
- Pie chart showing Critical/High/Medium/Low counts
- Clickable segments to filter tables
- Percentage and absolute counts

**Top Risk Accounts Table**:
- Top 20 highest-risk accounts
- Sortable by score, username, domain
- Risk factors displayed as badges
- Click username to see full details

**Password Complexity Analysis**:
- Bar chart of complexity categories
- Length distribution histogram
- Character set usage breakdown

**Cross-Domain Analysis** (multi-domain audits):
- Shared password heatmap
- Lateral movement risk matrix
- Domain comparison statistics

### Search Interface

**Search Capabilities**:

```
# Username search
john@CORP.INT
john*                    # Wildcard search

# Password pattern search
Password*                # Passwords starting with "Password"
*123                     # Passwords ending with "123"

# Risk level filter
risk:critical            # Only critical accounts
risk:high,critical       # High OR critical

# Domain filter
domain:CORP.INT          # Specific domain
domain:CORP*             # Domain wildcard

# Combined filters
john* risk:high domain:CORP.INT
```

**Advanced Filters**:
- Risk Level: Critical, High, Medium, Low
- Domain: Multi-select dropdown
- Enabled Status: Enabled, Disabled
- DA Pathway: Yes, No
- HIBP Breached: Yes, No
- Policy Compliant: Yes, No

**Export Options**:
- Export current results to CSV
- Export with selected columns only
- Maintain current sort order

### Customization

**Branding** (`report_lib/standalone_html/components.py`):
```python
# Customize header/footer
CUSTOM_HEADER = """
<div class="custom-banner">
    <img src="company-logo.png" />
    <h1>Company Name - Password Audit</h1>
</div>
"""
```

**Styling** (`report_lib/standalone_html/styles.py`):
```css
/* Modify CSS variables for theming */
:root {
    --primary-color: #007bff;
    --danger-color: #dc3545;
    --warning-color: #ffc107;
    --success-color: #28a745;
}
```

## Excel Actionable Reports

Excel reports provide **prioritized remediation sheets** with recommended actions.

### Sheet Structure

Each Excel file contains multiple worksheets:

| Sheet Name | Content | Use Case |
|------------|---------|----------|
| **Risk Summary** | High-level statistics | Executive overview |
| **Top 100 Risks** | Highest-risk accounts | Priority remediation |
| **DA Pathways** | Accounts with DA paths | Critical security issues |
| **Top Controllables** | High-privilege accounts | Privileged account review |
| **Non-Expiring** | Never-expiring passwords | Policy compliance |
| **Out of Compliance** | Aged passwords | Scheduled resets |
| **Similar Passwords** | Password reuse patterns | Security awareness |
| **HIBP Breached** | Known exposed passwords | Immediate resets |
| **All Accounts** | Complete data | Comprehensive analysis |

### Risk Summary Sheet

**Metrics Included**:
- Total accounts audited
- Risk distribution (Critical/High/Medium/Low)
- Cracked vs. uncracked counts
- Policy compliance statistics
- Domain Admin pathway counts
- HIBP exposure statistics
- Average risk score

**Charts**:
- Risk distribution pie chart
- Complexity distribution bar chart
- Timeline of audit completion

### DA Pathways Sheet

**Critical accounts with paths to Domain Admin**:

| Username | Risk Score | DA Pathway | Controlled Objects | Password | Recommended Action |
|----------|------------|------------|-------------------|----------|-------------------|
| john@CORP.INT | 10.0 | Yes | 234 | Password123! | **IMMEDIATE RESET** |
| admin@CORP.INT | 9.8 | Yes | 892 | Welcome2024 | **IMMEDIATE RESET** |

**Formatting**:
- Red highlighting for critical risk
- Bold for DA pathway = Yes
- Sorted by risk score (highest first)

**Recommended Actions**:
- Reset password immediately
- Enable MFA on account
- Review controlled objects
- Audit recent activity
- Consider disabling if unused

### Top Controllables Sheet

**Accounts controlling many AD objects**:

| Username | Controlled Objects | Risk Score | Password Complexity | HIBP Breached | Action |
|----------|-------------------|------------|---------------------|---------------|--------|
| svc_backup@CORP.INT | 1,234 | 8.2 | Low | Yes | Reset + MFA |
| admin_helpdesk@CORP.INT | 892 | 7.5 | Medium | No | Review privileges |

**Use Cases**:
- Identify over-privileged accounts
- Review service account security
- Reduce attack surface
- Implement least privilege

### HIBP Breached Sheet

**Passwords found in data breaches**:

| Username | HIBP Count | Risk Score | Password | Breach Tier | Action |
|----------|------------|------------|----------|-------------|--------|
| user1@CORP.INT | 2,400,000 | 9.5 | Password123! | Critical | **RESET NOW** |
| user2@CORP.INT | 47,000 | 8.1 | Welcome1! | Extreme | **RESET ASAP** |

**Sorting**: By HIBP count (highest first)

**Color Coding**:
- Red: 100,000+ occurrences (Critical)
- Orange: 10,000-99,999 (Extreme)
- Yellow: 1,000-9,999 (Very High)
- Light yellow: 100-999 (High)

### Similar Passwords Sheet

**Password reuse and pattern detection**:

| Password Pattern | Account Count | Accounts | Risk Level | Action |
|------------------|---------------|----------|------------|--------|
| Password[digits]! | 23 | user1@CORP.INT, user2@CORP.INT, ... | High | Security awareness training |
| Welcome[year] | 18 | admin@CORP.INT, ... | High | Policy enforcement |

**Use Cases**:
- Identify widespread password patterns
- Target security awareness training
- Update password policy
- Detect policy circumvention

### Formulas and Features

**Excel Formulas**:
```excel
# Risk distribution percentage
=COUNTIF(risk_column,"Critical")/COUNTA(risk_column)*100

# Average score by domain
=AVERAGEIF(domain_column,"CORP.INT",score_column)

# Conditional formatting
=IF(risk_score>=8,"Critical",IF(risk_score>=6,"High","Medium"))
```

**Features**:
- Auto-filters on all data sheets
- Freeze panes (headers always visible)
- Conditional formatting (color-coded risks)
- Data validation (dropdown filters)
- Protected sheets (prevent accidental edits)

### Opening Excel Reports

**Direct Access**:
```bash
# Open in Excel
open reports/latest/excel/DOMAIN_actionable.xlsx          # macOS
start reports/latest/excel/DOMAIN_actionable.xlsx         # Windows
libreoffice reports/latest/excel/DOMAIN_actionable.xlsx   # Linux
```

**Troubleshooting**:

**Issue: "File is corrupted"**
- Cause: Incomplete write or disk full during generation
- Solution: Re-run analysis, check disk space

**Issue: Formulas not calculating**
- Cause: Excel protection or compatibility mode
- Solution: Enable editing, recalculate (Ctrl+Alt+F9)

## CSV Data Exports

CSV reports provide **raw data** for automation, SIEM integration, and custom analysis.

### File Types

**Per-Domain CSV** (`DOMAIN_report.csv`):
- All accounts for a single domain
- Tab-delimited format
- UTF-8 encoding
- Quoted fields (handles commas in data)

**Combined CSV** (`combined_report.csv`):
- All domains in single file
- Includes domain column
- Identical schema to per-domain files

**Detailed JSON** (`DOMAIN_detailed_report.json`):
- Complete account data in JSON format
- Nested objects for complex data
- Includes all analysis metadata

### CSV Schema

**Columns** (total: 35+ fields):

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| Username | string | User principal name | john@CORP.INT |
| Domain | string | Domain name | CORP.INT |
| Password | string | Plaintext password (if cracked) | Password123! |
| Password Length | integer | Character count | 12 |
| NTLM Hash | string | NTLM hash (uppercase) | 8846F7EAEE8FB117AD06BDD830B7586C |
| Risk Score | float | Final risk score (0-10) | 8.5 |
| Risk Level | string | Risk category | Critical |
| Risk Vector | string | CVSS-style vector | C:C5/L:M/D:CO+BW/... |
| Base Score | float | Base component score | 7.2 |
| Temporal Score | float | Temporal component score | 8.1 |
| Environmental Score | float | Environmental component score | 8.5 |
| Complexity Label | string | Complexity category | Low |
| DA Pathway | boolean | Has DA path | Yes |
| DA Domains | string | Domains with DA access | CORP.INT, SUB.INT |
| Controlled Objects | integer | Object count | 234 |
| Enabled | boolean | Account enabled | Yes |
| Last Logon | datetime | Last logon timestamp | 2025-10-15T10:30:00 |
| Password Age (days) | integer | Days since last change | 189 |
| Password Expires | datetime | Expiration date | 2025-12-31T23:59:59 |
| Policy Compliant | boolean | Meets policy | No |
| HIBP Breached | boolean | Found in breaches | Yes |
| HIBP Count | integer | Breach occurrences | 2400000 |
| HIBP Tier | integer | Tier (0-6) | 6 |
| Dictionary Word | boolean | Contains dictionary word | Yes |
| Common Password | boolean | Known common password | Yes |
| Forbidden Words | string | Banned words found | Company, Admin |
| Keyboard Pattern | boolean | Has keyboard pattern | No |
| Similar Passwords | integer | Similar password count | 3 |
| Shared Hash Count | integer | Accounts with same hash | 5 |

**Sample Row**:
```csv
"john@CORP.INT","CORP.INT","Password123!",12,"8846F7EAEE8FB117AD06BDD830B7586C",8.5,"Critical","C:C5/L:M/D:CO+BW/SM:N/CM:H/EX:N/DA:N/CO:M/S:2/DR:M/HIBP:E",7.2,8.1,8.5,"Low","No","",45,"Yes","2025-10-15T10:30:00",189,"2025-12-31T23:59:59","No","Yes",2400000,6,"Yes","Yes","Password","No",3,1
```

### JSON Export Schema

**Structure** (`DOMAIN_detailed_report.json`):

```json
{
  "domain": "CORP.INT",
  "timestamp": "2025-10-21T14:30:22",
  "total_accounts": 1234,
  "accounts": [
    {
      "username": "john@CORP.INT",
      "domain": "CORP.INT",
      "password": "Password123!",
      "ntlm_hash": "8846F7EAEE8FB117AD06BDD830B7586C",
      "risk_score": 8.5,
      "risk_level": "Critical",
      "risk_vector": "C:C5/L:M/D:CO+BW/SM:N/CM:H/EX:N/DA:N/CO:M/S:2/DR:M/HIBP:E",
      "scores": {
        "base": 7.2,
        "temporal": 8.1,
        "environmental": 8.5,
        "components": {
          "complexity_factor": 0.3,
          "length_factor": 0.6,
          "dictionary_factor": 2.0,
          "similarity_factor": 0.5,
          "age_factor": 1.2,
          "privilege_factor": 1.3,
          "sharing_factor": 1.0,
          "hibp_factor": 1.5
        }
      },
      "analysis": {
        "complexity": "Low",
        "length": 12,
        "char_sets": ["uppercase", "lowercase", "digits", "special"],
        "dictionary_word": true,
        "common_password": true,
        "forbidden_words": ["Password"],
        "keyboard_pattern": false,
        "similar_count": 3
      },
      "bloodhound": {
        "has_da_path": false,
        "da_domains": [],
        "controlled_objects": 45,
        "enabled": true,
        "last_logon": "2025-10-15T10:30:00",
        "password_age_days": 189,
        "password_expires": "2025-12-31T23:59:59"
      },
      "hibp": {
        "breached": true,
        "count": 2400000,
        "tier": 6,
        "risk_level": "Extreme"
      }
    }
  ],
  "statistics": {
    "risk_distribution": {
      "Critical": 234,
      "High": 456,
      "Medium": 321,
      "Low": 223
    },
    "cracked_count": 891,
    "uncracked_count": 343
  }
}
```

### SIEM Integration Examples

**Splunk**:
```bash
# Index CSV
splunk add oneshot reports/latest/csv/combined_report.csv -sourcetype password_audit

# Index JSON
splunk add oneshot reports/latest/csv/DOMAIN_detailed_report.json -sourcetype password_audit:json
```

**Elasticsearch**:
```bash
# Using Logstash
cat reports/latest/csv/DOMAIN_detailed_report.json | \
  logstash -f password_audit.conf
```

**Custom Python Script**:
```python
import csv

with open('reports/latest/csv/combined_report.csv') as f:
    reader = csv.DictReader(f, delimiter='\t')
    for row in reader:
        if row['Risk Level'] == 'Critical':
            send_alert(row['Username'], row['Risk Score'])
```

## Markdown Reports

Markdown reports provide **detailed analysis** in human-readable format.

### Structure

**Per-Domain Report** (`DOMAIN_report.md`):
```markdown
# Password Audit Report: CORP.INT
**Generated**: 2025-10-21 14:30:22

## Executive Summary
- **Total Accounts**: 1,234
- **Risk Distribution**: 234 Critical, 456 High, 321 Medium, 223 Low
- **Average Risk Score**: 5.8/10

## Key Findings
### Critical Issues
1. **234 accounts** with critical risk scores (8.0-10.0)
2. **89 accounts** with Domain Admin pathways
3. **456 passwords** found in HIBP breaches

### Recommendations
1. **Immediate**: Reset all passwords with DA pathways
2. **Priority**: Reset HIBP-breached passwords
3. **Scheduled**: Enforce policy compliance (892 violations)

## Detailed Analysis
### Risk Score Distribution
[Chart: Risk distribution pie chart]

### Top 20 Highest Risk Accounts
| Username | Score | Risk Level | Issues |
|----------|-------|------------|--------|
| john@CORP.INT | 10.0 | Critical | DA pathway, HIBP 2.4M, Common password |
...

## Password Complexity Analysis
[Chart: Complexity distribution]

## Policy Compliance
- **Compliant**: 342 accounts (27.7%)
- **Non-Compliant**: 892 accounts (72.3%)
  - Length violations: 234
  - Age violations: 456
  - Complexity violations: 202

## Cross-Domain Analysis (if applicable)
### Shared Passwords
[Table: Password sharing between domains]

## Appendix
### Methodology
[Description of analysis methodology]

### Risk Scoring
[CVSS-style scoring explanation]
```

**Combined Report** (`combined_report.md`):
- Aggregates all domains
- Cross-domain comparisons
- Unified recommendations

### Features

- **Embedded Tables**: GitHub Flavored Markdown tables
- **Charts**: References to image files (PNG exports of Plotly charts)
- **Links**: Cross-references to other sections
- **Code Blocks**: Examples and commands
- **Formatting**: Bold, italic, lists for readability

### Use Cases

- **Documentation**: Archive audit findings
- **Presentations**: Convert to slides with pandoc
- **Collaboration**: Share via Git, markdown editors
- **Version Control**: Track changes over time

## PDF Reports

PDF reports are **professional printable versions** of Markdown reports.

### Generation

**Automatic** (if pandoc installed):
```bash
# PDFs generated automatically during normal run
python main.py -d "DOMAIN:cracked.txt:uncracked.txt"
```

**Manual**:
```bash
# Generate PDFs from existing Markdown
python main.py --pdf
```

**Requirements**:
- Pandoc 2.0+ installed
- LaTeX distribution (for advanced formatting)

### Formatting

**PDF Features**:
- Professional LaTeX styling
- Table of contents with page numbers
- Headers and footers
- Page numbers
- Syntax highlighting
- Embedded images (charts)

**Customization** (`utils/file_utils.py`):
```python
# Modify PDF generation options
pandoc_args = [
    '--pdf-engine=xelatex',
    '--toc',
    '--number-sections',
    '--highlight-style=tango',
    f'--metadata=title:{title}',
    f'--metadata=date:{date}'
]
```

### Use Cases

- **Executive briefings**: Printable summary reports
- **Compliance**: Audit documentation for regulators
- **Archival**: Long-term storage format
- **Distribution**: Email-friendly format

## Report Fields Reference

### Risk Scoring Fields

| Field | Type | Range | Description |
|-------|------|-------|-------------|
| Risk Score | float | 0.0-10.0 | Final combined risk score |
| Risk Level | enum | Low/Medium/High/Critical | Categorical risk level |
| Base Score | float | 0.0-10.0 | Password intrinsic risk |
| Temporal Score | float | 0.0-10.0 | Time-based risk |
| Environmental Score | float | 0.0-10.0 | Organizational context risk |
| Risk Vector | string | - | CVSS-style vector notation |

### Password Analysis Fields

| Field | Type | Description |
|-------|------|-------------|
| Password | string | Plaintext password (if cracked) |
| Password Length | integer | Character count |
| NTLM Hash | string | Uppercase NTLM hash |
| Complexity Label | enum | Best/Better/Good/Moderate/Low/VeryLow |
| Dictionary Word | boolean | Contains dictionary word |
| Common Password | boolean | Known common/weak password |
| Forbidden Words | string | Comma-separated banned words found |
| Keyboard Pattern | boolean | Contains keyboard pattern |
| Similar Passwords | integer | Count of similar passwords |

### BloodHound Fields

| Field | Type | Description |
|-------|------|-------------|
| DA Pathway | boolean | Has path to Domain Admin |
| DA Domains | string | Comma-separated DA accessible domains |
| Controlled Objects | integer | Number of AD objects controlled |
| Enabled | boolean | Account enabled status |
| Last Logon | datetime | Last successful logon |
| Password Age (days) | integer | Days since password change |
| Password Expires | datetime | Password expiration date |

### HIBP Fields

| Field | Type | Description |
|-------|------|-------------|
| HIBP Breached | boolean | Found in HIBP database |
| HIBP Count | integer | Number of breach occurrences |
| HIBP Tier | integer | Risk tier (0-6) |
| HIBP Risk Level | enum | None/Low/Medium/High/VeryHigh/Extreme/Critical |

## Related Documentation

- [Scoring System](SCORING_SYSTEM.md) - How risk scores are calculated
- [Scoring Examples](SCORING_EXAMPLES.md) - Real-world scoring scenarios
- [Configuration Guide](CONFIGURATION.md) - Report generation settings
- [Search Documentation](search/SEARCH_IMPLEMENTATION.md) - HTML search features

---

**Report Questions?** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common report issues.
