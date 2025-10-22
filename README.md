# Password!AtTheDisco

*"I crack passwords, and explain the chaos"*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-1.0-green.svg)]()

**Password!AtTheDisco** is a comprehensive password security auditing tool designed to evaluate and enhance password security across Active Directory environments. It combines password complexity analysis with BloodHound privilege data and Have I Been Pwned breach correlation to provide risk-based security insights that help organizations prioritize remediation efforts.

## 🎯 Key Features

- **🔒 CVSS-Style Risk Scoring**: Three-component scoring system (Base/Temporal/Environmental) with 0-10 risk scale
- **🩸 BloodHound Integration**: Identifies Domain Admin pathways and privilege escalation risks
- **🔐 HIBP Breach Correlation**: Checks 1.3 billion breached password hashes with 7-tier categorization
- **📊 Interactive Reports**: HTML dashboards with FlexSearch (<100ms), Excel actionable reports, CSV exports
- **🌐 Multi-Domain Analysis**: Cross-domain password sharing and lateral movement detection
- **📈 Advanced Analytics**: Password complexity, policy compliance, similarity detection, pattern matching
- **⚡ High Performance**: Parallel processing, indexed HIBP lookups, intelligent caching

## 🚀 Quick Start

### Installation

```bash
# Clone repository with submodules
git clone --recurse-submodules https://github.com/watson0x90/PasswordAtTheDisco.git
cd PasswordAtTheDisco

# Install dependencies
pip install -r requirements.txt

# Configure BloodHound
cp config/bloodhound.json.example config/bloodhound.json
# Edit with your BloodHound API credentials

# Test BloodHound connection
python main.py --test-bh
```

### First Audit

```bash
# Generate password files with Hashcat
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > cracked.txt
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > uncracked.txt

# Run audit
python main.py -d "CORP.INT:cracked.txt:uncracked.txt"

# View interactive reports
python main.py -s  # Opens browser to http://localhost:8008
```

**🎉 Done!** View comprehensive password security analysis with risk scores, remediation priorities, and interactive dashboards.

## 📖 Documentation

### Getting Started
- **[Getting Started Guide](docs/GETTING_STARTED.md)** - 10-minute setup and first audit
- **[Installation Guide](docs/INSTALLATION.md)** - Complete installation procedures
- **[Configuration Guide](docs/CONFIGURATION.md)** - All configuration options

### User Documentation
- **[User Guide](docs/USER_GUIDE.md)** - Complete end-to-end workflows
- **[Integrations Guide](docs/INTEGRATIONS.md)** - BloodHound, HIBP, Hashcat setup
- **[Reports Guide](docs/REPORTS.md)** - Understanding all report formats
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues and solutions

### Reference Material
- **[Scoring System](docs/SCORING_SYSTEM.md)** - How risk scores are calculated
- **[Scoring Examples](docs/SCORING_EXAMPLES.md)** - Real-world scoring scenarios
- **[Search Documentation](docs/search/)** - Interactive search features

### Developer Documentation
- **[Development Guide](docs/DEVELOPMENT.md)** - Contributing to the project
- **[Architecture Guide](docs/ARCHITECTURE.md)** - System design and decisions
- **[API Reference](docs/API_REFERENCE.md)** - Module and function reference

**📚 Full Documentation Index**: [docs/README.md](docs/README.md)

## 🔧 System Requirements

**Minimum**:
- Python 3.9+ (3.11+ recommended)
- 4GB RAM (8GB+ recommended with HIBP)
- Linux, macOS, or Windows with WSL

**Optional**:
- BloodHound Enterprise instance (for privilege analysis)
- HIBP NTLM database (~2GB, for breach detection)
- Hashcat 7.0+ (for password cracking)
- Pandoc (for PDF generation)

## 📊 What It Does

### Password Analysis
- **Complexity Assessment**: Character sets, length, entropy
- **Pattern Detection**: Dictionary words, keyboard patterns, common passwords
- **Policy Compliance**: Organizational password policy enforcement
- **Similarity Analysis**: Password reuse and variation detection

### BloodHound Integration
- **Privilege Analysis**: Domain Admin pathways, controlled objects
- **Account Properties**: Enabled status, last logon, password expiry
- **Risk Amplification**: Privilege-based environmental scoring

### HIBP Correlation
- **Breach Detection**: 1.3 billion breached NTLM hashes
- **Tier System**: 7-level categorization (0: clean → 6: critical)
- **Performance**: Three-tier lookup (cache → index → file)
- **Dual Impact**: Base tier scoring + environmental multiplier

### Risk Scoring (CVSS-Style)
```
Base Score (0-10)
  ↓ Temporal Factors (age, policy, expiration)
Temporal Score
  ↓ Environmental Factors (privilege, sharing, HIBP, domain)
Environmental Score = Final Risk Score
  ↓ Threshold Mapping
Risk Level (Critical/High/Medium/Low)
```

**Special Rule**: Any account with Domain Admin pathway = **Critical** (regardless of score)

### Report Formats

| Format | Use Case | Key Features |
|--------|----------|--------------|
| **HTML** | Interactive analysis | FlexSearch, filtering, visualizations, dark mode |
| **Excel** | Actionable remediation | Prioritized sheets, formulas, recommended actions |
| **CSV** | Data export | Raw data, SIEM integration |
| **Markdown** | Documentation | Detailed analysis, PDF conversion |
| **PDF** | Executive reports | Professional formatting, printable |

## 💡 Usage Examples

### Single Domain Audit
```bash
python main.py -d "CORP.INT:corp_cracked.txt:corp_uncracked.txt"
```

### Multi-Domain Audit
```bash
python main.py \
  -d "PROD.CORP.INT:prod_cracked.txt:prod_uncracked.txt" \
     "DEV.CORP.INT:dev_cracked.txt:dev_uncracked.txt" \
     "DMZ.CORP.INT:dmz_cracked.txt:dmz_uncracked.txt"
```

### Serve HTML Reports
```bash
python main.py -s  # Starts server on http://localhost:8008
```

### Generate PDFs
```bash
python main.py --pdf  # Converts Markdown reports to PDF
```

### Test BloodHound Connection
```bash
python main.py --test-bh
```

## 🔐 HIBP Integration Setup (Optional but Recommended)

HIBP integration identifies passwords exposed in data breaches, adding critical context to risk scoring.

### Quick Setup

```bash
# 1. Initialize HIBP downloader submodule (included with this repo)
git submodule update --init --recursive

# 2. Install .NET SDK (required to build downloader)
# Linux: sudo apt-get install dotnet-sdk-8.0
# macOS: brew install dotnet-sdk
# Windows: Download from https://dotnet.microsoft.com/download/dotnet/8.0

# 3. Build the HIBP downloader
cd PwnedPasswordsDownloader/src/HaveIBeenPwned.PwnedPasswords.Downloader
dotnet restore
dotnet build -c Release
cd ../../

# 4. Download HIBP NTLM database (~2GB download, ~42GB uncompressed)
dotnet run --project src/HaveIBeenPwned.PwnedPasswords.Downloader \
  -c Release -- \
  -o pwnedpasswords_ntlm.txt \
  -f ntlm

# This downloads 1.3 billion breached NTLM hashes (30-60 min)

# 5. Return to project root and configure
cd ../../
cp config/hibp.json.example config/hibp.json
# Edit ntlm_hash_file path (default: PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt)

# 6. First run builds index (5-10 minutes, one-time)
python main.py -d "DOMAIN:cracked.txt:uncracked.txt"
# Subsequent runs: index loads in 1-2 seconds
```

**What HIBP Provides**:
- Identifies passwords in 1.3 billion breached hashes
- Shows breach count (how many times hash appears)
- 7-tier risk categorization (0: clean → 6: 100k+ breaches)
- Dual impact: Base score contribution + environmental multiplier (1.0x-1.5x)

**Performance**:
- Cache hits: <1ms (90%+ hit rate)
- Index lookups: 10-50ms
- Configurable cache size (default: 1M hashes = ~50MB RAM)

**To Disable**: Set `"enable_lookup": false` in `config/hibp.json`

## 🩸 BloodHound Integration Setup

BloodHound enriches password analysis with Active Directory privilege data.

### Configuration

```bash
# 1. Copy example config
cp config/bloodhound.json.example config/bloodhound.json

# 2. Edit with your credentials
{
  "domain": "bloodhound.company.com",
  "port": 443,
  "scheme": "https",
  "token_id": "your-token-id",
  "token_key": "your-token-key",
  "search_limit": 1,
  "controllables_limit": 10
}

# 3. Test connection
python main.py --test-bh
```

**What BloodHound Provides**:
- Domain Admin pathway detection (auto-elevates to Critical risk)
- Controlled object counts (privilege-based risk amplification)
- Account properties (enabled, last logon, password expiry)
- Cross-domain privilege analysis

**API Token Setup**: See [BloodHound API Documentation](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api#create-a-personal-api-key-and-id-pair)

**Prerequisites**: SharpHound data collection completed and imported into BloodHound

## ⚙️ Configuration

### Password Policy

Customize password requirements in `lists/password_policy.json`:

**Single Domain**:
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
  }
}
```

**Multi-Domain** (different policies per domain):
```json
{
  "default": { "policy": { ... } },
  "PRODUCTION.CORP.INT": { "policy": { "min_length": 16, ... } },
  "DEV.CORP.INT": { "policy": { "min_length": 12, ... } }
}
```

See [lists/README.md](lists/README.md) for complete policy documentation.

### Word Lists

Customize detection lists in `lists/`:
- **forbidden_words.txt** - Organization-specific banned terms (⭐⭐⭐⭐⭐ **CRITICAL** to customize)
- **common_passwords.txt** - Weak password list (~10,000 entries)
- **dictionary_words.txt** - English dictionary (~479,000 words)
- **keyboard_patterns.txt** - Common keyboard patterns (~45 entries)

**Quick Start**:
```bash
# Add your company-specific terms
echo "YourCompany" >> lists/forbidden_words.txt
echo "YourProduct" >> lists/forbidden_words.txt
echo "YourLocation" >> lists/forbidden_words.txt
```

See [lists/README.md](lists/README.md) for complete customization guide.

## 📁 Input File Format

Password files must be in hashcat format with usernames:

```
user@DOMAIN.INT:RID:LMhash:NTLMhash:::password
```

**Generate with Hashcat**:
```bash
# Cracked passwords
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > cracked.txt

# Uncracked hashes
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > uncracked.txt
```

**Username Format**: Must be UPN format (`user@DOMAIN.INT`) for BloodHound integration

## 📊 Output Structure

```
reports/DOMAIN-2025-10-21-143022/
├── csv/                              # CSV data exports
│   ├── DOMAIN_report.csv
│   └── DOMAIN_detailed_report.json
├── excel/                            # Excel actionable reports
│   └── DOMAIN_actionable.xlsx
│       ├── Risk Summary
│       ├── Top 100 Risks
│       ├── DA Pathways               # Critical accounts
│       ├── Top Controllables
│       ├── HIBP Breached
│       ├── Non-Expiring
│       ├── Out of Compliance
│       ├── Similar Passwords
│       └── All Accounts
├── html/                             # Interactive HTML reports
│   ├── main.html                     # Dashboard
│   ├── search.html                   # Global search (FlexSearch)
│   ├── DOMAIN_report.html
│   └── password_data.json            # Embedded search data
├── markdown/                         # Markdown reports
│   ├── DOMAIN_report.md
│   └── combined_report.md
├── pdf/                              # PDF reports
│   └── DOMAIN_report.pdf
└── metadata.json                     # Audit run metadata

reports/latest -> DOMAIN-2025-10-21-143022/  # Symlink to latest
```

## 🎯 Risk Levels

| Risk Level | Score Range | Color | Action Timeline |
|------------|-------------|-------|-----------------|
| **Critical** | 8.0-10.0 | 🔴 Red | Immediate (24 hours) |
| **High** | 6.0-7.9 | 🟠 Orange | Priority (1 week) |
| **Medium** | 4.0-5.9 | 🟡 Yellow | Scheduled (1 month) |
| **Low** | 0.0-3.9 | 🟢 Green | Monitor |

**Special Rule**: Any account with Domain Admin pathway = **Critical** (regardless of score)

## 🔬 Testing

Comprehensive test suite available:

```bash
# Test HIBP integration
python scripts/test_hibp_integration.py

# Test with cleanup
python scripts/test_hibp_integration.py --cleanup
```

See [TESTING.md](TESTING.md) for complete testing documentation.

## 🤝 Contributing

We welcome contributions! Please see our [Development Guide](docs/DEVELOPMENT.md) for:
- Development environment setup
- Coding standards (PEP 8, Black, flake8)
- Testing requirements
- Pull request process
- Git workflow

**Quick Start**:
```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/PasswordAtTheDisco.git
cd PasswordAtTheDisco

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make changes, test, commit
git checkout -b feature/your-feature
# ... make changes ...
pytest  # Run tests
git commit -m "feat(scope): description"
git push origin feature/your-feature
```

## 📄 License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[BloodHound](https://bloodhound.readthedocs.io/)** - Active Directory privilege analysis
- **[Have I Been Pwned](https://haveibeenpwned.com/)** - Breach database
- **[Hashcat](https://hashcat.net/)** - Password cracking
- **[SecLists](https://github.com/danielmiessler/SecLists)** - Word lists (likely source)
- **[Project Gutenberg](https://www.gutenberg.org/)** - Dictionary words (likely source)
- **[CoreUI](https://coreui.io/)** - Modern UI framework
- **[FlexSearch](https://github.com/nextapps-de/flexsearch)** - Client-side search
- **[Plotly](https://plotly.com/)** - Interactive visualizations

## 📞 Support

- **Documentation**: [docs/README.md](docs/README.md)
- **Troubleshooting**: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- **Issues**: [GitHub Issues](https://github.com/watson0x90/PasswordAtTheDisco/issues)
- **Discussions**: [GitHub Discussions](https://github.com/watson0x90/PasswordAtTheDisco/discussions)

## 🗺️ Roadmap

- [ ] Advanced hashcat integration (automated cracking workflows)
- [ ] Additional report formats (SIEM integrations)
- [ ] Machine learning-based pattern detection
- [ ] Real-time monitoring capabilities
- [ ] Azure AD / Entra ID support
- [ ] Custom plugin system

## ⭐ Star History

If you find Password!AtTheDisco useful, please consider starring the repository!

---

**Password!AtTheDisco** - Comprehensive password security auditing for Active Directory environments.

*"I crack passwords, and explain the chaos"*
