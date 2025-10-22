# Password!AtTheDisco Documentation

Complete documentation for Password!AtTheDisco - a CVSS-style password security auditing tool with BloodHound integration.

## Quick Navigation

### 🚀 Getting Started
- **[Getting Started Guide](GETTING_STARTED.md)** - Get up and running in 10 minutes
- **[Installation Guide](INSTALLATION.md)** - Complete setup instructions
- **[Configuration Guide](CONFIGURATION.md)** - All configuration options explained

### 📖 User Documentation
- **[User Guide](USER_GUIDE.md)** - Complete end-to-end usage guide
- **[Integrations Guide](INTEGRATIONS.md)** - BloodHound, HIBP, and Hashcat setup
- **[Reports Guide](REPORTS.md)** - Understanding all report formats
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Common issues and solutions
- **[Scoring System](SCORING_SYSTEM.md)** - How risk scores are calculated
- **[Scoring Examples](SCORING_EXAMPLES.md)** - Real-world scoring scenarios

### 🔧 Advanced Topics
- **[Search Documentation](search/)** - Interactive search interface
  - [Architecture](search/SEARCH_ARCHITECTURE.txt)
  - [Implementation](search/SEARCH_IMPLEMENTATION.md) - CoreUI 5 search features
  - [Testing Checklist](search/SEARCH_TESTING_CHECKLIST.md)

### 👨‍💻 Developer Documentation
- **[Development Guide](DEVELOPMENT.md)** - Contributing to the project
- **[Architecture Guide](ARCHITECTURE.md)** - System design and decisions
- **[API Reference](API_REFERENCE.md)** - Module and function reference

## Documentation Overview

### For New Users

Start here if you're new to Password!AtTheDisco:

1. **[Getting Started](GETTING_STARTED.md)** (5-10 min read)
   - Quick installation
   - First audit run
   - Understanding results
   - Next steps

2. **[Installation Guide](INSTALLATION.md)** (15 min read)
   - System requirements
   - Python environment setup
   - BloodHound configuration
   - HIBP database setup
   - Verification steps

3. **[Configuration Guide](CONFIGURATION.md)** (Reference)
   - BloodHound settings
   - HIBP settings
   - Password policies
   - Performance tuning

### For Regular Users

Once you're up and running:

1. **[User Guide](USER_GUIDE.md)** (Comprehensive workflow guide)
   - Single and multi-domain audits
   - Understanding results
   - Remediation workflow
   - Advanced usage
   - Common scenarios

2. **[Integrations](INTEGRATIONS.md)** (External tool setup)
   - BloodHound Enterprise integration
   - HIBP breach correlation
   - Hashcat password cracking
   - Custom integrations

3. **[Reports](REPORTS.md)** (Understanding outputs)
   - HTML interactive dashboards
   - Excel actionable reports
   - CSV data exports
   - Markdown and PDF reports
   - Report fields reference

4. **[Troubleshooting](TROUBLESHOOTING.md)** (Problem solving)
   - Installation issues
   - Configuration errors
   - BloodHound connection problems
   - HIBP issues
   - FAQ

5. **[Scoring System](SCORING_SYSTEM.md)** (Risk calculation)
   - CVSS-style three-component scoring
   - Base, temporal, environmental scores
   - HIBP tier system
   - Risk vectors
   - Developer reference

6. **[Scoring Examples](SCORING_EXAMPLES.md)** (Real scenarios)
   - 7 detailed examples
   - Step-by-step calculations
   - Real-world scenarios
   - Risk level breakdown

### For Advanced Users

Deep dives into specific features:

1. **[Search Interface](search/)**
   - **[Architecture](search/SEARCH_ARCHITECTURE.txt)** - FlexSearch implementation
   - **[Implementation](search/SEARCH_IMPLEMENTATION.md)** - CoreUI 5 features
   - **[Testing Checklist](search/SEARCH_TESTING_CHECKLIST.md)** - QA testing

### For Developers

Contributing to the project:

1. **[Development Guide](DEVELOPMENT.md)** (Complete workflow)
   - Setting up dev environment
   - Coding standards and style
   - Testing requirements
   - Pull request process
   - Git workflow

2. **[Architecture Guide](ARCHITECTURE.md)** (System design)
   - High-level architecture
   - Module organization
   - Data flow
   - Design decisions
   - Performance considerations

3. **[API Reference](API_REFERENCE.md)** (Module documentation)
   - Core modules (config, data, analysis, scoring)
   - Integration modules (BloodHound, HIBP, Hashcat)
   - Data models
   - Report generation library
   - Utility functions

## Feature Documentation

### Risk Scoring System

Password!AtTheDisco uses a **CVSS-style three-component scoring system**:

```
Base Score (0-10)
  ↓
Temporal Score = Base × Temporal Factors
  ↓
Environmental Score = Temporal × Environmental Factors
  ↓
Final Risk Score → Risk Level (Low/Medium/High/Critical)
```

**Key Innovation**: Evidence-based HIBP tier system derived from analyzing 1.3 billion breached password hashes.

📖 **Read more**: [SCORING_SYSTEM.md](SCORING_SYSTEM.md)

### BloodHound Integration

Enriches password analysis with Active Directory privilege data:

- Domain Admin pathways
- Controlled object counts
- Account properties (enabled, last logon, password expiry)
- Privilege-based risk amplification

🔧 **Configure**: [CONFIGURATION.md#bloodhound-configuration](CONFIGURATION.md#bloodhound-configuration)

### HIBP Correlation

Checks passwords against 1.3 billion breached NTLM hashes:

- Three-tier lookup (cache → index → file)
- 7-level risk categorization
- Dual HIBP impact (base tier + environmental multiplier)
- Performance: <1ms (cache) to 50ms (file)

🔧 **Configure**: [CONFIGURATION.md#hibp-configuration](CONFIGURATION.md#hibp-configuration)

### Interactive Search

FlexSearch-powered global search across all accounts:

- Sub-100ms search across 10,000+ accounts
- Multi-field search (username, password, risk factors)
- Advanced filtering (risk level, domain, status)
- Real-time highlighting
- No server required (client-side)

📖 **Read more**: [search/SEARCH_IMPLEMENTATION.md](search/SEARCH_IMPLEMENTATION.md)

### Report Formats

Multiple output formats for different audiences:

| Format | Use Case | Features |
|--------|----------|----------|
| **HTML** | Interactive analysis | Search, filtering, visualizations, dark mode |
| **Excel** | Actionable remediation | Prioritized sheets, recommended actions |
| **CSV** | Data export | All fields, SIEM integration |
| **Markdown** | Documentation | Detailed analysis, PDF conversion |
| **PDF** | Executive reports | Professional formatting |

## Command-Line Reference

### Basic Usage

```bash
# Analyze single domain
python main.py -d "CORP.INT:cracked.txt:uncracked.txt"

# Analyze multiple domains
python main.py \
  -d "CORP.INT:corp_cracked.txt:corp_uncracked.txt" \
     "SUBSIDIARY.COM:sub_cracked.txt:sub_uncracked.txt"

# Serve HTML reports
python main.py -s

# Generate PDFs
python main.py --pdf

# Test BloodHound connection
python main.py --test-bh
```

### Input File Format

Hashcat format with username:

```
user@DOMAIN.INT:RID:LMhash:NTLMhash:::password
john@CORP.INT:1001:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::Password123
```

**Generate with hashcat:**

```bash
# Cracked passwords
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > cracked.txt

# Uncracked hashes
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > uncracked.txt
```

## Configuration Quick Reference

### BloodHound

```json
{
  "domain": "bloodhound.company.com",
  "port": 443,
  "scheme": "https",
  "token_id": "your-token-id",
  "token_key": "your-token-key",
  "search_limit": 1,
  "controllables_limit": 10
}
```

**File**: `config/bloodhound.json`
**Test**: `python main.py --test-bh`

### HIBP

```json
{
  "ntlm_hash_file": "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt",
  "enable_lookup": true,
  "cache_size": 1000000,
  "prefix_length": 5
}
```

**File**: `config/hibp.json`
**Download**: ~2GB NTLM database from HIBP

### Password Policy

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

**File**: `lists/password_policy.json`

## Output Structure

```
reports/DOMAIN-2025-10-21-143022/
├── csv/
│   ├── DOMAIN_report.csv
│   └── DOMAIN_detailed_report.json
├── excel/
│   └── DOMAIN_actionable.xlsx
├── html/
│   ├── main.html (dashboard)
│   ├── search.html (search interface)
│   ├── DOMAIN_report.html
│   └── password_data.json
├── markdown/
│   ├── DOMAIN_report.md
│   └── combined_report.md
├── pdf/
│   └── DOMAIN_report.pdf
└── metadata.json
```

**Latest symlink**: `reports/latest` → most recent run

## Risk Levels

| Risk Level | Score | Color | Action |
|------------|-------|-------|--------|
| **Critical** | 8.0-10.0 | 🔴 Red | Immediate reset |
| **High** | 6.0-7.9 | 🟠 Orange | Priority remediation |
| **Medium** | 4.0-5.9 | 🟡 Yellow | Scheduled reset |
| **Low** | 0.0-3.9 | 🟢 Green | Monitor |

**Special rule**: Any account with DA pathway = Critical (regardless of score)

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| ModuleNotFoundError | `pip install -r requirements.txt` |
| Config file not found | `cp config/*.example config/*.json` |
| BloodHound connection failed | `python main.py --test-bh` |
| HIBP file not found | Download from HIBP, update config |
| Invalid hashcat format | Verify colon-separated fields |

📖 **Full guide**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## Performance Tips

1. **Disable animation** for max parallelism:
   ```json
   { "ui": { "enable_animation": false } }
   ```

2. **Increase HIBP cache** (if RAM available):
   ```json
   { "cache_size": 10000000 }
   ```

3. **Use SSD** for HIBP database (10x faster than HDD)

4. **Local BloodHound** instance (reduce network latency)

5. **Disable HIBP** if not needed:
   ```json
   { "enable_lookup": false }
   ```

## Security Best Practices

1. **Protect credentials**:
   ```bash
   chmod 600 config/bloodhound.json
   # Add to .gitignore (already included)
   ```

2. **Use HTTPS** for BloodHound:
   ```json
   { "scheme": "https", "port": 443 }
   ```

3. **Rotate API tokens** quarterly

4. **Limit server access**:
   ```json
   { "server": { "host": "localhost" } }
   ```

5. **Secure HIBP database**:
   ```bash
   chmod 600 PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt
   ```

## Documentation Standards

All documentation follows these standards:

- **Format**: Markdown (.md)
- **Style**: Professional, clear, concise
- **Examples**: Real-world scenarios with code
- **References**: File:line format for code locations
- **Cross-links**: Related documentation linked
- **Tone**: Approachable but authoritative

## Contributing to Documentation

When adding or updating documentation:

1. Follow existing structure and style
2. Include practical examples
3. Add code references where applicable
4. Update this index (README.md)
5. Test all code examples
6. Spell check and grammar check
7. Submit pull request with description

## Getting Help

- **Documentation Issues**: Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Bug Reports**: GitHub Issues
- **Feature Requests**: GitHub Issues
- **Questions**: GitHub Discussions (if enabled)

## Document Status

| Document | Status | Last Updated | Completeness |
|----------|--------|--------------|--------------|
| **User Documentation** |||
| GETTING_STARTED.md | ✅ Complete | 2025-10-21 | 100% |
| INSTALLATION.md | ✅ Complete | 2025-10-21 | 100% |
| CONFIGURATION.md | ✅ Complete | 2025-10-21 | 100% |
| USER_GUIDE.md | ✅ Complete | 2025-10-21 | 100% |
| INTEGRATIONS.md | ✅ Complete | 2025-10-21 | 100% |
| REPORTS.md | ✅ Complete | 2025-10-21 | 100% |
| TROUBLESHOOTING.md | ✅ Complete | 2025-10-21 | 100% |
| SCORING_SYSTEM.md | ✅ Complete | Earlier | 100% |
| SCORING_EXAMPLES.md | ✅ Complete | Earlier | 100% |
| **Developer Documentation** |||
| DEVELOPMENT.md | ✅ Complete | 2025-10-21 | 100% |
| ARCHITECTURE.md | ✅ Complete | 2025-10-21 | 100% |
| API_REFERENCE.md | ✅ Complete | 2025-10-21 | 100% |
| **Search Documentation** |||
| search/SEARCH_ARCHITECTURE.txt | ✅ Complete | Earlier | 100% |
| search/SEARCH_IMPLEMENTATION.md | ✅ Complete | 2025-10-21 | 100% |
| search/SEARCH_TESTING_CHECKLIST.md | ✅ Complete | Earlier | 100% |

## Quick Links

### Essential Reading
- ⭐ [Getting Started](GETTING_STARTED.md) - Start here!
- 📦 [Installation](INSTALLATION.md) - Complete setup
- ⚙️ [Configuration](CONFIGURATION.md) - All settings
- 📖 [User Guide](USER_GUIDE.md) - Complete workflow
- 🔗 [Integrations](INTEGRATIONS.md) - External tools
- 📊 [Reports](REPORTS.md) - Understanding outputs
- 🆘 [Troubleshooting](TROUBLESHOOTING.md) - Problem solving

### Reference Material
- 📈 [Scoring System](SCORING_SYSTEM.md) - Risk calculation
- 📋 [Scoring Examples](SCORING_EXAMPLES.md) - Real scenarios
- 🔍 [Search Docs](search/) - Interactive search

### Developer Resources
- 💻 [Development Guide](DEVELOPMENT.md) - Contributing
- 🏗️ [Architecture](ARCHITECTURE.md) - System design
- 📚 [API Reference](API_REFERENCE.md) - Module docs

### External Resources
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)

---

**Documentation Version**: 1.0
**Last Updated**: 2025-10-21
**Tool Version**: Password!AtTheDisco v1.0

**Questions?** Start with [GETTING_STARTED.md](GETTING_STARTED.md) or check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
