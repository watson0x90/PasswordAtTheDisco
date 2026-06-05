# Integration Guide

Comprehensive guide to integrating Password!AtTheDisco with external tools and services.

## Table of Contents

- [BloodHound Enterprise Integration](#bloodhound-enterprise-integration)
- [Have I Been Pwned (HIBP) Integration](#have-i-been-pwned-hibp-integration)
- [Hashcat Integration](#hashcat-integration)
- [Custom Integrations](#custom-integrations)

## BloodHound Enterprise Integration

BloodHound enriches password analysis with Active Directory privilege data, enabling risk-based prioritization.

### What BloodHound Provides

Password!AtTheDisco queries BloodHound for:

- **Domain Admin Pathways** - Accounts with paths to Domain Admin
- **Controlled Object Counts** - Number of objects the account can control
- **Account Properties**:
  - Enabled status
  - Password expiry settings
  - Last logon timestamp
  - Account creation date

### Architecture

**API Client** (`core/bloodhound_integration.py`):
- `BloodHoundClient` class - Main API interface
- `BloodHoundEnricher` class - Account enrichment orchestration
- Parallel processing with batching
- Automatic retry logic for failed queries

**Query Flow**:
1. Search for account by username (UPN format: `user@DOMAIN.INT`)
2. Query for Domain Admin pathways
3. Query for controlled objects (with configurable limits)
4. Extract account properties from BloodHound graph data
5. Cache results to avoid duplicate queries

### Setup Instructions

#### Step 1: Create API Token

1. Log into BloodHound Enterprise UI
2. Navigate to **Settings → API Tokens**
3. Click **Create New Token**
4. **Important**: Save both Token ID and Token Key immediately (key only shown once!)

#### Step 2: Configure Connection

Create `config/bloodhound.json`:

```json
{
  "domain": "bloodhound.yourcompany.com",
  "port": 443,
  "scheme": "https",
  "token_id": "your-token-id-here",
  "token_key": "your-token-key-here",
  "search_limit": 1,
  "controllables_limit": 10
}
```

**Configuration Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | Required | BloodHound server hostname or IP |
| `port` | integer | 443 | API port (443 for HTTPS, 8080 for HTTP) |
| `scheme` | string | https | Protocol (https/http) |
| `token_id` | string | Required | API token ID from BloodHound |
| `token_key` | string | Required | API token key (keep secret!) |
| `search_limit` | integer | 1 | Max search results per query |
| `controllables_limit` | integer | 10 | Initial controllables query limit |

#### Step 3: Test Connection

```bash
python main.py --test-bh
```

**Expected Success Output**:
```
✓ Client initialized
✓ API connection successful (version: 5.x.x)
✓ Found 3 domains
✓ Sample data query successful
BloodHound connection test: SUCCESS
```

**Troubleshooting Connection Issues**:

| Issue | Solution |
|-------|----------|
| Connection refused | Check firewall, verify server is running |
| SSL certificate error | Use `http` scheme for dev, install proper cert for prod |
| 401 Unauthorized | Regenerate token, verify token_id and token_key |
| Timeout | Check network latency, use local BloodHound if possible |

### Username Format Requirements

**Critical**: Usernames must match BloodHound's format exactly.

**Supported Formats**:
- ✅ UPN format: `user@DOMAIN.INT`
- ✅ Email format: `user@company.com`

**Unsupported Formats**:
- ❌ DOMAIN\\user
- ❌ user (without domain)

**Hashcat Output Conversion**:

Hashcat outputs in correct format by default:
```bash
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt
# Output: john@CORP.INT:1001:aad3b...:::Password123
```

### Impact on Risk Scoring

BloodHound data affects the **Environmental Score** component:

**Domain Admin Pathway**:
- Any account with DA path automatically becomes **CRITICAL** risk
- Bypasses normal scoring calculation
- Highest priority for remediation

**Controlled Objects**:
- 0 objects: 1.0x multiplier (no change)
- 1-10 objects: 1.1x multiplier
- 11-50 objects: 1.2x multiplier
- 51-100 objects: 1.3x multiplier
- 101-500 objects: 1.4x multiplier
- 500+ objects: 1.5x multiplier

**Account Status**:
- Disabled accounts: Reduced risk (temporal factor 0.5x)
- Password never expires: Increased risk (temporal factor 1.3x)

### Performance Optimization

**Query Batching**:
The tool automatically batches BloodHound queries to improve performance:
- Processes accounts in parallel
- Caches results to avoid duplicate queries
- Configurable batch sizes

**Controllables Limit**:
The `controllables_limit` parameter controls how many controlled objects are initially queried:
- Lower values (10-50): Faster queries, may miss some high-privilege accounts
- Higher values (100-500): More complete data, slower queries
- Recommended: Start at 10, increase if needed

**Network Optimization**:
- Use local BloodHound instance to reduce latency
- Ensure stable network connection
- Consider VPN overhead if accessing remote instance

### Data Privacy and Security

**Best Practices**:

1. **Secure Credentials**:
   ```bash
   chmod 600 config/bloodhound.json
   # Ensure file is in .gitignore (already included)
   ```

2. **Use HTTPS**:
   Always use `"scheme": "https"` in production

3. **Rotate Tokens**:
   Regenerate API tokens quarterly or after personnel changes

4. **Limit Access**:
   Use dedicated service account with minimal BloodHound permissions

5. **Network Security**:
   - Use firewall rules to restrict API access
   - Consider network segmentation for sensitive environments

### Running Without BloodHound

Password!AtTheDisco can run without BloodHound integration:

**What You Lose**:
- No Domain Admin pathway detection
- No controlled object counts
- No account property data (enabled, last logon)
- Reduced environmental scoring accuracy

**What Still Works**:
- Password complexity analysis
- HIBP breach detection
- Dictionary/pattern detection
- Password similarity analysis
- Base and temporal scoring

**Minimal Configuration** (to skip BloodHound):
```json
{
  "domain": "127.0.0.1",
  "port": 8080,
  "scheme": "http",
  "token_id": "dummy",
  "token_key": "dummy"
}
```

The tool will attempt connection but gracefully handle failures.

## Have I Been Pwned (HIBP) Integration

HIBP integration checks passwords against 1.3 billion breached NTLM hashes from data breaches.

### What HIBP Provides

- **Breach Detection**: Identifies if password hash has been exposed
- **Breach Count**: Number of times hash appears in breaches
- **Risk Categorization**: 7-level risk system based on breach frequency
- **Evidence-Based Scoring**: Empirical data from real breaches

### Architecture

**HIBP Module** (`core/hibp_correlation.py`):
- `HIBPChecker` class - Main checker interface
- Three-tier lookup system (cache → index → file)
- Binary search with prefix indexing
- In-memory caching of most common hashes

**Lookup Flow**:
1. Check in-memory cache (top N most common hashes)
2. If miss, use binary search on index file
3. If found in index, sequential search within range
4. Return breach status and count

**Performance Characteristics**:
- Cache hits: <1ms (instant)
- Index lookups: 10-50ms (binary search + sequential scan)
- First run: 5-10 minutes (index building, one-time)
- Subsequent runs: 1-2 seconds (index loading)

### Setup Instructions

#### Step 1: Download HIBP Database

**Option 1: Using Git Submodule** (Recommended)
```bash
git submodule add https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader.git
cd PwnedPasswordsDownloader
# Follow their README to download pwnedpasswords_ntlm.txt
```

**Option 2: Direct Download**
```bash
# Clone the downloader
git clone https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader.git
cd PwnedPasswordsDownloader

# Download the NTLM hash file (follow their instructions)
# This may take 30-60 minutes depending on connection speed
```

**File Details**:
- **Filename**: `pwnedpasswords_ntlm.txt`
- **Size**: ~1.9GB compressed, ~42GB uncompressed
- **Format**: `NTLM_HASH:BREACH_COUNT` (one per line)
- **Contents**: 1.3 billion NTLM hashes from data breaches
- **Updates**: Downloaded file is a snapshot; re-download periodically for updates

#### Step 2: Configure HIBP

Create `config/hibp.json`:

```json
{
  "ntlm_hash_file": "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt",
  "enable_lookup": true,
  "cache_size": 1000000,
  "prefix_length": 5
}
```

**Configuration Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ntlm_hash_file` | string | Required | Path to HIBP NTLM database (relative or absolute) |
| `enable_lookup` | boolean | true | Enable/disable HIBP checking |
| `cache_size` | integer | 1000000 | Number of hashes to cache in memory |
| `prefix_length` | integer | 5 | Index prefix length (do not change) |

#### Step 3: First Run (Index Building)

On first run, the tool builds an index:

```bash
python main.py -d "DOMAIN:cracked.txt:uncracked.txt"
```

**Expected Output**:
```
Building HIBP index...
Progress: 10,000,000 lines processed...
Progress: 20,000,000 lines processed...
Progress: 30,000,000 lines processed...
...
✓ Index built successfully in 8m 23s
✓ Index saved to: pwnedpasswords_ntlm.txt.index5
✓ Cached 1,000,000 most common hashes
```

**Index File**:
- **Filename**: `pwnedpasswords_ntlm.txt.index5`
- **Size**: ~100MB
- **Purpose**: Enables fast binary search (5-character prefix → file offset)
- **Reused**: Subsequent runs load in 1-2 seconds

### HIBP Tier System

Password!AtTheDisco uses a **7-tier categorization** based on breach frequency:

| Tier | Breach Count | Risk Level | Description |
|------|--------------|------------|-------------|
| 0 | 0 | None | Not found in breaches |
| 1 | 1-9 | Low | Rarely seen in breaches |
| 2 | 10-99 | Medium | Uncommon in breaches |
| 3 | 100-999 | High | Common in breaches |
| 4 | 1,000-9,999 | Very High | Very common in breaches |
| 5 | 10,000-99,999 | Extreme | Extremely common password |
| 6 | 100,000+ | Critical | One of most common passwords |

**Examples**:
- `password123` - Tier 6 (2.4 million breaches)
- `Welcome1!` - Tier 5 (47,000 breaches)
- `MyD0g$Name` - Tier 2 (87 breaches)
- `Xk9#mP2$vL8!` - Tier 0 (not breached)

### Impact on Risk Scoring

HIBP affects both **Base Score** and **Environmental Score**:

**Base Score Component** (HIBP Tier):
- Tier 0 (Not breached): +0.0 points
- Tier 1 (1-9): +2.0 points
- Tier 2 (10-99): +4.0 points
- Tier 3 (100-999): +6.0 points
- Tier 4 (1,000-9,999): +8.0 points
- Tier 5 (10,000-99,999): +9.0 points
- Tier 6 (100,000+): +10.0 points (maximum base score)

**Environmental Score Multiplier** (HIBP Factor):
- Not breached: 1.0x
- 1-99 breaches: 1.1x
- 100-999 breaches: 1.2x
- 1,000-9,999 breaches: 1.3x
- 10,000-99,999 breaches: 1.4x
- 100,000+ breaches: 1.5x

**Example Impact**:
```
Password: "Password123!"
HIBP: 2,400,000 breaches (Tier 6)

Base Score Contribution: +10.0 (maximum)
Environmental Multiplier: 1.5x
Risk Vector: HIBP:C (Critical)
Final Result: HIGH or CRITICAL risk
```

### Performance Tuning

**Cache Size Optimization**:

The `cache_size` parameter controls memory vs. speed trade-off:

| Cache Size | RAM Usage | Cache Hit Rate | Recommended For |
|------------|-----------|----------------|-----------------|
| 100,000 | ~5MB | ~60% | Memory-constrained systems |
| 500,000 | ~25MB | ~80% | Balanced performance |
| 1,000,000 | ~50MB | ~90% | Default (recommended) |
| 5,000,000 | ~250MB | ~95% | High-performance systems |
| 10,000,000 | ~500MB | ~97% | Maximum performance |

**Calculation**:
- Each hash: ~32 bytes (NTLM hash) + ~8 bytes (count) = ~40 bytes
- 1M hashes ≈ 40MB + overhead ≈ 50MB

**Storage Performance**:
- **SSD**: 10-50ms per uncached lookup
- **HDD**: 50-200ms per uncached lookup
- **Recommendation**: Use SSD for HIBP database (10x faster)

### Disabling HIBP

To disable HIBP checking:

```json
{
  "enable_lookup": false
}
```

**When to Disable**:
- HIBP database not available
- Performance requirements exceed lookup time
- Air-gapped environments without HIBP access
- Testing scenarios

**What You Lose**:
- No breach detection
- No HIBP tier scoring
- Reduced base score accuracy
- Missing environmental multiplier

**What Still Works**:
- All password complexity analysis
- Dictionary/pattern detection
- BloodHound privilege scoring
- Password similarity analysis

### Updating HIBP Database

HIBP database is periodically updated with new breaches:

**Update Process**:
1. Download latest `pwnedpasswords_ntlm.txt` from HIBP
2. Replace old file with new file
3. Delete old index file: `rm pwnedpasswords_ntlm.txt.index5`
4. Run tool to rebuild index (automatic on next run)

**Recommended Frequency**: Quarterly or after major breach announcements

### Troubleshooting

**Issue: "HIBP file not found"**

Solution:
```bash
# Verify file exists
ls -lh PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt

# Check path in config
cat config/hibp.json

# Ensure path is correct (relative to project root)
```

**Issue: Index building fails with "No space left on device"**

Solution:
```bash
# Check available disk space (need ~100MB)
df -h .

# Free up space or move to larger partition
```

**Issue: Slow lookups after index built**

Diagnosis:
```python
# Verify index loaded correctly
python3 -c "
from core.hibp_correlation import HIBPChecker
checker = HIBPChecker()
print(f'Index size: {len(checker.index)}')
print(f'Cache size: {len(checker.hash_cache)}')
"
```

Expected output:
```
Index size: 1048576
Cache size: 1000000
```

**Issue: High memory usage**

Solution: Reduce cache size in `config/hibp.json`:
```json
{
  "cache_size": 500000  // Reduced from 1000000
}
```

## Hashcat Integration

Hashcat integration automates password cracking and potfile management.

### What Hashcat Provides

- **Password Cracking**: Automated cracking with wordlists and rules
- **Potfile Management**: Tracking cracked passwords across runs
- **Progress Tracking**: Real-time cracking status and ETA
- **Session Management**: Resume interrupted cracking sessions

### Architecture

**Hashcat Module** (`core/hashcat_integration.py`):
- `HashcatRunner` class - Automation wrapper
- `HashcatSession` class - Session management
- JSON status output parsing
- Brain mode support for distributed cracking

### Setup Instructions

#### Step 1: Install Hashcat

**Linux (Debian/Ubuntu)**:
```bash
sudo apt update
sudo apt install hashcat
```

**macOS**:
```bash
brew install hashcat
```

**From Source**:
```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
sudo make install
```

#### Step 2: Configure Hashcat

Create `config/hashcat.json`:

```json
{
  "binary_path": "/usr/bin/hashcat",
  "wordlists_dir": "/usr/share/wordlists",
  "rules_dir": "/usr/share/hashcat/rules",
  "potfile_dir": "hashcat_potfiles",
  "enable_json_status": true,
  "enable_brain_mode": false,
  "brain_host": "127.0.0.1",
  "brain_port": 6863,
  "brain_password": "changeme",
  "default_workload_profile": 3,
  "enable_optimized_kernel": true,
  "status_timer": 10
}
```

**Configuration Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `binary_path` | string | /usr/bin/hashcat | Path to hashcat binary |
| `wordlists_dir` | string | /usr/share/wordlists | Wordlist directory |
| `rules_dir` | string | /usr/share/hashcat/rules | Rule file directory |
| `potfile_dir` | string | hashcat_potfiles | Potfile storage directory |
| `enable_json_status` | boolean | true | Enable JSON status output |
| `enable_brain_mode` | boolean | false | Enable distributed cracking |
| `brain_host` | string | 127.0.0.1 | Brain server hostname |
| `brain_port` | integer | 6863 | Brain server port |
| `brain_password` | string | changeme | Brain server password |
| `default_workload_profile` | integer | 3 | GPU workload (1-4) |
| `enable_optimized_kernel` | boolean | true | Use -O flag for speed |
| `status_timer` | integer | 10 | Status update interval (seconds) |

#### Step 3: Verify Installation

```bash
# Check hashcat version
hashcat --version
# Expected: hashcat v6.2.6 or higher

# Test basic functionality
hashcat --benchmark
```

### Generating Input Files

**Extract NTLM Hashes**:

From Active Directory:
```powershell
# Using ntdsutil or DSInternals
Get-ADReplAccount -All -Server DC01 | Format-Custom -View HashcatNT | Out-File hashes.txt
```

**Crack with Hashcat**:
```bash
# Crack using wordlist
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# Crack with rules
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Crack with masks (brute force)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d?s
```

**Generate Password!AtTheDisco Input Files**:
```bash
# Cracked passwords (with plaintext)
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > domain_cracked.txt

# Uncracked hashes (no plaintext)
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > domain_uncracked.txt
```

**Output Format**:
```
# Cracked file
john@CORP.INT:1001:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::Password123

# Uncracked file
admin@CORP.INT:500:aad3b435b51404eeaad3b435b51404ee:5F4DCC3B5AA765D61D8327DEB882CF99:::
```

### Workload Profiles

Hashcat workload profiles control GPU utilization:

| Profile | Name | GPU Usage | Use Case |
|---------|------|-----------|----------|
| 1 | Low | ~20% | Desktop use, minimal impact |
| 2 | Default | ~50% | Balanced performance |
| 3 | High | ~90% | Dedicated cracking |
| 4 | Nightmare | ~100% | Maximum performance, system unusable |

**Recommendation**: Use profile 3 for dedicated cracking systems, profile 2 for shared systems.

### Brain Mode (Distributed Cracking)

Brain mode enables distributed cracking across multiple systems:

**Enable Brain Server**:
```bash
hashcat --brain-server --brain-port 6863 --brain-password changeme
```

**Configure Clients** (`config/hashcat.json`):
```json
{
  "enable_brain_mode": true,
  "brain_host": "192.168.1.100",
  "brain_port": 6863,
  "brain_password": "changeme"
}
```

**Benefits**:
- Avoid duplicate work across systems
- Coordinate attack strategies
- Centralized progress tracking

### Best Practices

**Wordlist Strategy**:
1. Start with common passwords (rockyou.txt)
2. Add corporate-specific wordlists (company name, product names)
3. Use rules for variations (best64.rule, dive.rule)
4. Finish with masks for brute force

**Potfile Management**:
- Use separate potfiles per audit: `audit_YYYY-MM-DD.pot`
- Archive potfiles for historical analysis
- Never delete potfiles (accumulate knowledge over time)

**Performance Optimization**:
- Use `-O` flag (optimized kernels) for 2-4x speedup
- Disable host system GUI when cracking
- Monitor GPU temperature (use fans/cooling)
- Use multiple GPUs if available

**Security**:
- Encrypt potfiles at rest: `gpg -c audit.pot`
- Restrict access to cracking systems
- Use dedicated air-gapped systems for sensitive audits
- Securely wipe hash files after audits

### Troubleshooting

**Issue: "clCreateBuffer(): CL_OUT_OF_RESOURCES"**

Solution: Reduce workload profile or use smaller wordlists
```bash
hashcat -m 1000 -w 2 hashes.txt wordlist.txt  # Reduce from -w 3
```

**Issue: Slow cracking performance**

Diagnosis:
```bash
# Check GPU utilization
nvidia-smi  # For NVIDIA GPUs
rocm-smi    # For AMD GPUs
```

Solution:
- Update GPU drivers
- Increase workload profile
- Use optimized kernel (`-O` flag)
- Close other GPU applications

**Issue: "Invalid username or hash"**

Solution: Verify hashcat format:
```bash
# Correct format (colon-separated, 6 or 7 fields)
user@DOMAIN:RID:LMhash:NTLMhash:::password
```

## Custom Integrations

Password!AtTheDisco supports custom integrations through its modular architecture.

### Integration Points

**1. Custom Scorers** (`core/scoring.py`):
Add custom risk factors to the scoring engine.

**2. Custom Analyzers** (`core/password_analysis.py`):
Implement additional password analysis logic.

**3. Custom Reports** (`report_lib/`):
Create new report formats or customize existing ones.

**4. Custom Visualizations** (`visualizations/`):
Add new chart types or modify existing visualizations.

### Example: Custom SIEM Integration

**Export to Splunk**:
```python
import json
import requests

# Read Password!AtTheDisco JSON output
with open('reports/latest/csv/DOMAIN_detailed_report.json') as f:
    data = json.load(f)

# Send to Splunk HEC
for account in data['accounts']:
    event = {
        'sourcetype': 'password_audit',
        'event': account
    }
    requests.post(
        'https://splunk.company.com:8088/services/collector',
        headers={'Authorization': 'Splunk YOUR-HEC-TOKEN'},
        json=event
    )
```

**Export to Elasticsearch**:
```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://elastic.company.com:9200'])

with open('reports/latest/csv/DOMAIN_detailed_report.json') as f:
    data = json.load(f)

for i, account in enumerate(data['accounts']):
    es.index(index='password-audit', id=i, document=account)
```

### Example: Custom Notification Integration

**Send alerts for critical accounts**:
```python
import json
import smtplib
from email.mime.text import MIMEText

with open('reports/latest/csv/DOMAIN_detailed_report.json') as f:
    data = json.load(f)

critical_accounts = [
    acc for acc in data['accounts']
    if acc['Risk Level'] == 'Critical'
]

if critical_accounts:
    body = f"Found {len(critical_accounts)} critical accounts:\n\n"
    for acc in critical_accounts[:10]:  # Top 10
        body += f"- {acc['Username']}: Score {acc['Score']}\n"

    msg = MIMEText(body)
    msg['Subject'] = 'Password Audit: Critical Accounts Found'
    msg['From'] = 'audit@company.com'
    msg['To'] = 'security@company.com'

    smtp = smtplib.SMTP('mail.company.com')
    smtp.send_message(msg)
    smtp.quit()
```

## Related Documentation

- [Configuration Guide](CONFIGURATION.md) - Detailed configuration reference
- [Getting Started](GETTING_STARTED.md) - Quick setup instructions
- [Troubleshooting](TROUBLESHOOTING.md) - Common integration issues
- [Scoring System](SCORING_SYSTEM.md) - How integrations affect scoring

---

**Integration support**: For help with integrations, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open an issue on GitHub.
