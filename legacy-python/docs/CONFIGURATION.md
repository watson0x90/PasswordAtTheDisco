# Configuration Reference Guide

Complete reference for all Password!AtTheDisco configuration options.

## Table of Contents

- [Configuration Files Overview](#configuration-files-overview)
- [BloodHound Configuration](#bloodhound-configuration)
- [HIBP Configuration](#hibp-configuration)
- [Hashcat Configuration](#hashcat-configuration)
- [Application Configuration](#application-configuration)
- [Password Policy Configuration](#password-policy-configuration)
- [Default Values Reference](#default-values-reference)
- [Security Best Practices](#security-best-practices)

## Configuration Files Overview

All configuration files are located in the `config/` directory and use JSON format.

```
config/
├── bloodhound.json       # BloodHound Enterprise API
├── hibp.json             # Have I Been Pwned database
├── hashcat.json          # Hashcat integration
└── application.json      # Application settings
```

Additionally, password policies are configured in:
```
lists/
└── password_policy.json  # Domain-specific policies
```

### Example Files

All configuration files have `.example` templates:

```bash
config/bloodhound.json.example
config/hibp.json.example
config/hashcat.json.example
config/application.json.example
```

Copy these to create your configurations:

```bash
cd config
cp bloodhound.json.example bloodhound.json
cp hibp.json.example hibp.json
cp hashcat.json.example hashcat.json
cp application.json.example application.json
```

## BloodHound Configuration

**File**: `config/bloodhound.json`
**Purpose**: Configure BloodHound Enterprise API connection for Active Directory privilege analysis.

### Complete Configuration

```json
{
  "domain": "bloodhound.company.com",
  "port": 443,
  "scheme": "https",
  "token_id": "your-token-id-here",
  "token_key": "your-token-key-here",
  "search_limit": 1,
  "controllables_limit": 10
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | string | Yes | `127.0.0.1` | BloodHound server hostname or IP |
| `port` | integer | Yes | `8080` | API port (443 for HTTPS, 8080 for HTTP) |
| `scheme` | string | Yes | `http` | Protocol scheme (`http` or `https`) |
| `token_id` | string | Yes | - | BloodHound API token ID |
| `token_key` | string | Yes | - | BloodHound API token key |
| `search_limit` | integer | No | `1` | Maximum results per search query |
| `controllables_limit` | integer | No | `10` | Initial controllables query limit |

### Parameter Details

#### `domain`
- **Format**: Hostname or IP address (no protocol prefix)
- **Examples**:
  - `bloodhound.company.com`
  - `192.168.1.100`
  - `bhe-server.local`
- **Note**: Do not include `http://` or `https://` prefix

#### `port`
- **Common values**:
  - `443` - HTTPS (recommended for production)
  - `8080` - HTTP (default BloodHound CE)
  - `80` - HTTP alternative
- **Range**: 1-65535
- **Note**: Must match server configuration

#### `scheme`
- **Values**: `http` or `https`
- **Recommended**: `https` for production
- **Note**: Must match server TLS configuration

#### `token_id` and `token_key`
- **Where to get**: BloodHound UI → Settings → API Tokens
- **Security**: Keep these secret! Do not commit to version control
- **Format**: UUID for token_id, Base64 string for token_key
- **Rotation**: Regenerate periodically for security

#### `search_limit`
- **Purpose**: Limits API search results
- **Default**: `1` (assumes unique usernames)
- **When to increase**:
  - If users exist in multiple domains
  - If search returns insufficient results
- **Performance**: Higher values = more API calls

#### `controllables_limit`
- **Purpose**: Limits controllable objects in initial query
- **Default**: `10` (first query only, full query follows)
- **Range**: 1-1000
- **Note**: Tool automatically fetches all controllables regardless of this setting

### Testing BloodHound Configuration

```bash
# Test connection
python main.py --test-bh

# Expected success output:
✓ Client initialized
✓ API connection successful (version: 5.x.x)
✓ Found N domains
✓ Sample data query successful
BloodHound connection test: SUCCESS
```

### Code Reference

Loaded in: `core/config.py` (lines 145-154)
Used by: `core/bloodhound_integration.py` (line 18)

## HIBP Configuration

**File**: `config/hibp.json`
**Purpose**: Configure Have I Been Pwned NTLM hash database for breach detection.

### Complete Configuration

```json
{
  "ntlm_hash_file": "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt",
  "enable_lookup": true,
  "cache_size": 1000000,
  "prefix_length": 5
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ntlm_hash_file` | string | Yes | - | Path to HIBP NTLM database file |
| `enable_lookup` | boolean | No | `true` | Enable/disable breach checking |
| `cache_size` | integer | No | `1000000` | Number of hashes to cache in memory |
| `prefix_length` | integer | No | `5` | Prefix length for indexing (do not change) |

### Parameter Details

#### `ntlm_hash_file`
- **Format**: Relative or absolute path
- **Relative paths**: Resolved from project root
- **Examples**:
  - `PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt` (relative)
  - `/data/hibp/pwnedpasswords_ntlm.txt` (absolute)
- **File size**: ~1.9GB
- **Contents**: 1.3 billion NTLM hashes with occurrence counts
- **Download**: See [INSTALLATION.md](INSTALLATION.md#hibp-database-setup)

#### `enable_lookup`
- **Purpose**: Master switch for HIBP functionality
- **Values**:
  - `true` - Enable breach checking
  - `false` - Disable (skips HIBP entirely)
- **Use case for disabling**:
  - Testing without HIBP database
  - Speeding up analysis when breach data not needed

#### `cache_size`
- **Purpose**: Number of most common breached hashes to keep in memory
- **Default**: 1,000,000 hashes (~50MB RAM)
- **Memory usage**: ~50 bytes per hash
- **Recommendations**:
  - 4GB RAM system: 500,000 hashes
  - 8GB RAM system: 1,000,000 hashes (default)
  - 16GB+ RAM system: 10,000,000 hashes
- **Performance**: Larger cache = faster lookups for common passwords

#### `prefix_length`
- **Purpose**: Hash prefix length for binary search indexing
- **Default**: `5` (optimized)
- **Do not change**: Algorithm is tuned for 5-character prefixes
- **Technical**: Creates 16^5 = 1,048,576 index entries

### HIBP Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| **First run** | 5-10 minutes | Index building (one-time) |
| **Subsequent runs** | 1-2 seconds | Index loading |
| **Cache hit** | <1ms | Common passwords |
| **Index lookup** | 10-50ms | Uncommon passwords |
| **File search** | 50-100ms | Very rare passwords |
| **Index file size** | ~100MB | Created automatically |

### Index File

The tool automatically creates an index file on first run:

```
pwnedpasswords_ntlm.txt.index5
```

- **Size**: ~100MB
- **Purpose**: Enables fast binary search
- **Rebuild**: Delete file to force rebuild
- **Location**: Same directory as NTLM file

### Code Reference

Loaded in: `core/config.py` (lines 186-192)
Used by: `core/hibp_correlation.py` (line 22)

## Hashcat Configuration

**File**: `config/hashcat.json`
**Purpose**: Configure Hashcat 7.0+ integration for password cracking automation.

### Complete Configuration

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

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `binary_path` | string | Yes | - | Path to hashcat executable |
| `wordlists_dir` | string | Yes | - | Directory containing wordlists |
| `rules_dir` | string | Yes | - | Directory containing rule files |
| `potfile_dir` | string | Yes | `hashcat_potfiles` | Directory for potfiles |
| `enable_json_status` | boolean | No | `true` | Enable JSON progress output |
| `enable_brain_mode` | boolean | No | `false` | Enable distributed cracking |
| `brain_host` | string | No | `127.0.0.1` | Brain server hostname |
| `brain_port` | integer | No | `6863` | Brain server port |
| `brain_password` | string | No | `changeme` | Brain authentication password |
| `default_workload_profile` | integer | No | `3` | GPU workload (1-4) |
| `enable_optimized_kernel` | boolean | No | `true` | Use -O flag |
| `status_timer` | integer | No | `10` | Status update interval (seconds) |

### Parameter Details

#### `binary_path`
- **Format**: Absolute or relative path
- **Common locations**:
  - Linux: `/usr/bin/hashcat`
  - macOS: `/usr/local/bin/hashcat`
  - Windows: `C:\hashcat\hashcat.exe`
  - Relative: `../../../hashcat/hashcat`
- **Verification**: `which hashcat` or `where hashcat`

#### `wordlists_dir` and `rules_dir`
- **Format**: Directory paths
- **Common locations**:
  - Linux: `/usr/share/wordlists`, `/usr/share/hashcat/rules`
  - macOS: `/usr/local/share/wordlists`
  - Custom: `~/hashcat/wordlists`, `~/hashcat/rules`
- **Contents**:
  - Wordlists: `rockyou.txt`, custom dictionaries
  - Rules: `best64.rule`, `dive.rule`, etc.

#### `potfile_dir`
- **Purpose**: Stores cracked hashes persistently
- **Default**: `hashcat_potfiles` (relative to project)
- **Auto-created**: Directory created automatically if missing
- **Format**: One potfile per session

#### `enable_json_status`
- **Purpose**: Enable real-time JSON progress output
- **Values**:
  - `true` - Get structured progress data
  - `false` - Standard hashcat output
- **Use case**: Real-time progress monitoring in scripts

#### `enable_brain_mode`
- **Purpose**: Enable Hashcat Brain for distributed cracking
- **Requirements**:
  - Hashcat Brain server running
  - Network connectivity to brain server
- **Benefits**: Coordinate across multiple machines, avoid duplicate work
- **Security**: Use strong `brain_password`

#### `default_workload_profile`
- **Purpose**: GPU/CPU utilization level
- **Values**:
  - `1` - Low (desktop usable)
  - `2` - Moderate
  - `3` - High (recommended)
  - `4` - Insane (dedicated cracking rig)
- **Impact**: Higher = faster cracking, higher resource usage

#### `enable_optimized_kernel`
- **Purpose**: Use hashcat's -O flag for optimized kernels
- **Trade-off**:
  - `true` - Faster, supports passwords up to 31 characters
  - `false` - Slower, supports longer passwords
- **Recommended**: `true` for most scenarios

#### `status_timer`
- **Purpose**: How often to query status (in seconds)
- **Range**: 1-60
- **Default**: 10 seconds
- **Impact**: Lower = more frequent updates, higher CPU overhead

### Code Reference

Loaded in: `core/config.py` (lines 157-180)
Used by: `core/hashcat_integration.py` (line 26)

## Application Configuration

**File**: `config/application.json`
**Purpose**: General application settings (UI, server).

### Complete Configuration

```json
{
  "server": {
    "port": 8008,
    "host": "localhost"
  },
  "ui": {
    "enable_animation": true
  }
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `server.port` | integer | No | `8008` | HTTP server port |
| `server.host` | string | No | `localhost` | Server bind address |
| `ui.enable_animation` | boolean | No | `true` | Terminal animation toggle |

### Parameter Details

#### `server.port`
- **Purpose**: Port for `python main.py -s` web server
- **Range**: 1024-65535
- **Default**: 8008
- **Common alternatives**: 8000, 8080, 5000
- **Note**: Must be available (not in use)

#### `server.host`
- **Purpose**: Network interface to bind
- **Values**:
  - `localhost` - Local access only (secure)
  - `0.0.0.0` - All interfaces (allows remote access)
  - Specific IP - Bind to one interface
- **Security**: Use `localhost` unless remote access needed

#### `ui.enable_animation`
- **Purpose**: Show terminal animation during processing
- **Values**:
  - `true` - Show progress animation (default)
  - `false` - Disable animation (headless/CI)
- **Benefits of disabling**:
  - Slightly faster processing
  - Better for log files
  - Required for non-interactive environments

### Code Reference

Loaded in: `core/config.py` (lines 194-218)
Used by: `utils/serve.py` (line 31), `core/processor.py` (line 20)

## Password Policy Configuration

**File**: `lists/password_policy.json`
**Purpose**: Define domain-specific password complexity requirements.

### Complete Configuration

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
      "require_uppercase": false,
      "require_lowercase": true,
      "require_digits": false,
      "require_special": false,
      "max_password_age_days": 180
    }
  }
}
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `min_length` | integer | Yes | `8` | Minimum password length |
| `require_uppercase` | boolean | Yes | `true` | Require uppercase letters (A-Z) |
| `require_lowercase` | boolean | Yes | `true` | Require lowercase letters (a-z) |
| `require_digits` | boolean | Yes | `true` | Require digits (0-9) |
| `require_special` | boolean | Yes | `true` | Require special characters |
| `max_password_age_days` | integer | Yes | `90` | Maximum password age before expiration |

### Domain-Specific Policies

Policies are applied by domain name:

```json
{
  "default": { ... },           # Fallback for all domains
  "CORP.INT": { ... },          # Specific for CORP.INT
  "SUBSIDIARY.COM": { ... }     # Specific for SUBSIDIARY.COM
}
```

**Fallback hierarchy:**
1. Exact domain match (e.g., `CORP.INT`)
2. `default` policy
3. Hardcoded defaults (if file missing)

### Parameter Details

#### `min_length`
- **Purpose**: Minimum acceptable password length
- **Recommendations**:
  - NIST SP 800-63B: 8 characters minimum
  - Enterprise: 12-16 characters
  - High-security: 16+ characters
- **Scoring impact**: Passwords below this get compliance violations

#### `require_uppercase`, `require_lowercase`, `require_digits`, `require_special`
- **Purpose**: Character set requirements
- **Used for**: Compliance checking (not complexity scoring)
- **Note**: Complexity is scored separately based on actual character sets used

#### `max_password_age_days`
- **Purpose**: Password expiration policy
- **Common values**:
  - 90 days - Standard enterprise
  - 60 days - High-security environments
  - 180 days - Low-risk environments
  - 365 days - Relaxed policy
- **Scoring impact**: Used to calculate "days out of compliance"

### Code Reference

Loaded in: `core/config.py` (lines 33-57)
Function: `get_policy_for_domain()` (lines 64-90)
Used by: `core/processor.py` (line 103)

## Default Values Reference

Quick reference for all default values:

### BloodHound Defaults

```python
domain: "127.0.0.1"
port: 8080
scheme: "http"
search_limit: 1
controllables_limit: 10
```

### HIBP Defaults

```python
enable_lookup: true
cache_size: 1000000
prefix_length: 5
```

### Hashcat Defaults

```python
enable_json_status: true
enable_brain_mode: false
brain_port: 6863
default_workload_profile: 3
enable_optimized_kernel: true
status_timer: 10
```

### Application Defaults

```python
server.port: 8008
server.host: "localhost"
ui.enable_animation: true
```

### Password Policy Defaults

```python
min_length: 8
require_uppercase: true
require_lowercase: true
require_digits: true
require_special: true
max_password_age_days: 90
```

## Security Best Practices

### 1. Protect API Credentials

**BloodHound tokens are sensitive!**

```bash
# Add to .gitignore (already included)
config/bloodhound.json
config/hashcat.json

# Set restrictive permissions
chmod 600 config/bloodhound.json
chmod 600 config/hibp.json
```

### 2. Use HTTPS for BloodHound

```json
{
  "scheme": "https",  # Not "http"
  "port": 443
}
```

### 3. Rotate API Tokens Regularly

- Generate new tokens quarterly
- Revoke old tokens after rotation
- Use separate tokens per environment (dev/prod)

### 4. Limit Server Access

```json
{
  "server": {
    "host": "localhost"  # Not "0.0.0.0" unless needed
  }
}
```

### 5. Secure HIBP Database

```bash
# Ensure only readable by user
chmod 600 PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt
```

### 6. Environment Variables (Optional)

For CI/CD, use environment variables:

```bash
export BHE_TOKEN_ID="your-token-id"
export BHE_TOKEN_KEY="your-token-key"
```

Modify config loading to read from environment.

## Configuration Validation

The tool validates configurations on startup:

### BloodHound Validation
- File exists and is valid JSON
- Required fields present (domain, port, scheme, token_id, token_key)
- Port in valid range (1-65535)
- Scheme is "http" or "https"

### HIBP Validation
- File exists and is valid JSON
- ntlm_hash_file path resolves to existing file
- cache_size is positive integer

### Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Configuration file not found` | Missing config file | Copy from .example file |
| `Invalid JSON in configuration` | Syntax error | Validate JSON with linter |
| `Missing required field: token_id` | Incomplete config | Add missing fields |
| `HIBP hash file not found` | Wrong path | Check ntlm_hash_file path |

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#configuration-issues) for detailed help with:
- Configuration file errors
- BloodHound connection failures
- HIBP index build issues
- Permission problems

## Related Documentation

- [Installation Guide](INSTALLATION.md) - Initial setup
- [Integration Guide](INTEGRATIONS.md) - External tool setup
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues

---

**Configuration complete!** Your settings are loaded from `config/` on every run. No restart needed after changes.
