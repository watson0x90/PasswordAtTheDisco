# Installation & Setup Guide

Complete installation instructions for Password!AtTheDisco.

## Table of Contents

- [System Requirements](#system-requirements)
- [Python Environment Setup](#python-environment-setup)
- [Dependencies Installation](#dependencies-installation)
- [Configuration Files](#configuration-files)
- [BloodHound Enterprise Setup](#bloodhound-enterprise-setup)
- [HIBP Database Setup](#hibp-database-setup)
- [Hashcat Setup](#hashcat-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Operating System**: Linux, macOS, or Windows with WSL
- **Python**: 3.9 or higher
- **Memory**: 4GB RAM (8GB+ recommended for HIBP)
- **Disk Space**:
  - Tool: ~100MB
  - HIBP Database: ~2GB
  - Reports: ~500MB per 10,000 accounts
- **Network**: Access to BloodHound Enterprise API (if using BloodHound integration)

### Recommended Requirements

- **Python**: 3.11+
- **Memory**: 16GB RAM
- **Disk**: SSD with 10GB+ free space
- **CPU**: 4+ cores for parallel processing

### Optional Dependencies

- **Hashcat 7.0+**: For password cracking (not required if using pre-cracked files)
- **Pandoc**: For Markdown to PDF conversion
- **BloodHound Enterprise**: For privilege escalation analysis

## Python Environment Setup

### Option 1: System Python (Simple)

```bash
# Check Python version
python3 --version  # Should be 3.9+

# Navigate to project directory
cd PasswordAtTheDisco
```

### Option 2: Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# OR
.\venv\Scripts\activate  # Windows

# Verify activation
which python  # Should show venv path
```

### Option 3: Conda Environment

```bash
# Create conda environment
conda create -n patd python=3.11

# Activate environment
conda activate patd

# Verify
which python  # Should show conda path
```

## Dependencies Installation

### Install Python Packages

```bash
# Install all required packages
pip install -r requirements.txt
```

This installs:
- **Flask 3.1.0** - Web server for HTML reports
- **Plotly 6.0+** - Interactive visualizations
- **OpenPyXL 3.1+** - Excel report generation
- **Requests 2.31+** - HTTP client for BloodHound API
- **PasswordLib** - NTLM hash generation (or pure Python fallback)

### Verify Installation

```bash
# Check installed packages
pip list | grep -E 'Flask|plotly|openpyxl|requests'

# Expected output:
# Flask         3.1.0
# plotly        6.0.0
# openpyxl      3.1.5
# requests      2.31.0
```

## Configuration Files

Password!AtTheDisco uses JSON configuration files in the `config/` directory.

### Step 1: Copy Example Files

```bash
cd PasswordAtTheDisco

# Copy all example configs
cp config/bloodhound.json.example config/bloodhound.json
cp config/hibp.json.example config/hibp.json
cp config/hashcat.json.example config/hashcat.json
cp config/application.json.example config/application.json
```

### Step 2: Basic Application Settings (Optional)

Edit `config/application.json`:

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

**Settings:**
- `server.port`: Port for web server (default: 8008)
- `server.host`: Bind address (use "0.0.0.0" for remote access)
- `ui.enable_animation`: Terminal animation during processing

### Step 3: Password Policy (Optional)

Edit `lists/password_policy.json` to match your organizational requirements:

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

You can add domain-specific policies:

```json
{
  "default": {
    "policy": { "min_length": 14, "max_password_age_days": 90, ... }
  },
  "PRODUCTION.CORP": {
    "policy": { "min_length": 16, "max_password_age_days": 60, ... }
  },
  "DEV.CORP": {
    "policy": { "min_length": 12, "max_password_age_days": 180, ... }
  }
}
```

## BloodHound Enterprise Setup

BloodHound integration enriches password analysis with Active Directory privilege data.

### Step 1: Get API Credentials

1. Log into BloodHound Enterprise UI
2. Navigate to **Settings → API Tokens**
3. Click **Create New Token**
4. Save the **Token ID** and **Token Key**

### Step 2: Configure BloodHound

Edit `config/bloodhound.json`:

```json
{
  "domain": "bloodhound.yourcompany.com",
  "port": 443,
  "scheme": "https",
  "token_id": "47a0ed15-f3ac-475a-98ea-a4212e7ad6d1",
  "token_key": "pOF/JGUrixzkJP9LA9VRnYatuFO7moxVPEm69o58BdFViWAydVPvRQ==",
  "search_limit": 1,
  "controllables_limit": 10
}
```

**Settings:**
- `domain`: BloodHound server hostname or IP
- `port`: API port (usually 443 for HTTPS, 8080 for HTTP)
- `scheme`: "https" (recommended) or "http"
- `token_id`: Your API token ID
- `token_key`: Your API token key (keep secret!)
- `search_limit`: Max search results per query (default: 1)
- `controllables_limit`: Initial controllables limit (default: 10)

### Step 3: Test Connection

```bash
python main.py --test-bh
```

**Expected output:**
```
✓ Client initialized
✓ API connection successful (version: 5.x.x)
✓ Found 3 domains
✓ Sample data query successful
BloodHound connection test: SUCCESS
```

**If connection fails:**
- Verify server is reachable: `ping bloodhound.yourcompany.com`
- Check firewall rules allow outbound HTTPS
- Verify token credentials are correct
- Check scheme matches server (http vs https)

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#bloodhound-connection-issues) for more help.

## HIBP Database Setup

Have I Been Pwned (HIBP) integration checks if passwords have been exposed in data breaches.

### Step 1: Initialize HIBP Downloader Submodule

Password!AtTheDisco includes a customized HIBP downloader as a git submodule:

```bash
# If you cloned without --recurse-submodules, initialize the submodule
git submodule update --init --recursive

# Verify the submodule is checked out
ls -la PwnedPasswordsDownloader/
```

**What this does:**
- Checks out the `watson0x90/PwnedPasswordsDownloader` fork
- Uses the `updated-downlaoder` branch with optimizations
- Creates the `PwnedPasswordsDownloader/` directory

### Step 2: Install .NET SDK (Required for Downloader)

The HIBP downloader is a .NET application and requires the .NET SDK:

**Linux (Debian/Ubuntu):**
```bash
# Install .NET 8.0 SDK
wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

sudo apt-get update
sudo apt-get install -y dotnet-sdk-8.0

# Verify installation
dotnet --version
```

**macOS:**
```bash
# Install via Homebrew
brew install dotnet-sdk

# Verify installation
dotnet --version
```

**Windows:**
- Download and install from: https://dotnet.microsoft.com/download/dotnet/8.0

### Step 3: Build the HIBP Downloader

```bash
cd PwnedPasswordsDownloader/src/HaveIBeenPwned.PwnedPasswords.Downloader

# Restore dependencies and build
dotnet restore
dotnet build -c Release

# Verify build succeeded
ls -la bin/Release/net8.0/
```

### Step 4: Download HIBP NTLM Database

Use the downloader to fetch the NTLM hash database:

```bash
# Run the downloader (from the PwnedPasswordsDownloader directory)
cd ../../  # Back to PwnedPasswordsDownloader root

dotnet run --project src/HaveIBeenPwned.PwnedPasswords.Downloader \
  -c Release -- \
  -o pwnedpasswords_ntlm.txt \
  -f ntlm

# This will download and extract the database
# File size: ~2GB download, ~42GB uncompressed
# Contains: 1.3+ billion NTLM hashes
# Time: 30-60 minutes depending on connection
```

**What happens during download:**
1. Downloads compressed HIBP database from CloudFlare
2. Extracts and formats as NTLM hashes
3. Saves to `pwnedpasswords_ntlm.txt`
4. File format: `HASH:COUNT` (e.g., `8846F7EAEE8FB117AD06BDD830B7586C:12345`)

**Alternative - Manual Download:**

If the downloader fails, you can manually download:

1. Visit: https://haveibeenpwned.com/Passwords
2. Download the NTLM hash file (CloudFlare link)
3. Extract to `PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt`
4. Verify format: `HASH:COUNT` per line

### Step 5: Return to Project Root

```bash
# Go back to main project directory
cd ../../  # Back to PasswordAtTheDisco root
```

### Step 6: Configure HIBP

Edit `config/hibp.json`:

```json
{
  "ntlm_hash_file": "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt",
  "enable_lookup": true,
  "cache_size": 1000000,
  "prefix_length": 5
}
```

**Settings:**
- `ntlm_hash_file`: Path to HIBP database (relative or absolute)
- `enable_lookup`: Enable breach checking (true/false)
- `cache_size`: Number of hashes to cache (default: 1M)
- `prefix_length`: Index prefix length (default: 5)

### Step 7: First Run (Index Building)

On first run with HIBP enabled, the tool builds an index:

```bash
python main.py -d "DOMAIN:cracked.txt:uncracked.txt"
```

**Expected output:**
```
Building HIBP index...
Progress: 10,000,000 lines processed...
Progress: 20,000,000 lines processed...
...
✓ Index built successfully (5-10 minutes)
✓ Index saved to: pwnedpasswords_ntlm.txt.index5
```

**Index file:** `pwnedpasswords_ntlm.txt.index5` (~100MB)

Subsequent runs load the index in 1-2 seconds (no rebuilding needed).

### HIBP Performance Notes

- **Cache size**: Adjust based on available RAM
  - 1M hashes = ~50MB RAM
  - 10M hashes = ~500MB RAM
- **Prefix length**: Don't change (optimized at 5)
- **Lookup speed**:
  - Cache hit: <1ms
  - Index lookup: 10-50ms
  - File search: 50-100ms

## Hashcat Setup

Hashcat is used to crack NTLM hashes before running the tool.

### Step 1: Install Hashcat

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install hashcat
```

**macOS:**
```bash
brew install hashcat
```

**From Source:**
```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
```

### Step 2: Configure Hashcat

Edit `config/hashcat.json`:

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

**Settings:**
- `binary_path`: Path to hashcat binary
- `wordlists_dir`: Directory containing wordlists
- `rules_dir`: Directory containing rule files
- `potfile_dir`: Where to store potfiles
- `default_workload_profile`: GPU load (1=low, 4=insane)
- `enable_optimized_kernel`: Use -O flag (faster but less accurate)

### Step 3: Verify Hashcat

```bash
hashcat --version
# Expected: hashcat v6.2.6 or higher
```

## Verification

Run a complete verification of your installation:

### Test 1: Python Dependencies

```bash
python3 -c "import flask, plotly, openpyxl, requests; print('✓ All dependencies installed')"
```

### Test 2: Configuration Files

```bash
# Check all config files exist
ls -l config/*.json

# Expected output:
# -rw-r--r-- application.json
# -rw-r--r-- bloodhound.json
# -rw-r--r-- hashcat.json
# -rw-r--r-- hibp.json
```

### Test 3: BloodHound Connection

```bash
python main.py --test-bh
# Should show: BloodHound connection test: SUCCESS
```

### Test 4: Tool Version

```bash
python main.py --version
# Should show: Password!AtTheDisco v1.0
```

### Test 5: Help Menu

```bash
python main.py --help
```

Should display:
```
usage: main.py [-h] [-d DOMAINS [DOMAINS ...]] [-p] [-s] [--test-bh] [-v]

Audit password files across multiple domains.

options:
  -h, --help            show this help message and exit
  -d DOMAINS [DOMAINS ...], --domains DOMAINS [DOMAINS ...]
  -p, --pdf             Generate PDFs from existing Markdown reports
  -s, --serve           Start HTTP server to view HTML reports
  --test-bh             Test BloodHound API connection
  -v, --version         Show program version
```

## Directory Structure Verification

After installation, your directory should look like:

```
PasswordAtTheDisco/
├── config/
│   ├── application.json         ✓ Created
│   ├── bloodhound.json          ✓ Created
│   ├── hashcat.json             ✓ Created
│   └── hibp.json                ✓ Created
├── lists/
│   ├── password_policy.json     ✓ Exists (may need customization)
│   ├── forbidden_words.txt      ✓ Exists
│   ├── common_passwords.txt     ✓ Exists
│   └── dictionary_words.txt     ✓ Exists
├── PwnedPasswordsDownloader/    ✓ Optional (HIBP)
│   └── pwnedpasswords_ntlm.txt
├── main.py                      ✓ Entry point
├── requirements.txt             ✓ Dependencies
└── venv/                        ✓ Optional (virtual env)
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'flask'"

**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### "Configuration file not found"

**Solution**: Copy example files
```bash
cp config/bloodhound.json.example config/bloodhound.json
```

### "Permission denied" when accessing files

**Solution**: Check file permissions
```bash
chmod +r config/*.json
```

### HIBP index build fails

**Solution**: Ensure sufficient disk space
```bash
df -h .  # Check free space (need ~100MB)
```

### BloodHound connection timeout

**Solution**: Check network connectivity
```bash
ping bloodhound.yourcompany.com
telnet bloodhound.yourcompany.com 443
```

## Next Steps

1. ✅ Installation complete!
2. 📖 Read the [User Guide](USER_GUIDE.md) for usage instructions
3. 🔧 Review [Configuration Guide](CONFIGURATION.md) for advanced settings
4. 🚀 Run your first audit - see [Getting Started](GETTING_STARTED.md#step-4-run-your-first-audit)

## Upgrading

To upgrade to a newer version:

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Check version
python main.py --version
```

## Uninstalling

To remove Password!AtTheDisco:

```bash
# Deactivate virtual environment (if using)
deactivate

# Remove installation directory
cd ..
rm -rf PasswordAtTheDisco

# Remove virtual environment (if created outside project)
rm -rf venv
```

---

**Installation complete!** You're ready to start auditing passwords. See the [Getting Started Guide](GETTING_STARTED.md) for your first analysis.
