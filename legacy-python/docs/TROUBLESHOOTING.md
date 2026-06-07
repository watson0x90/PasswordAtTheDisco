# Troubleshooting Guide

Solutions to common issues with Password!AtTheDisco.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Errors](#configuration-errors)
- [BloodHound Connection](#bloodhound-connection)
- [HIBP Issues](#hibp-issues)
- [File Format Errors](#file-format-errors)
- [Performance Issues](#performance-issues)
- [Report Generation](#report-generation)
- [FAQ](#frequently-asked-questions)

## Installation Issues

### ModuleNotFoundError

**Error:**
```
ModuleNotFoundError: No module named 'flask'
```

**Cause**: Dependencies not installed

**Solution:**
```bash
pip install -r requirements.txt
```

### Permission Denied

**Error:**
```
PermissionError: [Errno 13] Permission denied: 'config/bloodhound.json'
```

**Cause**: Insufficient file permissions

**Solution:**
```bash
chmod 644 config/*.json
chmod 755 .
```

### Python Version Too Old

**Error:**
```
SyntaxError: invalid syntax (f-strings, match statements)
```

**Cause**: Python version < 3.9

**Solution:**
```bash
# Check version
python3 --version

# Upgrade Python or use virtual environment with Python 3.9+
python3.11 -m venv venv
source venv/bin/activate
```

## Configuration Errors

### Configuration File Not Found

**Error:**
```
ERROR: BloodHound configuration file not found!
Expected location: config/bloodhound.json
```

**Cause**: Missing configuration file

**Solution:**
```bash
cp config/bloodhound.json.example config/bloodhound.json
# Edit with your credentials
```

### Invalid JSON

**Error:**
```
ERROR: Invalid JSON in BloodHound configuration file!
Error: Expecting ',' delimiter: line 5 column 3
```

**Cause**: JSON syntax error (missing comma, extra comma, etc.)

**Solution:**
```bash
# Validate JSON online or with:
python3 -m json.tool config/bloodhound.json

# Common issues:
# - Trailing comma after last item
# - Missing quotes around strings
# - Using single quotes instead of double quotes
```

### Missing Required Field

**Error:**
```
KeyError: 'token_id'
```

**Cause**: Required configuration field missing

**Solution:**
Ensure all required fields are present:

```json
{
  "domain": "...",      // Required
  "port": 8080,         // Required
  "scheme": "https",    // Required
  "token_id": "...",    // Required
  "token_key": "..."    // Required
}
```

## BloodHound Connection

### Connection Refused

**Error:**
```
ConnectionError: Failed to connect to BloodHound API
```

**Diagnostic steps:**
```bash
# 1. Test network connectivity
ping bloodhound.company.com

# 2. Test port accessibility
telnet bloodhound.company.com 443
# OR
nc -zv bloodhound.company.com 443

# 3. Test HTTPS connection
curl -k https://bloodhound.company.com/api/version
```

**Common causes:**
- Firewall blocking outbound connections
- Wrong hostname/IP
- BloodHound server down
- Wrong port number

**Solutions:**
- Verify server is running
- Check firewall rules
- Verify port in config matches server
- Try IP address instead of hostname

### Authentication Failed

**Error:**
```
HTTP 401: Unauthorized
```

**Cause**: Invalid API credentials

**Solution:**
```bash
# 1. Regenerate token in BloodHound UI
# Settings → API Tokens → Create New Token

# 2. Update config/bloodhound.json with new credentials

# 3. Test connection
python main.py --test-bh
```

### SSL Certificate Error

**Error:**
```
SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Cause**: Self-signed certificate or certificate validation issues

**Temporary workaround** (development only):
```python
# Not recommended for production!
# Modify core/bloodhound_integration.py to disable verification
```

**Proper solution:**
- Install proper SSL certificate on BloodHound server
- Add CA certificate to system trust store

### No Domains Found

**Error:**
```
✗ Found 0 domains
```

**Cause**: BloodHound has no collected data

**Solution:**
```bash
# 1. Verify SharpHound data collection completed
# 2. Check data was uploaded to BloodHound
# 3. Verify domain name matches in BloodHound UI
```

## HIBP Issues

### HIBP File Not Found

**Error:**
```
FileNotFoundError: pwnedpasswords_ntlm.txt not found
```

**Cause**: HIBP database not downloaded or wrong path

**Solution:**
```bash
# 1. Verify file exists
ls -lh PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt

# 2. Check path in config
cat config/hibp.json

# 3. Download if missing
cd PwnedPasswordsDownloader
# Follow their download instructions
```

### Index Build Fails

**Error:**
```
OSError: [Errno 28] No space left on device
```

**Cause**: Insufficient disk space for index file

**Solution:**
```bash
# Check free space (need ~100MB)
df -h .

# Clean up space or move to larger partition
```

### Index Build Slow

**Symptom**: Index building takes >15 minutes

**Normal**: First index build takes 5-10 minutes

**Too slow causes:**
- Slow disk (HDD vs SSD)
- Competing disk I/O
- System under load

**Solution:**
- Run on SSD if possible
- Close other applications
- Wait for initial build (one-time cost)

### HIBP Lookups Slow

**Symptom**: Each password takes seconds to check

**Diagnosis:**
```python
# Check index loaded
python3 -c "
from core.hibp_correlation import HIBPChecker
checker = HIBPChecker()
print(f'Index size: {len(checker.index)}')
print(f'Cache size: {len(checker.hash_cache)}')
"
```

**Expected output:**
```
Index size: 1048576
Cache size: 1000000
```

**Solutions:**
- Ensure index file exists (`.index5` file)
- Increase cache_size in config
- Check disk I/O performance

## File Format Errors

### Invalid Hashcat Format

**Error:**
```
ValueError: Invalid line format - expected 6 colon-separated fields
```

**Cause**: Input file not in hashcat format

**Solution:**
Verify file format:

**Correct format:**
```
username@DOMAIN.INT:RID:LMhash:NTLMhash:::password
john@CORP.INT:1001:aad3b435b51404eeaad3b435b51404ee:8846F7EAE...:::Password123
```

**Generate proper format:**
```bash
# Cracked passwords
hashcat -m 1000 --show --username --potfile-path audit.pot hashes.txt > cracked.txt

# Uncracked hashes
hashcat -m 1000 --left --username --potfile-path audit.pot hashes.txt > uncracked.txt
```

### Username Format Error

**Error:**
```
Warning: Username 'DOMAIN\user' not in expected format
```

**Cause**: Wrong username format for BloodHound

**Solution:**
Usernames must be in UPN format:
- ✅ Correct: `user@DOMAIN.INT`
- ❌ Wrong: `DOMAIN\user`
- ❌ Wrong: `user`

**Convert format:**
```bash
# Use ntdsutil or PowerShell to export in UPN format
```

### Empty File

**Error:**
```
ValueError: No accounts found in file
```

**Cause**: File is empty or improperly formatted

**Solution:**
```bash
# Check file has content
wc -l domain_cracked.txt

# Check first few lines
head -5 domain_cracked.txt
```

## Performance Issues

### Slow Processing

**Symptom**: Processing takes >10 minutes per 1000 accounts

**Diagnosis:**
```bash
# Check what's slow:
# 1. BloodHound queries (network latency)
# 2. HIBP lookups (disk I/O)
# 3. Complexity analysis (CPU)
```

**Solutions:**

**For BloodHound:**
- Increase network bandwidth
- Use local BloodHound instance
- Reduce controllables_limit

**For HIBP:**
- Increase cache_size
- Use SSD instead of HDD
- Disable HIBP if not needed: `"enable_lookup": false`

**For CPU:**
- Close other applications
- Use faster CPU
- Enable parallel processing (automatic with animation disabled)

### High Memory Usage

**Symptom**: Process uses >4GB RAM

**Causes:**
- Large HIBP cache
- Many accounts (>50,000)
- Large visualizations

**Solutions:**
```json
// Reduce HIBP cache
{
  "cache_size": 500000  // Instead of 1000000
}
```

```bash
# Monitor memory
top -p $(pgrep -f main.py)
```

### Parallel Processing Not Working

**Symptom**: Only one domain processes at a time

**Cause**: Animation enabled (limits workers to 4)

**Solution:**
```json
// Disable animation for max parallelism
{
  "ui": {
    "enable_animation": false
  }
}
```

## Report Generation

### Reports Not Created

**Error:**
```
ERROR: Failed to generate reports
```

**Diagnosis:**
```bash
# Check permissions
ls -ld reports/

# Check disk space
df -h reports/
```

**Solution:**
```bash
# Create reports directory
mkdir -p reports

# Fix permissions
chmod 755 reports
```

### HTML Report Blank

**Symptom**: HTML opens but shows no data

**Cause**: JavaScript error or missing password_data.json

**Diagnosis:**
```bash
# Check browser console (F12) for errors
# Check file exists
ls -l reports/latest/html/password_data.json
```

**Solution:**
```bash
# Regenerate reports
python main.py -d "DOMAIN:cracked.txt:uncracked.txt"

# Check JSON is valid
python3 -m json.tool reports/latest/html/password_data.json
```

### PDF Generation Fails

**Error:**
```
FileNotFoundError: pandoc not found
```

**Cause**: Pandoc not installed (required for Markdown → PDF)

**Solution:**
```bash
# Install pandoc
sudo apt install pandoc  # Debian/Ubuntu
brew install pandoc      # macOS

# Generate PDFs
python main.py --pdf
```

### Excel File Corrupted

**Error:**
```
Excel reports "file is corrupted"
```

**Cause**: Typically incomplete write or disk full

**Solution:**
```bash
# Check disk space
df -h .

# Regenerate
python main.py -d "DOMAIN:cracked.txt:uncracked.txt"
```

## Frequently Asked Questions

### Q: Can I run without BloodHound?

**A:** Yes! BloodHound is optional. Without it:
- No DA pathway detection
- No controlled object counts
- No account properties (enabled, last logon)
- Scoring still works based on passwords alone

Create minimal config:
```json
{
  "domain": "127.0.0.1",
  "port": 8080,
  "scheme": "http",
  "token_id": "dummy",
  "token_key": "dummy"
}
```

### Q: Can I run without HIBP?

**A:** Yes! Disable in config:
```json
{
  "enable_lookup": false
}
```

Without HIBP:
- No breach count data
- HIBP tier scoring disabled
- Still gets pattern/complexity scoring

### Q: How do I speed up analysis?

**A:**
1. Disable animation: `"enable_animation": false`
2. Increase HIBP cache: `"cache_size": 10000000`
3. Use SSD for HIBP database
4. Use local BloodHound instance
5. Disable HIBP if not needed

### Q: Can I analyze multiple domains at once?

**A:** Yes!
```bash
python main.py \
  -d "DOMAIN1:d1_cracked.txt:d1_uncracked.txt" \
     "DOMAIN2:d2_cracked.txt:d2_uncracked.txt" \
     "DOMAIN3:d3_cracked.txt:d3_uncracked.txt"
```

Domains are processed in parallel.

### Q: Where are reports saved?

**A:**
```
reports/
├── DOMAIN1-DOMAIN2-2025-10-21-143022/  # Timestamped
└── latest/  # Symlink to most recent
```

### Q: How do I view old reports?

**A:**
```bash
# Start server
python main.py -s

# Select report from menu
```

Or open HTML directly:
```bash
firefox reports/DOMAIN-2025-10-21-143022/html/main.html
```

### Q: Can I run in Docker?

**A:** Not officially supported yet, but possible:
- Mount config/ directory
- Mount reports/ output directory
- Ensure network access to BloodHound
- Mount HIBP database

### Q: How do I update word lists?

**A:** Edit files in `lists/`:
```bash
lists/
├── forbidden_words.txt      # Company names, banned terms
├── keyboard_patterns.txt    # Common patterns
├── common_passwords.txt     # Weak passwords
└── dictionary_words.txt     # English dictionary
```

Add one entry per line. Restart not required.

### Q: Can I export data to SIEM?

**A:** Yes! Use JSON or CSV exports:
```bash
# JSON format
reports/latest/csv/DOMAIN_detailed_report.json

# CSV format
reports/latest/csv/DOMAIN_report.csv
```

Parse with your SIEM connector.

### Q: How do I handle Unicode passwords?

**A:** Fully supported! The tool handles:
- UTF-8 encoded passwords
- Non-ASCII characters
- Emojis

Ensure input files are UTF-8 encoded.

### Q: What if hashcat is still cracking?

**A:** You can run analysis with partial results:
- Use current cracked.txt
- Use current uncracked.txt
- Re-run analysis after more cracks

Reports will update with new data.

## Getting More Help

### Check Logs

```bash
# View latest log file
ls -lt output/audit_*.log | head -1

# Follow log in real-time
tail -f output/audit_*.log
```

### Enable Debug Logging

Edit `utils/logging.py` to set DEBUG level for console:
```python
console_handler.setLevel(logging.DEBUG)  # Instead of ERROR
```

### Report an Issue

When reporting issues, include:
1. Python version: `python3 --version`
2. OS version: `uname -a` or `systeminfo`
3. Error message (full traceback)
4. Configuration files (redact secrets!)
5. Log file excerpt
6. Steps to reproduce

**GitHub Issues**: https://github.com/your-repo/issues

## Related Documentation

- [Installation Guide](INSTALLATION.md) - Setup instructions
- [Configuration Guide](CONFIGURATION.md) - Config reference
- [User Guide](USER_GUIDE.md) - Usage documentation
- [Integration Guide](INTEGRATIONS.md) - External tools

---

**Still stuck?** Check the FAQ above or open an issue with full details.
