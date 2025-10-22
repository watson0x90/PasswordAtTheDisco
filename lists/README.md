# Word Lists and Password Policy

This directory contains word lists and password policy configurations used by Password!AtTheDisco for password analysis and risk scoring.

## Table of Contents

- [Password Policy Configuration](#password-policy-configuration)
- [Word List Files](#word-list-files)
- [Customization Guide](#customization-guide)
- [File Sources](#file-sources)

## Password Policy Configuration

### password_policy.json

This file defines password complexity requirements and age policies for your organization. The tool uses these policies to determine compliance and calculate temporal risk factors.

#### Structure

The policy file supports **multiple domain-specific policies** with a **default fallback**:

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
  "PRODUCTION.CORP.INT": {
    "policy": {
      "min_length": 16,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_password_age_days": 60
    }
  },
  "DEV.CORP.INT": {
    "policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": false,
      "max_password_age_days": 180
    }
  }
}
```

#### Policy Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `min_length` | integer | Minimum password length | 14 |
| `require_uppercase` | boolean | Require uppercase letters (A-Z) | true |
| `require_lowercase` | boolean | Require lowercase letters (a-z) | true |
| `require_digits` | boolean | Require digits (0-9) | true |
| `require_special` | boolean | Require special characters | true |
| `max_password_age_days` | integer | Maximum password age in days | 90 |

#### Single Domain Configuration

If you're auditing a single domain or want the same policy everywhere, simply use the `default` policy:

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

All domains will use this policy unless a specific domain policy is defined.

#### Multi-Domain Configuration

For organizations with multiple domains and different security requirements, define domain-specific policies:

```json
{
  "default": {
    "policy": {
      "min_length": 14,
      "max_password_age_days": 90,
      ...
    }
  },
  "PRODUCTION.CORP.INT": {
    "policy": {
      "min_length": 16,           // Stricter for production
      "max_password_age_days": 60,
      ...
    }
  },
  "DEV.CORP.INT": {
    "policy": {
      "min_length": 12,           // Relaxed for development
      "max_password_age_days": 180,
      ...
    }
  },
  "DMZ.CORP.INT": {
    "policy": {
      "min_length": 20,           // Strictest for DMZ
      "max_password_age_days": 30,
      ...
    }
  }
}
```

**How it works**:
1. Tool checks if a domain-specific policy exists (e.g., "PRODUCTION.CORP.INT")
2. If found, uses that policy for the domain
3. If not found, falls back to "default" policy

#### Customizing for Your Organization

**Step 1**: Copy your current password policy

**Step 2**: Edit `lists/password_policy.json`

**Step 3**: Add your domain(s):

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
  "YOURCOMPANY.COM": {
    "policy": {
      "min_length": 16,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_password_age_days": 60
    }
  }
}
```

**Step 4**: Run your audit - the tool automatically applies the correct policy to each domain

#### Impact on Scoring

Password policy affects the **Temporal Score** component:

- **Compliance**: Passwords meeting all requirements get lower temporal risk
- **Violations**: Each violation increases temporal risk
- **Age**: Passwords exceeding `max_password_age_days` get higher temporal risk
  - 1-30 days over: 1.1x multiplier
  - 31-90 days over: 1.2x multiplier
  - 91-180 days over: 1.3x multiplier
  - 181-365 days over: 1.4x multiplier
  - 365+ days over: 1.5x multiplier

## Word List Files

### forbidden_words.txt

**Purpose**: Contains organization-specific banned words that should NOT appear in passwords.

**Default Content**: Basic examples (company, admin, password, etc.)

**What to Add**:
- Your company name(s)
- Product names
- Office locations
- Department names
- Common internal terms
- Subsidiary names
- Brand names

**Example**:
```
# Company names
YourCompany
YourCompanyInc
CompanyName

# Products
ProductA
ProductB
MainProduct

# Locations
NewYorkOffice
LondonOffice
Headquarters

# Departments
Engineering
Marketing
Sales

# Common terms
ServiceAccount
AdminAccount
TestAccount
```

**Format**:
- One word per line
- Case-insensitive (will match "company", "Company", "COMPANY")
- Lines starting with `#` are comments
- Blank lines ignored

**Impact on Scoring**:
- Passwords containing forbidden words receive +2.0 points to base score
- Multiple forbidden words compound the penalty
- Detection is case-insensitive and matches partial words

**Customization Priority**: PPPPP **CRITICAL**
- **Update this file before your first audit**
- Add all company-specific terms
- Review quarterly and update

### common_passwords.txt

**Purpose**: List of commonly used weak passwords known to appear frequently in password audits.

**Source**: Compiled from [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- SecLists/Passwords/Common-Credentials/
- SecLists/Passwords/xato-net-10-million-passwords-1000000.txt
- Real-world breach data compilations

**Size**: ~10,000 entries

**Content Examples**:
```
password
Password1
Welcome1
Admin123
Summer2024
Winter2024
```

**Impact on Scoring**:
- Passwords in this list receive +2.0 points to base score
- Automatically flagged as "Common Password: Yes" in reports
- Combined with other factors (dictionary, HIBP) for comprehensive risk

**Customization**: Optional
- Pre-populated with industry-standard common passwords
- Can add organization-specific weak patterns if discovered
- Review after each audit for patterns to add

**Customization Priority**: PP Optional
- Default list is comprehensive
- Add organization-specific weak passwords if you discover patterns

### dictionary_words.txt

**Purpose**: English dictionary word list used to detect passwords containing common words.

**Source**: Compiled from [Project Gutenberg](https://www.gutenberg.org/)
- English word lists from public domain texts
- Supplemented with technical terms and common variations

**Size**: ~479,000 entries

**Content**: Standard English words in lowercase
```
password
computer
security
network
system
hello
world
```

**Impact on Scoring**:
- Passwords containing dictionary words receive +1.0 points to base score
- Checks for whole words and substrings
- Case-insensitive matching
- Flagged as "Dictionary Word: Yes" in reports

**How Detection Works**:
```
Password: "Hello123!"
Detection: Contains "hello" (dictionary word) � +1.0 base score

Password: "X9k#mP2$"
Detection: No dictionary words � No penalty
```

**Customization**: Generally Not Needed
- Comprehensive English dictionary pre-loaded
- Can add technical jargon or industry terms if desired

**Customization Priority**: P Rarely Needed
- Default dictionary is extensive
- Only modify if you have industry-specific terminology

### keyboard_patterns.txt

**Purpose**: Common keyboard patterns and sequences that make passwords predictable.

**Source**: Compiled from [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- SecLists/Passwords/Keyboard-Combinations.txt
- Common QWERTY keyboard walks
- Number pad patterns

**Size**: ~45 entries

**Content Examples**:
```
qwerty
asdfgh
zxcvbn
12345
1qaz2wsx
qwertyuiop
asdfghjkl
987654321
```

**Impact on Scoring**:
- Passwords containing keyboard patterns receive +1.0 points to base score
- Common sequences like "qwerty", "12345", "asdfgh" detected
- Both horizontal and vertical keyboard walks detected
- Flagged as "Keyboard Pattern: Yes" in reports

**How Detection Works**:
```
Password: "qwerty123"
Detection: Contains "qwerty" (keyboard pattern) � +1.0 base score

Password: "Welcome123"
Detection: No keyboard pattern � No penalty
```

**Customization**: Optional
- Pre-populated with common patterns
- Can add custom patterns observed in your environment

**Customization Priority**: P Rarely Needed
- Default patterns cover most common cases
- Only add if you discover organization-specific patterns

## Customization Guide

### Quick Start Customization

**Minimum Required** (before first audit):

1. **Update forbidden_words.txt**:
   ```bash
   # Add your company-specific terms
   echo "YourCompany" >> lists/forbidden_words.txt
   echo "YourProduct" >> lists/forbidden_words.txt
   echo "YourLocation" >> lists/forbidden_words.txt
   ```

2. **Update password_policy.json**:
   ```bash
   # Edit with your actual policy
   nano lists/password_policy.json
   ```

### Advanced Customization

**After First Audit** (optional improvements):

1. **Review Results**: Look for patterns in high-risk passwords

2. **Update forbidden_words.txt**: Add any company-specific terms you find

3. **Update common_passwords.txt**: Add weak patterns specific to your org
   ```bash
   # Example: If you find many users using "CompanyName + Year"
   echo "YourCompany2024" >> lists/common_passwords.txt
   echo "YourCompany2025" >> lists/common_passwords.txt
   ```

4. **Update keyboard_patterns.txt**: Add any custom patterns observed

### Testing Your Changes

After customizing word lists, test with a sample:

```bash
# Test forbidden words detection
python3 -c "
from core.password_analysis import find_forbidden_words
forbidden = set(open('lists/forbidden_words.txt').read().lower().split())
test_password = 'YourCompany2024!'
found = find_forbidden_words(test_password, forbidden)
print(f'Forbidden words found: {found}')
"
```

### Word List Maintenance

**Quarterly Review**:
1. Review high-risk passwords from recent audits
2. Look for common patterns or terms
3. Add new forbidden words as organization evolves
4. Update password policy if requirements change

**Annual Review**:
1. Remove obsolete terms (old product names, etc.)
2. Add new company acquisitions/products/locations
3. Review and update password policy for compliance

## File Sources

All word lists are compiled from publicly available sources:

### SecLists (Likely Source)
- **Source**: https://github.com/danielmiessler/SecLists
- **License**: MIT License
- **Likely Used For**:
  - `common_passwords.txt` - Common credential lists
  - `keyboard_patterns.txt` - Keyboard combinations

### Project Gutenberg (Likely Source)
- **Source**: https://www.gutenberg.org/
- **License**: Public Domain
- **Likely Used For**:
  - `dictionary_words.txt` - English word lists from public domain texts

**Note**: These word lists were compiled from various public sources. The exact sources may include SecLists, Project Gutenberg, and other publicly available password/word databases. All sources are freely available and not subject to copyright restrictions.

### Custom Organization Lists
- **forbidden_words.txt** - User-customizable organization-specific terms (provided as template)

## File Format Requirements

All text files must follow these rules:

1. **Encoding**: UTF-8
2. **Line Endings**: Unix (LF) or Windows (CRLF) - both supported
3. **Comments**: Lines starting with `#` are ignored
4. **Blank Lines**: Ignored
5. **Case Sensitivity**:
   - Word lists: Case-insensitive (converted to lowercase internally)
   - Policy JSON: Case-sensitive (use exact domain names)

## Examples

### Example 1: Single Domain with Basic Policy

```json
{
  "default": {
    "policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": false,
      "max_password_age_days": 90
    }
  }
}
```

```
# forbidden_words.txt
acme
acmecorp
headquarters
```

### Example 2: Multi-Domain with Different Policies

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
  "SECURE.ACME.COM": {
    "policy": {
      "min_length": 20,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_password_age_days": 30
    }
  },
  "INTERNAL.ACME.COM": {
    "policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": false,
      "max_password_age_days": 120
    }
  }
}
```

```
# forbidden_words.txt
acme
acmecorp
headquarters
boston
newyork
secure
internal
finance
hr
payroll
```

## Troubleshooting

### Issue: Policy Not Being Applied

**Problem**: Passwords not being marked as policy violations

**Solution**:
1. Check domain name matches exactly (case-sensitive)
   ```bash
   # Check your domain name in the data
   head domain_cracked.txt | cut -d'@' -f2 | cut -d':' -f1
   ```

2. Verify JSON syntax:
   ```bash
   python3 -m json.tool lists/password_policy.json
   ```

3. Ensure policy is under correct key:
   ```json
   {
     "YOURDOMAIN.COM": {  // � Must match exactly
       "policy": { ... }
     }
   }
   ```

### Issue: Forbidden Words Not Detected

**Problem**: Known forbidden words not being flagged

**Solution**:
1. Check file encoding (must be UTF-8):
   ```bash
   file lists/forbidden_words.txt
   # Should show: UTF-8 Unicode text
   ```

2. Verify file has content:
   ```bash
   wc -l lists/forbidden_words.txt
   ```

3. Check for hidden characters:
   ```bash
   cat -A lists/forbidden_words.txt
   ```

### Issue: Too Many False Positives

**Problem**: Too many passwords flagged for dictionary words

**Solution**:
- Dictionary detection is working as intended
- Consider that dictionary words ARE a legitimate risk factor
- Focus on high-risk accounts (Critical/High) rather than all flagged accounts

## Related Documentation

- [Configuration Guide](../docs/CONFIGURATION.md) - Overall configuration
- [Scoring System](../docs/SCORING_SYSTEM.md) - How word lists affect scoring
- [User Guide](../docs/USER_GUIDE.md) - Using the tool
- [Troubleshooting](../docs/TROUBLESHOOTING.md) - Common issues

---

**Questions?** See the [Troubleshooting Guide](../docs/TROUBLESHOOTING.md) or open an issue on GitHub.
