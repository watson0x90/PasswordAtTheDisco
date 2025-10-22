# Password!AtTheDisco Risk Scoring System

## Executive Summary

Password!AtTheDisco implements a **CVSS-style three-component risk scoring system** (0-10 scale) that evaluates password security through multiple lenses:

1. **Base Score** (0-10): Intrinsic password qualities (complexity, length, exposure)
2. **Temporal Score** (0-10): Time-based factors (compliance, expiration)
3. **Environmental Score** (0-10): Organizational context (privileges, sharing, breach exposure)

**Key Innovation**: The system uses **evidence-based thresholds** derived from analyzing **1.3 billion NTLM password hashes** from the Have I Been Pwned (HIBP) database, ensuring risk assessments reflect real-world password exposure.

**Critical Principle**: Any cracked password represents inherent risk, regardless of apparent complexity. A 20-character random password that was successfully cracked indicates a compromise that must be addressed.

---

## Architecture Overview

### Three-Component Model

The scoring system follows a hierarchical calculation flow:

```
Base Score (0-10)
    ↓
Temporal Score = Base × Compliance Factor × Expiration Factor
    ↓
Environmental Score = Temporal × Privilege × Sharing × Domain × HIBP Multiplier
    ↓
Final Risk Score (0-10) → Risk Level (Low/Medium/High/Critical)
```

**Implementation**: `core/scoring.py`

### Risk Level Classification

| Score Range | Risk Level | Automatic Escalation |
|-------------|-----------|---------------------|
| 0.0 - 3.9 | Low | - |
| 4.0 - 5.9 | Medium | - |
| 6.0 - 7.9 | High | - |
| 8.0 - 10.0 | Critical | Any account with DA pathway → Critical |

---

## Base Score Component (0-10)

The base score evaluates intrinsic password qualities using **five factors** combined into a single metric.

### Formula

```python
combined_factor = (complexity_factor × length_factor) + dictionary_factor + similarity_factor
base_score = combined_factor × (10.0 / 4.0)
```

**Code Reference**: `core/scoring.py:9-77` (`calculate_base_score()`)

### Factor 1: Complexity Factor (0.2 - 1.0)

Evaluates character set diversity. **Lower values = stronger passwords.**

| Complexity Label | Factor | Description |
|-----------------|--------|-------------|
| `mixedalphaspecialnum` | 0.2 | Best: uppercase, lowercase, numbers, special |
| `mixedalphaspecial` | 0.3 | Mixed case + special |
| `upperalphaspecialnum` | 0.4 | Uppercase + special + numbers |
| `loweralphaspecialnum` | 0.5 | Lowercase + special + numbers |
| `mixedalphanum` | 0.6 | Mixed case + numbers |
| `specialnum` | 0.7 | Special + numbers only |
| `mixedalpha` | 0.7 | Mixed case letters only |
| `upperalphaspecial` | 0.7 | Uppercase + special |
| `loweralphaspecial` | 0.8 | Lowercase + special |
| `upperalphanum` | 0.8 | Uppercase + numbers |
| `loweralphanum` | 0.9 | Lowercase + numbers |
| `special` | 0.9 | Special characters only |
| `upperalpha` | 0.95 | Uppercase only |
| `loweralpha` | 0.95 | Lowercase only |
| `numeric` | 1.0 | Worst: numbers only |
| `none` | 1.0 | No detectable pattern |

### Factor 2: Length Factor (Sigmoid Function)

Uses sigmoid curve to smoothly scale password length contribution.

**Formula**:
```python
length_factor = 1.0 / (1.0 + exp((password_length - 10) / 2))
```

**Examples**:
- 6 chars → 0.88
- 8 chars → 0.73
- 10 chars → 0.50 (inflection point)
- 12 chars → 0.27
- 16 chars → 0.05
- 20 chars → 0.006

**Lower values = longer passwords = better.**

### Factor 3: Dictionary Factor (0.0 - 1.0+)

Aggregates multiple pattern-based weaknesses.

**Formula**:
```python
dictionary_factor = min(1.0,
    (0.7 if is_common else 0) +
    (0.5 if is_dictionary_word else 0) +
    (min(0.8, 0.2 × banned_words_count)) +
    (min(0.5, 0.1 × keyboard_patterns_count))
)
```

**Components**:
- **Common password** (+0.7): Found in `lists/common_passwords.txt`
- **Dictionary word** (+0.5): Exact match in `lists/dictionary_words.txt`
- **Banned words** (up to +0.8): Company names, forbidden terms (`lists/forbidden_words.txt`)
- **Keyboard patterns** (up to +0.5): Sequential keys (`lists/keyboard_patterns.txt`)

### Factor 4: Similarity Factor (0.0 - 0.6)

Evaluates reuse and variation of existing passwords.

| Max Similarity | Factor | Description |
|---------------|--------|-------------|
| < 70% | 0.0 | Unique password |
| 70-79% | 0.2 | Moderately similar |
| 80-89% | 0.4 | Highly similar |
| ≥ 90% | 0.6 | Nearly identical |

**Detection**: Compares against all other passwords in domain using sequence matching algorithms.

### Factor 5: HIBP-Based Minimum Tiers

**Critical Innovation**: Any cracked password receives a **minimum base score** regardless of calculated factors, ensuring strong passwords that were compromised still reflect risk.

#### Evidence-Based Tier System

Thresholds derived from analyzing **1,306,757,568 NTLM hashes** in the HIBP database.

| Tier | HIBP Count | Min Base Score | Percentile | Hash Count | Description |
|------|-----------|---------------|-----------|------------|-------------|
| **1** | ≥ 1,000,000 | **8.0** | Top 0.00001% | 123 hashes | Ultra-extreme exposure (blank password, "123456") |
| **2** | ≥ 100,000 | **7.5** | Top 0.0003% | ~3,257 hashes | Extreme exposure (nearly every breach) |
| **3** | ≥ 10,000<br>OR is_common | **7.0** | Top 0.01% | ~128K hashes | Very high exposure OR common wordlist |
| **4** | ≥ 1,000<br>OR is_dictionary | **6.0** | Top 0.24% | ~3.2M hashes | High exposure OR exact dictionary word |
| **5** | ≥ 100 | **5.0** | Top 3% | ~39M hashes | Medium-high exposure |
| **6** | ≥ 10<br>OR patterns | **4.0** | Top 20% | ~229M hashes | Medium exposure OR identifiable patterns |
| **7** | ≥ 1<br>OR len < 12 | **3.0** | Top 45% | ~580M hashes | Any HIBP presence OR below NIST length |
| **8** | Cracked (else) | **2.0** | - | - | Difficult offline crack (strong but still cracked) |

**HIBP Database Stats** (analyzed 2025-10-20):
- Total hashes: 1,306,757,568
- Maximum occurrences: 132,211,338 (blank password)
- Distribution: Heavily logarithmic (top 123 hashes account for 1M+ occurrences each)

**Code Reference**: `core/scoring.py:230-274`

**Application**:
```python
# Calculate base score from factors
base_score = combined_factor × (10.0/4.0)

# Apply HIBP tier floor
if hibp_breach_count >= 1000000:
    base_score = max(base_score, 8.0)
elif hibp_breach_count >= 100000:
    base_score = max(base_score, 7.5)
# ... (continues through all tiers)
```

**Example**: A 20-character random password (`mixedalphaspecialnum`) might calculate to base score 0.003, but if it was cracked (even offline), Tier 8 ensures it gets **minimum 2.0**.

---

## Temporal Score Component (0-10)

Applies time-based risk modifiers to the base score.

### Formula

```python
temporal_score = base_score × compliance_factor × expiration_factor
```

**Code Reference**: `core/scoring.py:80-109` (`calculate_temporal_score()`)

### Compliance Factor (0.6 - 1.0)

Measures password age against organizational policy.

**Formula**:
```python
compliance_factor = min(1.0, 0.6 + (0.4 × min(1.0, days_out_of_compliance / 180.0)))
```

**Examples**:
- 0 days overdue → 0.60 (compliant)
- 90 days overdue → 0.80
- 180+ days overdue → 1.00 (maximum risk)
- Unknown → 0.80 (middle risk assumption)

### Expiration Factor (0.85 - 1.0)

Evaluates password expiration policy.

| Password Set to Expire | Factor |
|------------------------|--------|
| Yes (expires) | 0.85 |
| No (never expires) | 1.00 |
| Unknown | 0.925 |

**Rationale**: Non-expiring passwords accumulate risk over time as attack methods evolve.

---

## Environmental Score Component (0-10)

Applies organizational context multipliers to temporal score, representing **real-world impact** of compromise.

### Formula

```python
environmental_score = temporal_score × privilege_factor × share_factor × domain_factor × hibp_factor
```

**Code Reference**: `core/scoring.py:112-191` (`calculate_environmental_score()`)

### Privilege Factor (1.0 - 1.8)

Aggregates account privilege based on Active Directory control.

**Base Privilege**:
- Has Domain Admin pathway: **+0.5**

**Controlled Object Count** (additive):
| Object Count | Additional Factor |
|-------------|------------------|
| > 1,000 | +0.5 (extreme control) |
| 501 - 1,000 | +0.4 (very high control) |
| 101 - 500 | +0.3 (high control) |
| 51 - 100 | +0.2 (medium-high control) |
| 11 - 50 | +0.1 (medium control) |
| ≤ 10 | +0.0 |

**Example**: DA account controlling 1,200 objects → 1.0 + 0.5 (DA) + 0.5 (extreme) = **2.0** privilege factor

**Data Source**: BloodHound Enterprise API queries (`core/bloodhound_integration.py`)

### Share Factor (1.0 - 1.5)

Logarithmic scale for password reuse across accounts.

| Accounts Sharing Password | Factor | Level |
|---------------------------|--------|-------|
| 0 (unique) | 1.0 | No sharing |
| 1-9 | 1.2 | S:1 - Low sharing |
| 10-99 | 1.3 | S:2 - High sharing |
| 100-999 | 1.4 | S:3 - Critical sharing |
| ≥ 1,000 | 1.5 | S:4 - Extreme sharing |

**Rationale**: Single credential compromise affects all accounts using that password.

### Domain Factor (1.0 - 1.3)

Domain-wide risk assessment multiplier.

| Domain Risk Level | Factor |
|------------------|--------|
| Low | 1.0 |
| Medium | 1.1 |
| High | 1.2 |
| Critical | 1.3 |
| Unknown | 1.0 |

**Use Case**: Enables weighting based on domain business criticality (e.g., production vs. test environments).

### HIBP Factor (1.0 - 1.5)

**Second HIBP impact**: Environmental multiplier for breach exposure.

| HIBP Breach Count | Factor |
|------------------|--------|
| 0 (not breached) | 1.0 |
| 1-99 | 1.1 (rare breach) |
| 100-999 | 1.2 (moderately common) |
| 1,000-9,999 | 1.3 (common) |
| 10,000-99,999 | 1.4 (very common) |
| ≥ 100,000 | 1.5 (extremely common) |

**Why Dual HIBP Impact?**
1. **Base Score Tier**: Establishes floor based on password vulnerability
2. **Environmental Factor**: Amplifies risk based on exposure prevalence

**Example**: Password with 500K HIBP occurrences gets:
- Base tier floor: 7.5 (Tier 2)
- Environmental multiplier: ×1.5 (extremely common)

---

## Risk Vector System

Compact machine-readable representation of all risk factors.

### Format

```
C:C5/L:M/D:CO+BW/SM:N/CM:H/EX:N/DA:Y/CO:VH/S:2/DR:H/HIBP:E
```

### Component Breakdown

| Component | Values | Description |
|-----------|--------|-------------|
| **C** | C0-C9 | Complexity level (0=worst, 9=best) |
| **L** | L/M/H | Length (Low/Medium/High) |
| **D** | CO/DW/BW/KP | Dictionary matches (Common/Dictionary Word/Banned/Keyboard) |
| **SM** | N/L/M/H | Similarity (None/Low/Med/High) |
| **CM** | L/M/H/U | Compliance (Low/Med/High/Unknown) |
| **EX** | Y/N/U | Expires (Yes/No/Unknown) |
| **DA** | Y/N | Domain Admin pathway |
| **CO** | N/L/M/H/VH/E | Controlled objects (None/Low/Med/High/Very High/Extreme) |
| **S** | 0-4 | Share level |
| **DR** | L/M/H/C/U | Domain risk |
| **HIBP** | N/L/M/H/VH/E/C | HIBP exposure level |

### HIBP Component Values

| Value | HIBP Count Range | Description |
|-------|-----------------|-------------|
| **N** | 0 | Not breached |
| **L** | 1-9 | Low (rare) |
| **M** | 10-99 | Medium |
| **H** | 100-999 | High |
| **VH** | 1,000-9,999 | Very High |
| **E** | 10,000-99,999 | Extreme |
| **C** | ≥ 100,000 | Critical |

**Code Reference**: `core/vector.py`

---

## Practical Examples

### Example 1: Critical Domain Admin Account

**Scenario**: Domain admin with blank password

**Account Details**:
- Username: `admin@CORP.COM`
- Password: `""` (blank)
- Complexity: `none`
- Length: 0 characters
- HIBP Count: 132,211,338 (most common in HIBP)
- DA Pathway: Yes
- Controlled Objects: 15,432
- Shared With: 0
- Days Out of Compliance: 730

**Calculation**:

**Base Score**:
- Complexity factor: 1.0 (none)
- Length factor: 1.0 (length 0)
- Dictionary factor: 0.7 (common password)
- Similarity factor: 0.0
- Combined: (1.0 × 1.0) + 0.7 + 0.0 = 1.7
- Calculated base: 1.7 × 2.5 = 4.25
- **HIBP Tier 1 floor**: max(4.25, **8.0**) = **8.0**

**Temporal Score**:
- Compliance factor: 1.0 (730 days / 180 = 4.0, capped at 1.0)
- Expiration factor: 1.0 (never expires)
- Temporal: 8.0 × 1.0 × 1.0 = **8.0**

**Environmental Score**:
- Privilege factor: 1.0 + 0.5 (DA) + 0.5 (>1000 objects) = 2.0
- Share factor: 1.0 (unique)
- Domain factor: 1.0
- HIBP factor: 1.5 (≥100K occurrences)
- Environmental: 8.0 × 2.0 × 1.0 × 1.0 × 1.5 = **24.0** → capped at **10.0**

**Final Score**: **10.0 / 10** - **Critical**

**Risk Vector**: `C:C0/L:L/D:CO/SM:N/CM:H/EX:N/DA:Y/CO:E/S:0/DR:U/HIBP:C`

---

### Example 2: Strong Password, High Privilege Account

**Scenario**: Strong random password on privileged account

**Account Details**:
- Username: `JD@PHANTOM.CORP`
- Password: `kF8#mN2$pL9@qR5!tX7^`
- Complexity: `mixedalphaspecialnum`
- Length: 20 characters
- HIBP Count: 0 (not in breaches)
- DA Pathway: Yes
- Controlled Objects: 709
- Shared With: 0
- Days Out of Compliance: 0

**Calculation**:

**Base Score**:
- Complexity factor: 0.2 (best)
- Length factor: 0.006 (sigmoid of 20)
- Dictionary factor: 0.0
- Similarity factor: 0.0
- Combined: (0.2 × 0.006) + 0.0 + 0.0 = 0.0012
- Calculated base: 0.0012 × 2.5 = 0.003 → rounds to 0.0
- **Tier 8 floor** (cracked password): max(0.003, **2.0**) = **2.0**

**Temporal Score**:
- Compliance factor: 0.6 (0 days overdue)
- Expiration factor: 0.85 (set to expire)
- Temporal: 2.0 × 0.6 × 0.85 = **1.02**

**Environmental Score**:
- Privilege factor: 1.0 + 0.5 (DA) + 0.5 (>500 objects) = 2.0
- Share factor: 1.0 (unique)
- Domain factor: 1.0
- HIBP factor: 1.0 (not breached)
- Environmental: 1.02 × 2.0 × 1.0 × 1.0 × 1.0 = **2.04**

**Final Score**: **2.0 / 10** - **Critical** (DA pathway auto-escalates)

**Risk Vector**: `C:C8/L:H/D:N/SM:N/CM:L/EX:Y/DA:Y/CO:VH/S:0/DR:U/HIBP:N`

**Key Insight**: Despite low calculated risk, the password was successfully cracked (offline attack), indicating compromise. DA pathway ensures Critical classification.

---

### Example 3: Common Password, Widely Shared

**Scenario**: Shared service account with common password

**Account Details**:
- Username: `svc_backup@CORP.COM`
- Password: `Password123`
- Complexity: `mixedalphanum`
- Length: 11 characters
- HIBP Count: 503,189
- DA Pathway: No
- Controlled Objects: 5
- Shared With: 47 accounts
- Days Out of Compliance: 365

**Calculation**:

**Base Score**:
- Complexity factor: 0.6
- Length factor: 0.37 (sigmoid of 11)
- Dictionary factor: 0.7 (common password)
- Similarity factor: 0.0
- Combined: (0.6 × 0.37) + 0.7 + 0.0 = 0.922
- Calculated base: 0.922 × 2.5 = 2.305
- **HIBP Tier 2 floor**: max(2.305, **7.5**) = **7.5**

**Temporal Score**:
- Compliance factor: 1.0 (365/180 = 2.0, capped)
- Expiration factor: 1.0 (never expires)
- Temporal: 7.5 × 1.0 × 1.0 = **7.5**

**Environmental Score**:
- Privilege factor: 1.0 (no DA, <10 objects)
- Share factor: 1.3 (10-99 shared accounts)
- Domain factor: 1.0
- HIBP factor: 1.5 (≥100K occurrences)
- Environmental: 7.5 × 1.0 × 1.3 × 1.0 × 1.5 = **14.625** → capped at **10.0**

**Final Score**: **10.0 / 10** - **Critical**

**Risk Vector**: `C:C5/L:M/D:CO/SM:N/CM:H/EX:N/DA:N/CO:L/S:2/DR:U/HIBP:C`

**Key Insight**: Extreme HIBP exposure (500K+ occurrences) combined with wide sharing creates maximum risk.

---

### Example 4: Dictionary Word, Medium Privilege

**Scenario**: Standard user with dictionary password

**Account Details**:
- Username: `alice@CORP.COM`
- Password: `elephant`
- Complexity: `loweralpha`
- Length: 8 characters
- HIBP Count: 12,847
- DA Pathway: No
- Controlled Objects: 0
- Shared With: 2
- Days Out of Compliance: 45

**Calculation**:

**Base Score**:
- Complexity factor: 0.95
- Length factor: 0.73 (sigmoid of 8)
- Dictionary factor: 0.5 (exact dictionary word)
- Similarity factor: 0.0
- Combined: (0.95 × 0.73) + 0.5 + 0.0 = 1.1935
- Calculated base: 1.1935 × 2.5 = 2.98
- **HIBP Tier 3 floor**: max(2.98, **7.0**) = **7.0**

**Temporal Score**:
- Compliance factor: 0.70 (45/180 = 0.25 → 0.6 + 0.1 = 0.70)
- Expiration factor: 0.85 (set to expire)
- Temporal: 7.0 × 0.70 × 0.85 = **4.165**

**Environmental Score**:
- Privilege factor: 1.0
- Share factor: 1.2 (1-9 shared)
- Domain factor: 1.0
- HIBP factor: 1.4 (10K-99K occurrences)
- Environmental: 4.165 × 1.0 × 1.2 × 1.0 × 1.4 = **7.00**

**Final Score**: **7.0 / 10** - **High**

**Risk Vector**: `C:C2/L:L/D:DW/SM:N/CM:M/EX:Y/DA:N/CO:N/S:1/DR:U/HIBP:E`

---

### Example 5: Keyboard Pattern Password

**Scenario**: User with keyboard walking pattern

**Account Details**:
- Username: `bob@CORP.COM`
- Password: `qwerty123!`
- Complexity: `loweralphaspecialnum`
- Length: 10 characters
- HIBP Count: 87,234
- DA Pathway: No
- Controlled Objects: 3
- Shared With: 0
- Days Out of Compliance: 0

**Calculation**:

**Base Score**:
- Complexity factor: 0.5
- Length factor: 0.50 (sigmoid of 10, inflection point)
- Dictionary factor: 0.1 (1 keyboard pattern detected)
- Similarity factor: 0.0
- Combined: (0.5 × 0.50) + 0.1 + 0.0 = 0.35
- Calculated base: 0.35 × 2.5 = 0.875
- **HIBP Tier 2 floor**: max(0.875, **7.5**) = **7.5**

**Temporal Score**:
- Compliance factor: 0.6 (compliant)
- Expiration factor: 0.85 (expires)
- Temporal: 7.5 × 0.6 × 0.85 = **3.825**

**Environmental Score**:
- Privilege factor: 1.0
- Share factor: 1.0
- Domain factor: 1.0
- HIBP factor: 1.4 (10K-99K)
- Environmental: 3.825 × 1.0 × 1.0 × 1.0 × 1.4 = **5.355**

**Final Score**: **5.4 / 10** - **Medium**

**Risk Vector**: `C:C4/L:M/D:KP/SM:N/CM:L/EX:Y/DA:N/CO:L/S:0/DR:U/HIBP:E`

---

### Example 6: Long Passphrase, Low Exposure

**Scenario**: User with long passphrase, minimal HIBP presence

**Account Details**:
- Username: `charlie@CORP.COM`
- Password: `correct horse battery staple monkey`
- Complexity: `loweralpha`
- Length: 35 characters
- HIBP Count: 7 (low exposure)
- DA Pathway: No
- Controlled Objects: 0
- Shared With: 0
- Days Out of Compliance: 120

**Calculation**:

**Base Score**:
- Complexity factor: 0.95 (lowercase only)
- Length factor: 0.00001 (sigmoid of 35, very low)
- Dictionary factor: 0.0 (not flagged as common, despite being famous passphrase)
- Similarity factor: 0.0
- Combined: (0.95 × 0.00001) + 0.0 + 0.0 = 0.0000095
- Calculated base: 0.0000095 × 2.5 ≈ 0.0
- **Tier 7 floor** (HIBP ≥ 1): max(0.0, **3.0**) = **3.0**

**Temporal Score**:
- Compliance factor: 0.867 (120/180 = 0.667 → 0.6 + 0.267)
- Expiration factor: 0.85 (expires)
- Temporal: 3.0 × 0.867 × 0.85 = **2.21**

**Environmental Score**:
- Privilege factor: 1.0
- Share factor: 1.0
- Domain factor: 1.0
- HIBP factor: 1.1 (1-99 occurrences, rare)
- Environmental: 2.21 × 1.0 × 1.0 × 1.0 × 1.1 = **2.43**

**Final Score**: **2.4 / 10** - **Low**

**Risk Vector**: `C:C2/L:H/D:N/SM:N/CM:M/EX:Y/DA:N/CO:N/S:0/DR:U/HIBP:L`

**Key Insight**: Long passphrase gets low risk due to minimal HIBP exposure and no privilege escalation, despite low complexity.

---

### Example 7: Banned Word Password, No HIBP Match

**Scenario**: Password containing company name, not yet in HIBP

**Account Details**:
- Username: `dave@ACME.COM`
- Password: `Acme2024!`
- Complexity: `mixedalphaspecialnum`
- Length: 9 characters
- HIBP Count: 0 (not breached)
- DA Pathway: No
- Controlled Objects: 0
- Shared With: 0
- Days Out of Compliance: 0
- Banned Words: 1 ("Acme")

**Calculation**:

**Base Score**:
- Complexity factor: 0.2 (best complexity)
- Length factor: 0.62 (sigmoid of 9)
- Dictionary factor: 0.2 (1 banned word: 0.2 × 1)
- Similarity factor: 0.0
- Combined: (0.2 × 0.62) + 0.2 + 0.0 = 0.324
- Calculated base: 0.324 × 2.5 = 0.81
- **Tier 8 floor** (cracked): max(0.81, **2.0**) = **2.0**

**Temporal Score**:
- Compliance factor: 0.6 (compliant)
- Expiration factor: 0.85 (expires)
- Temporal: 2.0 × 0.6 × 0.85 = **1.02**

**Environmental Score**:
- Privilege factor: 1.0
- Share factor: 1.0
- Domain factor: 1.0
- HIBP factor: 1.0 (not breached)
- Environmental: 1.02 × 1.0 × 1.0 × 1.0 × 1.0 = **1.02**

**Final Score**: **1.0 / 10** - **Low**

**Risk Vector**: `C:C8/L:L/D:BW/SM:N/CM:L/EX:Y/DA:N/CO:N/S:0/DR:U/HIBP:N`

**Key Insight**: Despite containing company name, lack of HIBP exposure and no privileges keeps risk low. However, predictability remains a concern.

---

## Developer Reference

### Integration Points

**Domain Analysis** (`core/domain_analysis.py`):
```python
# Lines 258-262: Main scoring call
score, score_breakdown, has_da_path = calculate_password_risk_score(
    analysis_result, shared_with, da_domains, controlled_object_count,
    similar_passwords, hibp_breach_count=breach_count
)
```

**HIBP Lookup** (`core/hibp_correlation.py`):
```python
# Check hash against HIBP
checker = HIBPChecker()
is_breached, breach_count = checker.check_ntlm_hash(ntlm_hash)
```

**BloodHound Data** (`core/bloodhound_integration.py`):
```python
# Fetch privilege data
account_data = client.get_account_info(username, domain)
da_domains = account_data.get('da_domains', [])
controlled_objects = account_data.get('controlled_object_count', 0)
```

### Output Fields

All reports include these scoring-related fields:

| Field | Type | Description |
|-------|------|-------------|
| `Score` | float | Final risk score (0-10) |
| `Risk Level` | str | Low/Medium/High/Critical |
| `Risk Vector` | str | Compact risk representation |
| `Score Breakdown` | dict | Base/temporal/environmental components |
| `HIBP Breached` | bool | Hash found in HIBP |
| `HIBP Breach Count` | int | Occurrence count |
| `HIBP Risk Level` | str | HIBP-specific risk category |

---

## Formulas Quick Reference

### Base Score
```
combined_factor = (complexity_factor × length_factor) + dictionary_factor + similarity_factor
base_score_raw = combined_factor × 2.5
base_score = max(base_score_raw, hibp_tier_floor)  # 8-tier system
base_score = min(base_score, 10.0)
```

### Temporal Score
```
compliance_factor = min(1.0, 0.6 + (0.4 × min(1.0, days_overdue / 180)))
expiration_factor = 1.0 if never_expires else 0.85
temporal_score = base_score × compliance_factor × expiration_factor
```

### Environmental Score
```
privilege_factor = 1.0 + DA_bonus + object_count_bonus  # range: 1.0-1.8
share_factor = 1.0 + share_level_bonus                  # range: 1.0-1.5
domain_factor = domain_risk_multiplier                  # range: 1.0-1.3
hibp_factor = hibp_multiplier                           # range: 1.0-1.5

environmental_score = temporal_score × privilege_factor × share_factor × domain_factor × hibp_factor
environmental_score = min(environmental_score, 10.0)
```

### Length Factor (Sigmoid)
```
length_factor = 1.0 / (1.0 + e^((password_length - 10) / 2))
```

### Risk Level
```
if has_da_path:
    return "Critical"
elif score >= 8.0:
    return "Critical"
elif score >= 6.0:
    return "High"
elif score >= 4.0:
    return "Medium"
else:
    return "Low"
```

---

## Appendix: HIBP Distribution Analysis

**Analysis Date**: 2025-10-20
**File**: `PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt`
**Method**: Full file scan using awk stream processing

### Raw Statistics

```
Total NTLM Hashes: 1,306,757,568
Maximum Occurrences: 132,211,338 (blank password)
File Size: 42.88 GB
```

### Distribution by Occurrence Count

| Occurrence Range | Hash Count | Percentage | Cumulative % |
|-----------------|-----------|------------|--------------|
| 1-9 | 580,185,947 | 44.4% | 44.4% |
| 10-99 | 497,334,299 | 38.1% | 82.5% |
| 100-999 | 190,082,456 | 14.5% | 97.0% |
| 1,000-9,999 | 35,896,709 | 2.7% | 99.7% |
| 10,000-99,999 | 3,129,233 | 0.24% | 99.96% |
| 100,000-999,999 | 128,801 | 0.01% | 99.97% |
| 1,000,000+ | 123 | 0.00001% | 100.0% |

### Tier Threshold Justification

| Tier | Threshold | Percentile | Rationale |
|------|-----------|-----------|-----------|
| 1 | 1M+ | Top 0.00001% | Only 123 passwords worldwide - the absolute most common |
| 2 | 100K+ | Top 0.0003% | Found in nearly every breach dataset |
| 3 | 10K+ | Top 0.01% | Standard "common password" lists |
| 4 | 1K+ | Top 0.24% | High-frequency breach presence |
| 5 | 100+ | Top 3% | Moderate breach exposure |
| 6 | 10+ | Top 20% | Some breach presence |
| 7 | 1+ | Top 45% | Any HIBP match indicates exposure |
| 8 | 0 | - | Not in HIBP but still cracked |

**Key Insight**: The distribution is **heavily logarithmic**. The top 0.00001% (123 hashes) account for massive occurrence volumes, while 44% of hashes appear fewer than 10 times. This justifies logarithmic tier boundaries.

---

## Conclusion

The Password!AtTheDisco scoring system provides **evidence-based, context-aware risk assessment** by:

1. **Recognizing that cracking = compromise**: All cracked passwords receive minimum risk scores
2. **Using real-world data**: 1.3B hash analysis informs HIBP tier thresholds
3. **Incorporating privilege context**: BloodHound data amplifies scores for high-value accounts
4. **Differentiating exposure levels**: Dual HIBP impact (base tier + environmental multiplier)
5. **Providing actionable prioritization**: Risk levels guide remediation efforts

**For Developers**: All scoring logic is in `core/scoring.py`. Integration points in `core/domain_analysis.py` (lines 258-262) for account processing.

**For Security Teams**: Focus remediation on:
- Critical (8.0-10.0): Immediate action required
- High (6.0-7.9): Priority remediation
- Medium (4.0-5.9): Scheduled remediation
- Low (0.0-3.9): Monitor and educate

**For Auditors**: Risk vectors provide machine-readable, reproducible risk assessment documentation.
