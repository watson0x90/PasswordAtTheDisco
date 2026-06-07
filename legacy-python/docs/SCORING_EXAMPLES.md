# Password Scoring System - Comprehensive Examples

This document provides detailed examples showing how the CVSS-style password risk scoring system works in practice. Each example walks through the complete calculation process from password characteristics to final risk level.

## Scoring System Overview

The scoring system uses three components:
1. **Base Score (0-10)**: Intrinsic password qualities (complexity, length, dictionary checks, patterns)
2. **Temporal Score (0-10)**: Time-based factors (age, expiration settings)
3. **Environmental Score (0-10)**: Organizational context (privileges, sharing, domain risk, HIBP exposure)

The final score is calculated as:
```
Base Score → Temporal Score (base × temporal_factors) → Environmental Score (temporal × environmental_factors)
```

**Risk Levels:**
- **Critical**: DA pathway OR score >= 8.0
- **High**: Score >= 6.0
- **Medium**: Score >= 4.0
- **Low**: Score < 4.0

---

## Example 1: Strong Password on DA Account

### Password Characteristics
- **Password**: `kR7#mP9@nQ2$wX5&zL8!` (20 characters)
- **Username**: `admin.backup@CORP.INT`
- **Complexity**: mixedalphaspecialnum (lowercase, uppercase, digits, special chars)
- **Dictionary/Pattern Issues**: None
- **Similar Passwords**: None
- **Password Age**: 45 days old
- **Policy Max Age**: 261 days
- **Password Expiration**: Yes (expires)

### BloodHound Data
- **DA Pathway**: Yes (has path to Domain Admin)
- **Controlled Objects**: 709 objects
- **Account Enabled**: Yes
- **Shared With**: 0 accounts (unique password)

### HIBP Data
- **Breached**: No
- **Breach Count**: 0

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `mixedalphaspecialnum` = **0.2** (best complexity)

**Length Factor:**
- Formula: `1.0 / (1.0 + e^((length - 10) / 2))`
- Length: 20 characters
- Calculation: `1.0 / (1.0 + e^((20 - 10) / 2))` = `1.0 / (1.0 + e^5)` = `1.0 / (1.0 + 148.41)` = **0.0067**

**Dictionary Factor:**
- Common password: No = 0
- Dictionary word: No = 0
- Banned words: 0 = 0
- Keyboard patterns: 0 = 0
- Total dictionary factor: **0.0**

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(complexity_factor × length_factor) + dictionary_factor + similarity_factor`
- `(0.2 × 0.0067) + 0.0 + 0.0` = **0.00134**

**Base Score:**
- `combined_factor × (10.0 / 4.0)` = `0.00134 × 2.5` = **0.00335**

**HIBP Tier Adjustment:**
- HIBP count: 0 (not breached)
- Length: 20 (>= 12 characters)
- No patterns or dictionary issues
- Falls into **Tier 8: Minimal Risk** → Base score raised to **2.0**

**Final Base Score: 2.0**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: Password is 45 days old, policy allows 261 days
- Days out: `45 - 261 = -216` (compliant)
- Since compliant (negative value), days = 0
- Formula: `min(1.0, 0.6 + (0.4 × min(1.0, days / 180.0)))`
- `min(1.0, 0.6 + (0.4 × 0))` = **0.6**

**Expiration Factor:**
- Password set to expire: Yes
- Factor: **0.85**

**Temporal Score:**
- `base_score × compliance_factor × expiration_factor`
- `2.0 × 0.6 × 0.85` = **1.02**

**Final Temporal Score: 1.02** (rounded to 1.0)

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: Yes → +0.5
- Controlled objects: 709 (> 500, <= 1000) → +0.4
- Total privilege factor: `1.0 + 0.5 + 0.4` = **1.9** (capped at 1.8)
- **Final: 1.8**

**Share Factor:**
- Shared with: 0 accounts
- Factor: **1.0**

**Domain Factor:**
- Domain risk level: Not specified (assume Unknown)
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 0
- Factor: **1.0**

**Environmental Score:**
- `temporal_score × privilege_factor × share_factor × domain_factor × hibp_factor`
- `1.02 × 1.8 × 1.0 × 1.0 × 1.0` = **1.836**

**Final Environmental Score: 1.8**

---

### Final Results

**Score Breakdown:**
```
Base Score:        2.0
  Complexity:      0.20 (mixedalphaspecialnum)
  Length:          0.01 (20 chars)
  Dictionary:      0.00 (none)
  Similarity:      0.00 (none)

Temporal Score:    1.0
  Compliance:      0.60 (compliant)
  Expiration:      0.85 (expires)

Environmental:     1.8
  Privilege:       1.80 (DA path + 709 objects)
  Share:           1.00 (unique)
  Domain:          1.00 (unknown)
  HIBP:            1.00 (not breached)
```

**Final Score: 1.8**

**Risk Level: CRITICAL** (has DA pathway - automatic Critical regardless of score)

**Risk Vector:**
```
C:C1/L:VL/D:N/SM:N/CM:N/EX:Y/DA:Y/CO:VH/S:0/DR:U/HIBP:N
```

**Vector Breakdown:**
- `C:C1` - Best complexity (mixed case, numbers, symbols)
- `L:VL` - Very long (20 characters)
- `D:N` - No dictionary issues
- `SM:N` - No similarity to other passwords
- `CM:N` - Compliant (0 days out)
- `EX:Y` - Password expires
- `DA:Y` - Has Domain Admin pathway
- `CO:VH` - Very High controlled objects (709)
- `S:0` - Not shared
- `DR:U` - Domain risk unknown
- `HIBP:N` - Not found in breaches

**Key Insight:** Despite having an extremely strong password (low intrinsic risk), this account is CRITICAL due to its DA pathway. This demonstrates how environmental factors can elevate risk even with strong passwords.

---

## Example 2: Weak Password on DA Account

### Password Characteristics
- **Password**: `Password123!` (12 characters)
- **Username**: `admin.helpdesk@CORP.INT`
- **Complexity**: mixedalphaspecialnum
- **Dictionary/Pattern Issues**: Common password, contains banned word "Password"
- **Similar Passwords**: None detected
- **Password Age**: 450 days old
- **Policy Max Age**: 261 days
- **Password Expiration**: No (never expires)

### BloodHound Data
- **DA Pathway**: Yes (has path to Domain Admin)
- **Controlled Objects**: 234 objects
- **Account Enabled**: Yes
- **Shared With**: 0 accounts

### HIBP Data
- **Breached**: Yes
- **Breach Count**: 2,456,823 (extremely common)

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `mixedalphaspecialnum` = **0.2**

**Length Factor:**
- `1.0 / (1.0 + e^((12 - 10) / 2))` = `1.0 / (1.0 + e^1)` = `1.0 / (1.0 + 2.718)` = **0.269**

**Dictionary Factor:**
- Common password: Yes = 0.7
- Dictionary word: No = 0
- Banned words: 1 ("Password") = `min(0.8, 0.2 × 1)` = 0.2
- Keyboard patterns: 0 = 0
- Total: `min(1.0, 0.7 + 0 + 0.2 + 0)` = **0.9**

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(0.2 × 0.269) + 0.9 + 0.0` = `0.0538 + 0.9` = **0.9538**

**Base Score:**
- `0.9538 × 2.5` = **2.3845**

**HIBP Tier Adjustment:**
- HIBP count: 2,456,823 (>= 1,000,000)
- Falls into **Tier 1: Ultra-extreme exposure** → Base score raised to **8.0**

**Final Base Score: 8.0**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: `450 - 261 = 189` days
- Formula: `min(1.0, 0.6 + (0.4 × min(1.0, 189 / 180.0)))`
- `min(1.0, 0.6 + (0.4 × 1.05))` = `min(1.0, 0.6 + 0.42)` = **1.0**

**Expiration Factor:**
- Password never expires: No
- Factor: **1.0**

**Temporal Score:**
- `8.0 × 1.0 × 1.0` = **8.0**

**Final Temporal Score: 8.0**

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: Yes → +0.5
- Controlled objects: 234 (> 100, <= 500) → +0.3
- Total: `1.0 + 0.5 + 0.3` = **1.8**

**Share Factor:**
- Shared with: 0 accounts
- Factor: **1.0**

**Domain Factor:**
- Domain risk level: Unknown
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 2,456,823 (>= 100,000)
- Factor: **1.5**

**Environmental Score:**
- `8.0 × 1.8 × 1.0 × 1.0 × 1.5` = **21.6** → capped at **10.0**

**Final Environmental Score: 10.0**

---

### Final Results

**Score Breakdown:**
```
Base Score:        8.0
  Complexity:      0.20 (mixedalphaspecialnum)
  Length:          0.27 (12 chars)
  Dictionary:      0.90 (common + banned word)
  Similarity:      0.00 (none)
  HIBP Tier:       Tier 1 (2.4M+ breaches)

Temporal Score:    8.0
  Compliance:      1.00 (189 days out)
  Expiration:      1.00 (never expires)

Environmental:     10.0 (capped)
  Privilege:       1.80 (DA path + 234 objects)
  Share:           1.00 (unique)
  Domain:          1.00 (unknown)
  HIBP:            1.50 (extremely common breach)
```

**Final Score: 10.0**

**Risk Level: CRITICAL** (DA pathway + maximum score)

**Risk Vector:**
```
C:C1/L:L/D:CO+BW/SM:N/CM:E/EX:N/DA:Y/CO:H/S:0/DR:U/HIBP:C
```

**Vector Breakdown:**
- `C:C1` - Best complexity (technical, but actually weak password)
- `L:L` - Long (12 characters, meets minimum)
- `D:CO+BW` - Common password + Banned word
- `SM:N` - No similarity
- `CM:E` - Extreme compliance violation (189 days over)
- `EX:N` - Never expires
- `DA:Y` - Has Domain Admin pathway
- `CO:H` - High controlled objects (234)
- `S:0` - Not shared
- `DR:U` - Domain risk unknown
- `HIBP:C` - CRITICAL breach exposure (2.4M+ occurrences)

**Key Insight:** This password has maximum risk (10.0/10.0). Despite having "good" technical complexity, it's one of the most common passwords globally with over 2.4 million breach occurrences. Combined with DA pathway, 189 days past policy, and never expiring, this represents an immediate critical vulnerability.

---

## Example 3: Common Password (Non-Privileged)

### Password Characteristics
- **Password**: `password` (8 characters)
- **Username**: `john.smith@CORP.INT`
- **Complexity**: loweralpha (only lowercase letters)
- **Dictionary/Pattern Issues**: Common password, dictionary word, banned word
- **Similar Passwords**: None detected
- **Password Age**: 90 days old
- **Policy Max Age**: 261 days
- **Password Expiration**: Yes (expires)

### BloodHound Data
- **DA Pathway**: No
- **Controlled Objects**: 5 objects
- **Account Enabled**: Yes
- **Shared With**: 0 accounts

### HIBP Data
- **Breached**: Yes
- **Breach Count**: 9,545,824 (millions of occurrences)

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `loweralpha` = **0.95** (very weak)

**Length Factor:**
- `1.0 / (1.0 + e^((8 - 10) / 2))` = `1.0 / (1.0 + e^(-1))` = `1.0 / (1.0 + 0.368)` = **0.731**

**Dictionary Factor:**
- Common password: Yes = 0.7
- Dictionary word: Yes = 0.5
- Banned words: 1 ("password") = 0.2
- Keyboard patterns: 0 = 0
- Total: `min(1.0, 0.7 + 0.5 + 0.2 + 0)` = **1.0** (maxed out)

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(0.95 × 0.731) + 1.0 + 0.0` = `0.694 + 1.0` = **1.694**

**Base Score:**
- `1.694 × 2.5` = **4.235**

**HIBP Tier Adjustment:**
- HIBP count: 9,545,824 (>= 1,000,000)
- Falls into **Tier 1: Ultra-extreme exposure** → Base score raised to **8.0**

**Final Base Score: 8.0**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: `90 - 261 = -171` (compliant)
- Days = 0
- `min(1.0, 0.6 + (0.4 × 0))` = **0.6**

**Expiration Factor:**
- Password expires: Yes
- Factor: **0.85**

**Temporal Score:**
- `8.0 × 0.6 × 0.85` = **4.08**

**Final Temporal Score: 4.1**

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: No → +0
- Controlled objects: 5 (<= 10) → +0
- Total: **1.0**

**Share Factor:**
- Shared with: 0 accounts
- Factor: **1.0**

**Domain Factor:**
- Domain risk level: Unknown
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 9,545,824 (>= 100,000)
- Factor: **1.5**

**Environmental Score:**
- `4.08 × 1.0 × 1.0 × 1.0 × 1.5` = **6.12**

**Final Environmental Score: 6.1**

---

### Final Results

**Score Breakdown:**
```
Base Score:        8.0
  Complexity:      0.95 (loweralpha - very weak)
  Length:          0.73 (8 chars - minimum)
  Dictionary:      1.00 (common + dict + banned)
  Similarity:      0.00 (none)
  HIBP Tier:       Tier 1 (9.5M+ breaches)

Temporal Score:    4.1
  Compliance:      0.60 (compliant)
  Expiration:      0.85 (expires)

Environmental:     6.1
  Privilege:       1.00 (no DA, 5 objects)
  Share:           1.00 (unique)
  Domain:          1.00 (unknown)
  HIBP:            1.50 (extremely common breach)
```

**Final Score: 6.1**

**Risk Level: HIGH** (score >= 6.0)

**Risk Vector:**
```
C:C9/L:M/D:CO+DW+BW/SM:N/CM:N/EX:Y/DA:N/CO:L/S:0/DR:U/HIBP:C
```

**Vector Breakdown:**
- `C:C9` - Very weak complexity (lowercase only)
- `L:M` - Medium length (8 characters)
- `D:CO+DW+BW` - Common + Dictionary word + Banned word
- `SM:N` - No similarity
- `CM:N` - Compliant
- `EX:Y` - Expires
- `DA:N` - No DA pathway
- `CO:L` - Low controlled objects (5)
- `S:0` - Not shared
- `DR:U` - Domain risk unknown
- `HIBP:C` - CRITICAL breach exposure (9.5M+ occurrences)

**Key Insight:** Even without privileged access, "password" scores HIGH (6.1/10) due to extreme HIBP exposure. The temporal factors (compliant, expires) reduce the score from 8.0 to 4.1, but HIBP multiplier (1.5x) brings it back to 6.1. This is one of THE most common passwords globally.

---

## Example 4: Dictionary Word (Moderate HIBP)

### Password Characteristics
- **Password**: `elephant` (8 characters)
- **Username**: `jane.doe@CORP.INT`
- **Complexity**: loweralpha
- **Dictionary/Pattern Issues**: Dictionary word (exact match)
- **Similar Passwords**: None
- **Password Age**: 120 days old
- **Policy Max Age**: 261 days
- **Password Expiration**: Yes

### BloodHound Data
- **DA Pathway**: No
- **Controlled Objects**: 12 objects
- **Account Enabled**: Yes
- **Shared With**: 1 account

### HIBP Data
- **Breached**: Yes
- **Breach Count**: 3,847 (moderately common)

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `loweralpha` = **0.95**

**Length Factor:**
- `1.0 / (1.0 + e^((8 - 10) / 2))` = **0.731**

**Dictionary Factor:**
- Common password: No = 0
- Dictionary word: Yes = 0.5
- Banned words: 0 = 0
- Keyboard patterns: 0 = 0
- Total: **0.5**

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(0.95 × 0.731) + 0.5 + 0.0` = `0.694 + 0.5` = **1.194**

**Base Score:**
- `1.194 × 2.5` = **2.985**

**HIBP Tier Adjustment:**
- HIBP count: 3,847 (>= 1,000, < 10,000)
- Dictionary word: Yes
- Falls into **Tier 4: High exposure** → Base score raised to **6.0**

**Final Base Score: 6.0**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: `120 - 261 = -141` (compliant)
- Days = 0
- Factor: **0.6**

**Expiration Factor:**
- Password expires: Yes
- Factor: **0.85**

**Temporal Score:**
- `6.0 × 0.6 × 0.85` = **3.06**

**Final Temporal Score: 3.1**

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: No → +0
- Controlled objects: 12 (> 10, <= 50) → +0.1
- Total: **1.1**

**Share Factor:**
- Shared with: 1 account (1-9 range)
- Factor: `1.0 + 0.2` = **1.2**

**Domain Factor:**
- Domain risk level: Unknown
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 3,847 (>= 1,000, < 10,000)
- Factor: **1.3**

**Environmental Score:**
- `3.06 × 1.1 × 1.2 × 1.0 × 1.3` = **5.26**

**Final Environmental Score: 5.3**

---

### Final Results

**Score Breakdown:**
```
Base Score:        6.0
  Complexity:      0.95 (loweralpha)
  Length:          0.73 (8 chars)
  Dictionary:      0.50 (dict word)
  Similarity:      0.00 (none)
  HIBP Tier:       Tier 4 (3,847 breaches)

Temporal Score:    3.1
  Compliance:      0.60 (compliant)
  Expiration:      0.85 (expires)

Environmental:     5.3
  Privilege:       1.10 (12 objects)
  Share:           1.20 (1 account)
  Domain:          1.00 (unknown)
  HIBP:            1.30 (common breach)
```

**Final Score: 5.3**

**Risk Level: MEDIUM** (4.0 <= score < 6.0)

**Risk Vector:**
```
C:C9/L:M/D:DW/SM:N/CM:N/EX:Y/DA:N/CO:M/S:1/DR:U/HIBP:VH
```

**Vector Breakdown:**
- `C:C9` - Weak complexity (lowercase only)
- `L:M` - Medium length (8 characters)
- `D:DW` - Dictionary word
- `SM:N` - No similarity
- `CM:N` - Compliant
- `EX:Y` - Expires
- `DA:N` - No DA pathway
- `CO:M` - Medium controlled objects (12)
- `S:1` - Low sharing (1 account)
- `DR:U` - Domain risk unknown
- `HIBP:VH` - Very High breach exposure (3,847 occurrences)

**Key Insight:** Simple dictionary words score MEDIUM even without privileges. The HIBP tier system ensures dictionary words have baseline risk (6.0), reduced by good temporal factors (3.1), then elevated by sharing and HIBP multipliers to 5.3.

---

## Example 5: Pattern-Based Password

### Password Characteristics
- **Password**: `qwerty123` (9 characters)
- **Username**: `bob.jones@CORP.INT`
- **Complexity**: loweralphanum
- **Dictionary/Pattern Issues**: Keyboard pattern "qwerty"
- **Similar Passwords**: None
- **Password Age**: 200 days old
- **Policy Max Age**: 261 days
- **Password Expiration**: Yes

### BloodHound Data
- **DA Pathway**: No
- **Controlled Objects**: 8 objects
- **Account Enabled**: Yes
- **Shared With**: 3 accounts

### HIBP Data
- **Breached**: Yes
- **Breach Count**: 428,562 (very common)

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `loweralphanum` = **0.9**

**Length Factor:**
- `1.0 / (1.0 + e^((9 - 10) / 2))` = `1.0 / (1.0 + e^(-0.5))` = `1.0 / (1.0 + 0.606)` = **0.622**

**Dictionary Factor:**
- Common password: No = 0
- Dictionary word: No = 0
- Banned words: 0 = 0
- Keyboard patterns: 1 ("qwerty") = `min(0.5, 0.1 × 1)` = 0.1
- Total: **0.1**

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(0.9 × 0.622) + 0.1 + 0.0` = `0.560 + 0.1` = **0.660**

**Base Score:**
- `0.660 × 2.5` = **1.650**

**HIBP Tier Adjustment:**
- HIBP count: 428,562 (>= 100,000, < 1,000,000)
- Falls into **Tier 2: Extreme exposure** → Base score raised to **7.5**

**Final Base Score: 7.5**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: `200 - 261 = -61` (compliant)
- Days = 0
- Factor: **0.6**

**Expiration Factor:**
- Password expires: Yes
- Factor: **0.85**

**Temporal Score:**
- `7.5 × 0.6 × 0.85` = **3.825**

**Final Temporal Score: 3.8**

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: No → +0
- Controlled objects: 8 (<= 10) → +0
- Total: **1.0**

**Share Factor:**
- Shared with: 3 accounts (1-9 range)
- Factor: `1.0 + 0.2` = **1.2**

**Domain Factor:**
- Domain risk level: Unknown
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 428,562 (>= 100,000, < 1,000,000)
- Factor: **1.5**

**Environmental Score:**
- `3.825 × 1.0 × 1.2 × 1.0 × 1.5` = **6.885**

**Final Environmental Score: 6.9**

---

### Final Results

**Score Breakdown:**
```
Base Score:        7.5
  Complexity:      0.90 (loweralphanum)
  Length:          0.62 (9 chars)
  Dictionary:      0.10 (keyboard pattern)
  Similarity:      0.00 (none)
  HIBP Tier:       Tier 2 (428K+ breaches)

Temporal Score:    3.8
  Compliance:      0.60 (compliant)
  Expiration:      0.85 (expires)

Environmental:     6.9
  Privilege:       1.00 (no DA, 8 objects)
  Share:           1.20 (3 accounts)
  Domain:          1.00 (unknown)
  HIBP:            1.50 (extremely common breach)
```

**Final Score: 6.9**

**Risk Level: HIGH** (score >= 6.0)

**Risk Vector:**
```
C:C8/L:M/D:KP/SM:N/CM:N/EX:Y/DA:N/CO:L/S:1/DR:U/HIBP:C
```

**Vector Breakdown:**
- `C:C8` - Weak complexity (lowercase + numbers)
- `L:M` - Medium length (9 characters)
- `D:KP` - Keyboard pattern
- `SM:N` - No similarity
- `CM:N` - Compliant
- `EX:Y` - Expires
- `DA:N` - No DA pathway
- `CO:L` - Low controlled objects (8)
- `S:1` - Low sharing (3 accounts)
- `DR:U` - Domain risk unknown
- `HIBP:C` - CRITICAL breach exposure (428K+ occurrences)

**Key Insight:** Keyboard patterns like "qwerty123" are extremely common and heavily breached. Despite being compliant and having no privileges, the extreme HIBP exposure (428K+) pushes this to HIGH risk (6.9/10). Sharing with 3 accounts amplifies the risk.

---

## Example 6: Shared Password (Cross-Account Risk)

### Password Characteristics
- **Password**: `Winter2024!` (11 characters)
- **Username**: `service.account@CORP.INT`
- **Complexity**: mixedalphaspecialnum
- **Dictionary/Pattern Issues**: None
- **Similar Passwords**: None
- **Password Age**: 30 days old
- **Policy Max Age**: 261 days
- **Password Expiration**: No (never expires)

### BloodHound Data
- **DA Pathway**: No
- **Controlled Objects**: 45 objects
- **Account Enabled**: Yes
- **Shared With**: 47 accounts (widely shared!)

### HIBP Data
- **Breached**: Yes
- **Breach Count**: 18 occurrences

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `mixedalphaspecialnum` = **0.2**

**Length Factor:**
- `1.0 / (1.0 + e^((11 - 10) / 2))` = `1.0 / (1.0 + e^0.5)` = `1.0 / (1.0 + 1.649)` = **0.377**

**Dictionary Factor:**
- Common password: No = 0
- Dictionary word: No = 0
- Banned words: 0 = 0
- Keyboard patterns: 0 = 0
- Total: **0.0**

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(0.2 × 0.377) + 0.0 + 0.0` = **0.0754**

**Base Score:**
- `0.0754 × 2.5` = **0.1885**

**HIBP Tier Adjustment:**
- HIBP count: 18 (>= 10, < 100)
- No patterns, but contains keyboard pattern or banned words: No
- Falls into **Tier 6: Medium exposure** → Base score raised to **4.0**

**Final Base Score: 4.0**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: `30 - 261 = -231` (compliant)
- Days = 0
- Factor: **0.6**

**Expiration Factor:**
- Password never expires: No
- Factor: **1.0**

**Temporal Score:**
- `4.0 × 0.6 × 1.0` = **2.4**

**Final Temporal Score: 2.4**

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: No → +0
- Controlled objects: 45 (> 10, <= 50) → +0.1
- Total: **1.1**

**Share Factor:**
- Shared with: 47 accounts (10-99 range)
- Log scale: `log10(47) = 1.67` → level 2
- Factor: `1.0 + 0.3` = **1.3**

**Domain Factor:**
- Domain risk level: Unknown
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 18 (>= 10, < 100)
- Factor: **1.2**

**Environmental Score:**
- `2.4 × 1.1 × 1.3 × 1.0 × 1.2` = **4.118**

**Final Environmental Score: 4.1**

---

### Final Results

**Score Breakdown:**
```
Base Score:        4.0
  Complexity:      0.20 (mixedalphaspecialnum)
  Length:          0.38 (11 chars)
  Dictionary:      0.00 (none)
  Similarity:      0.00 (none)
  HIBP Tier:       Tier 6 (18 breaches)

Temporal Score:    2.4
  Compliance:      0.60 (compliant)
  Expiration:      1.00 (never expires)

Environmental:     4.1
  Privilege:       1.10 (45 objects)
  Share:           1.30 (47 accounts!)
  Domain:          1.00 (unknown)
  HIBP:            1.20 (moderate breach)
```

**Final Score: 4.1**

**Risk Level: MEDIUM** (4.0 <= score < 6.0)

**Risk Vector:**
```
C:C1/L:M/D:N/SM:N/CM:N/EX:N/DA:N/CO:M/S:2/DR:U/HIBP:M
```

**Vector Breakdown:**
- `C:C1` - Best complexity
- `L:M` - Medium length (11 characters)
- `D:N` - No dictionary issues
- `SM:N` - No similarity
- `CM:N` - Compliant
- `EX:N` - Never expires
- `DA:N` - No DA pathway
- `CO:M` - Medium controlled objects (45)
- `S:2` - High sharing (47 accounts - log scale level 2)
- `DR:U` - Domain risk unknown
- `HIBP:M` - Moderate breach exposure (18 occurrences)

**Key Insight:** Despite decent password strength, sharing across 47 accounts creates MEDIUM risk (4.1/10). The share factor (1.3x) significantly amplifies environmental risk. If ONE of those 47 accounts gets compromised, attackers can pivot to 46 others. Password reuse is a force multiplier for attackers.

---

## Example 7: Non-Compliant Password (Aged Out)

### Password Characteristics
- **Password**: `Tr0ub4dor&3` (11 characters)
- **Username**: `legacy.admin@CORP.INT`
- **Complexity**: mixedalphaspecialnum
- **Dictionary/Pattern Issues**: None
- **Similar Passwords**: None
- **Password Age**: 1,095 days old (3 years!)
- **Policy Max Age**: 261 days
- **Password Expiration**: No (never expires)

### BloodHound Data
- **DA Pathway**: Yes (has path to Domain Admin)
- **Controlled Objects**: 89 objects
- **Account Enabled**: Yes
- **Shared With**: 0 accounts

### HIBP Data
- **Breached**: Yes
- **Breach Count**: 2 occurrences (rare)

---

### Step-by-Step Score Calculation

#### 1. Base Score Calculation

**Complexity Factor:**
- Complexity label: `mixedalphaspecialnum` = **0.2**

**Length Factor:**
- `1.0 / (1.0 + e^((11 - 10) / 2))` = **0.377**

**Dictionary Factor:**
- Common password: No = 0
- Dictionary word: No = 0
- Banned words: 0 = 0
- Keyboard patterns: 0 = 0
- Total: **0.0**

**Similarity Factor:**
- No similar passwords: **0.0**

**Combined Factor:**
- `(0.2 × 0.377) + 0.0 + 0.0` = **0.0754**

**Base Score:**
- `0.0754 × 2.5` = **0.1885**

**HIBP Tier Adjustment:**
- HIBP count: 2 (> 0, < 10)
- Length: 11 (< 12 characters)
- Falls into **Tier 7: Low exposure** → Base score raised to **3.0**

**Final Base Score: 3.0**

---

#### 2. Temporal Score Calculation

**Compliance Factor:**
- Days out of compliance: `1095 - 261 = 834` days (2.28 years out!)
- Formula: `min(1.0, 0.6 + (0.4 × min(1.0, 834 / 180.0)))`
- `min(1.0, 0.6 + (0.4 × 1.0))` = `min(1.0, 0.6 + 0.4)` = **1.0**

**Expiration Factor:**
- Password never expires: No
- Factor: **1.0**

**Temporal Score:**
- `3.0 × 1.0 × 1.0` = **3.0**

**Final Temporal Score: 3.0**

---

#### 3. Environmental Score Calculation

**Privilege Factor:**
- Has DA path: Yes → +0.5
- Controlled objects: 89 (> 50, <= 100) → +0.2
- Total: `1.0 + 0.5 + 0.2` = **1.7**

**Share Factor:**
- Shared with: 0 accounts
- Factor: **1.0**

**Domain Factor:**
- Domain risk level: Unknown
- Factor: **1.0**

**HIBP Factor:**
- Breach count: 2 (> 0, < 10)
- Factor: **1.1**

**Environmental Score:**
- `3.0 × 1.7 × 1.0 × 1.0 × 1.1` = **5.61**

**Final Environmental Score: 5.6**

---

### Final Results

**Score Breakdown:**
```
Base Score:        3.0
  Complexity:      0.20 (mixedalphaspecialnum)
  Length:          0.38 (11 chars)
  Dictionary:      0.00 (none)
  Similarity:      0.00 (none)
  HIBP Tier:       Tier 7 (2 breaches)

Temporal Score:    3.0
  Compliance:      1.00 (834 days out - maxed!)
  Expiration:      1.00 (never expires)

Environmental:     5.6
  Privilege:       1.70 (DA path + 89 objects)
  Share:           1.00 (unique)
  Domain:          1.00 (unknown)
  HIBP:            1.10 (rare breach)
```

**Final Score: 5.6**

**Risk Level: CRITICAL** (has DA pathway - automatic Critical)

**Risk Vector:**
```
C:C1/L:M/D:N/SM:N/CM:E/EX:N/DA:Y/CO:M+/S:0/DR:U/HIBP:L
```

**Vector Breakdown:**
- `C:C1` - Best complexity
- `L:M` - Medium length (11 characters)
- `D:N` - No dictionary issues
- `SM:N` - No similarity
- `CM:E` - EXTREME compliance violation (834 days = 2.3 years over!)
- `EX:N` - Never expires
- `DA:Y` - Has Domain Admin pathway
- `CO:M+` - Medium-High controlled objects (89)
- `S:0` - Not shared
- `DR:U` - Domain risk unknown
- `HIBP:L` - Low breach exposure (2 occurrences)

**Key Insight:** A 3-year-old password on a DA-capable account is CRITICAL regardless of password quality. The compliance factor is maxed out (1.0), meaning the password is so old that temporal risk cannot increase further. This account should trigger immediate remediation - the password has been unchanged for over 1,000 days while the policy allows 261.

---

## Summary Table: All Examples

| Example | Password | Length | Complexity | HIBP Count | DA Path | Shared | Base | Temporal | Final | Risk Level | Key Factor |
|---------|----------|--------|------------|------------|---------|--------|------|----------|-------|------------|------------|
| 1 | `kR7#mP9@nQ2$wX5&zL8!` | 20 | C1 | 0 | Yes | 0 | 2.0 | 1.0 | 1.8 | **CRITICAL** | DA pathway |
| 2 | `Password123!` | 12 | C1 | 2,456,823 | Yes | 0 | 8.0 | 8.0 | 10.0 | **CRITICAL** | HIBP Tier 1 |
| 3 | `password` | 8 | C9 | 9,545,824 | No | 0 | 8.0 | 4.1 | 6.1 | **HIGH** | HIBP Tier 1 |
| 4 | `elephant` | 8 | C9 | 3,847 | No | 1 | 6.0 | 3.1 | 5.3 | **MEDIUM** | Dictionary + HIBP |
| 5 | `qwerty123` | 9 | C8 | 428,562 | No | 3 | 7.5 | 3.8 | 6.9 | **HIGH** | HIBP Tier 2 |
| 6 | `Winter2024!` | 11 | C1 | 18 | No | 47 | 4.0 | 2.4 | 4.1 | **MEDIUM** | High sharing |
| 7 | `Tr0ub4dor&3` | 11 | C1 | 2 | Yes | 0 | 3.0 | 3.0 | 5.6 | **CRITICAL** | 834 days old + DA |

---

## Key Takeaways

### 1. HIBP Tier System is Powerful
The evidence-based HIBP tier system ensures cracked passwords have appropriate baseline risk:
- **Tier 1** (1M+ breaches): Base score 8.0 - Ultra-extreme exposure
- **Tier 2** (100K+ breaches): Base score 7.5 - Extreme exposure
- **Tier 3** (10K+ breaches OR common): Base score 7.0 - Very high exposure
- **Tier 4** (1K+ breaches OR dictionary): Base score 6.0 - High exposure
- **Tier 5** (100+ breaches): Base score 5.0 - Medium-high exposure
- **Tier 6** (10+ breaches OR patterns): Base score 4.0 - Medium exposure
- **Tier 7** (1+ breaches OR short): Base score 3.0 - Low exposure
- **Tier 8** (not breached, long): Base score 2.0 - Minimal risk

### 2. DA Pathway = Automatic Critical
Any account with a Domain Admin pathway is automatically CRITICAL, regardless of password strength. Example 1 shows a strong password (1.8/10 score) that's still CRITICAL due to DA access.

### 3. Environmental Factors Amplify Risk
- **HIBP Factor** (1.0-1.5x): Breached passwords are inherently riskier
- **Privilege Factor** (1.0-1.8x): DA path + controlled objects compound risk
- **Share Factor** (1.0-1.5x): Password reuse creates lateral movement risk
- **Domain Factor** (1.0-1.3x): High-risk domains increase exposure

### 4. Temporal Factors Reduce Risk (Usually)
- **Compliance Factor** (0.6-1.0): Old passwords are riskier
- **Expiration Factor** (0.85-1.0): Never-expiring passwords are slightly riskier
- These factors can **reduce** score by up to 49% (0.6 × 0.85 = 0.51)

### 5. Password Sharing is Dangerous
Example 6 shows a decent password (`Winter2024!`) scoring MEDIUM (4.1) due to sharing across 47 accounts. The share factor (1.3x) amplifies environmental risk significantly.

### 6. Age Matters
Example 7 demonstrates a 3-year-old password (834 days out of compliance) on a DA account. Even with good complexity and low HIBP exposure, extreme age pushes this to CRITICAL.

### 7. Common Passwords Always Score High
"Password123!" and "password" both achieve base scores of 8.0 due to HIBP Tier 1 classification (millions of breaches). Technical complexity is meaningless when a password is globally common.

---

## Recommendations Based on Examples

### Immediate Action (Critical Risk)
1. **Example 2**: Change `Password123!` immediately - 2.4M+ breaches + DA pathway
2. **Example 7**: Force reset `Tr0ub4dor&3` - 834 days old + DA pathway

### High Priority (High Risk)
3. **Example 3**: Replace `password` - 9.5M+ breaches
4. **Example 5**: Change `qwerty123` - 428K+ breaches + shared with 3 accounts

### Medium Priority (Medium Risk)
5. **Example 4**: Update `elephant` - dictionary word + shared
6. **Example 6**: Eliminate `Winter2024!` sharing - 47 accounts at risk

### Monitor (Low Risk)
7. **Example 1**: `kR7#mP9@nQ2$wX5&zL8!` is CRITICAL only due to DA pathway - monitor for privilege changes

---

## Vector Quick Reference

### Risk Vector Format
```
C:X/L:Y/D:Z/SM:W/CM:V/EX:U/DA:T/CO:S/S:R/DR:Q/HIBP:P
```

### Component Ranges
- **C** (Complexity): C1 (best) to C10 (worst)
- **L** (Length): VL, L, M, S, VS
- **D** (Dictionary): N, CO, DW, BW, KP (combinable with +)
- **SM** (Similarity): N, M, H, VH
- **CM** (Compliance): N, L, M, H, VH, E, U
- **EX** (Expiration): Y, N, U
- **DA** (Domain Admin): N, Y, M
- **CO** (Controlled Objects): L, M, M+, H, VH, E, U
- **S** (Sharing): 0, 1, 2, 3, 4 (log scale)
- **DR** (Domain Risk): L, M, H, C, U
- **HIBP**: N, L, M, H, VH, E, C

### Example Vectors Explained
- `C:C1/L:VL/D:N/SM:N/CM:N/EX:Y/DA:Y/CO:VH/S:0/DR:U/HIBP:N` - Strong password, DA account
- `C:C9/L:M/D:CO+DW+BW/SM:N/CM:N/EX:Y/DA:N/CO:L/S:0/DR:U/HIBP:C` - Weak password, high HIBP
- `C:C1/L:M/D:N/SM:N/CM:N/EX:N/DA:N/CO:M/S:2/DR:U/HIBP:M` - Shared password

---

## Conclusion

The CVSS-style scoring system provides a comprehensive, evidence-based approach to password risk assessment. By combining intrinsic password qualities (base score), time factors (temporal score), and organizational context (environmental score), the system accurately identifies high-risk passwords while accounting for real-world attack patterns observed in the HIBP dataset.

The most important insight: **Technical complexity alone is insufficient**. HIBP exposure, privilege levels, password age, and sharing patterns are equally critical factors in determining true password risk.
