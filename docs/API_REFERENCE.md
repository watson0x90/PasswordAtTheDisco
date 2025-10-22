# API Reference

Complete API reference for Password!AtTheDisco modules and functions.

## Table of Contents

- [Core Modules](#core-modules)
  - [config](#coreconfig)
  - [data](#coredata)
  - [password_analysis](#corepassword_analysis)
  - [domain_analysis](#coredomain_analysis)
  - [scoring](#corescoring)
  - [vector](#corevector)
  - [bloodhound_integration](#corebloodhound_integration)
  - [hibp_correlation](#corehibp_correlation)
  - [hashcat_integration](#corehashcat_integration)
- [Models](#models)
- [Report Library](#report-library)
- [Utilities](#utilities)

## Core Modules

### core.config

Configuration management and loading.

#### Constants

```python
# Directory paths
REPORTS_DIR: Path          # Base reports directory
HTML_DIR: Path             # HTML report output
MARKDOWN_DIR: Path         # Markdown report output
PDF_DIR: Path             # PDF report output
CSV_DIR: Path             # CSV export directory
EXCEL_DIR: Path           # Excel report directory

# Configuration dictionaries
BHE_CONFIG: dict          # BloodHound Enterprise settings
HIBP_CONFIG: dict         # HIBP correlation settings
HASHCAT_CONFIG: dict      # Hashcat integration settings
APP_CONFIG: dict          # Application settings
```

#### Functions

```python
def load_json_config(config_path: str) -> dict:
    """Load and parse JSON configuration file.

    Args:
        config_path: Path to JSON config file (relative or absolute)

    Returns:
        Parsed configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file contains invalid JSON

    Example:
        >>> config = load_json_config("config/bloodhound.json")
        >>> print(config['domain'])
        'bloodhound.company.com'
    """
```

---

### core.data

Data loading and parsing from hashcat format files.

#### Functions

```python
def parse_hashcat_file(
    filepath: str,
    has_passwords: bool = True
) -> list[dict]:
    """Parse hashcat format file into account dictionaries.

    Expected format:
        user@DOMAIN:RID:LMhash:NTLMhash:::password

    Args:
        filepath: Path to hashcat file
        has_passwords: True if file contains passwords (cracked),
                      False if only hashes (uncracked)

    Returns:
        List of account dictionaries with keys:
            - username: User principal name (user@DOMAIN)
            - domain: Domain name
            - rid: Relative identifier
            - lm_hash: LM hash (usually empty)
            - ntlm_hash: NTLM hash
            - password: Plaintext password (if has_passwords=True)

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file format is invalid

    Example:
        >>> cracked = parse_hashcat_file("domain_cracked.txt", has_passwords=True)
        >>> print(cracked[0])
        {
            'username': 'john@CORP.INT',
            'domain': 'CORP.INT',
            'ntlm_hash': '8846F7...',
            'password': 'Password123!'
        }
    """

def load_wordlists() -> dict:
    """Load all word lists from lists/ directory.

    Returns:
        Dictionary containing:
            - forbidden_words: Set of banned words
            - dictionary_words: Set of dictionary words
            - common_passwords: Set of common weak passwords
            - keyboard_patterns: List of keyboard patterns

    Example:
        >>> wordlists = load_wordlists()
        >>> print(len(wordlists['dictionary_words']))
        479829
    """

def load_password_policy(domain: str) -> dict:
    """Load password policy for domain.

    Args:
        domain: Domain name (e.g., "CORP.INT")

    Returns:
        Policy dictionary with keys:
            - min_length: Minimum password length
            - require_uppercase: Require uppercase letters
            - require_lowercase: Require lowercase letters
            - require_digits: Require digits
            - require_special: Require special characters
            - max_password_age_days: Maximum password age

    Example:
        >>> policy = load_password_policy("CORP.INT")
        >>> print(policy['min_length'])
        14
    """
```

---

### core.password_analysis

Individual password analysis functions.

#### Functions

```python
def analyze_password(
    password: str,
    wordlists: dict,
    other_passwords: Optional[list] = None
) -> dict:
    """Comprehensive password analysis.

    Args:
        password: Plaintext password to analyze
        wordlists: Dictionary from load_wordlists()
        other_passwords: List of other passwords for similarity check

    Returns:
        Analysis dictionary with keys:
            - complexity_label: Complexity category (Best/Better/Good/Moderate/Low/VeryLow)
            - char_sets: List of character sets present
            - length: Password length
            - dictionary_word: Boolean indicating dictionary word found
            - common_password: Boolean indicating common password
            - forbidden_words: List of forbidden words found
            - keyboard_pattern: Boolean indicating keyboard pattern
            - similar_passwords: Count of similar passwords
            - similarity_score: Highest similarity score (0.0-1.0)

    Example:
        >>> wordlists = load_wordlists()
        >>> analysis = analyze_password("Password123!", wordlists)
        >>> print(analysis['complexity_label'])
        'Low'
        >>> print(analysis['dictionary_word'])
        True
    """

def assess_complexity(password: str) -> tuple[str, list, int]:
    """Assess password complexity.

    Args:
        password: Plaintext password

    Returns:
        Tuple of (complexity_label, char_sets, char_set_count)
            - complexity_label: Best/Better/Good/Moderate/Low/VeryLow
            - char_sets: List of sets present (uppercase, lowercase, digits, special)
            - char_set_count: Number of different character sets (0-5)

    Example:
        >>> label, sets, count = assess_complexity("Abc123!@#")
        >>> print(label)
        'Best'
        >>> print(count)
        5
    """

def check_dictionary_word(password: str, dictionary: set) -> bool:
    """Check if password contains dictionary word.

    Args:
        password: Plaintext password
        dictionary: Set of dictionary words

    Returns:
        True if password contains dictionary word

    Example:
        >>> dictionary = {'password', 'hello', 'world'}
        >>> check_dictionary_word("Password123", dictionary)
        True
    """

def check_common_password(password: str, common_passwords: set) -> bool:
    """Check if password is in common password list.

    Args:
        password: Plaintext password
        common_passwords: Set of common passwords

    Returns:
        True if password is common

    Example:
        >>> common = {'Password123', 'Welcome1', 'Admin123'}
        >>> check_common_password("Password123", common)
        True
    """

def find_forbidden_words(password: str, forbidden: set) -> list:
    """Find forbidden words in password.

    Args:
        password: Plaintext password
        forbidden: Set of forbidden words (case-insensitive)

    Returns:
        List of forbidden words found in password

    Example:
        >>> forbidden = {'company', 'admin', 'password'}
        >>> find_forbidden_words("CompanyAdmin2024", forbidden)
        ['company', 'admin']
    """

def detect_keyboard_pattern(password: str, patterns: list) -> bool:
    """Detect keyboard pattern in password.

    Args:
        password: Plaintext password
        patterns: List of keyboard patterns (e.g., ['qwerty', 'asdfgh'])

    Returns:
        True if keyboard pattern detected

    Example:
        >>> patterns = ['qwerty', '12345', 'asdfgh']
        >>> detect_keyboard_pattern("qwerty123", patterns)
        True
    """

def calculate_similarity(
    password: str,
    other_passwords: list,
    threshold: float = 0.8
) -> tuple[int, float]:
    """Calculate similarity to other passwords.

    Uses Levenshtein distance to find similar passwords.

    Args:
        password: Plaintext password
        other_passwords: List of other passwords to compare
        threshold: Similarity threshold (0.0-1.0)

    Returns:
        Tuple of (similar_count, max_similarity)

    Example:
        >>> others = ["Password123", "Password456", "Different!"]
        >>> count, max_sim = calculate_similarity("Password789", others)
        >>> print(count)
        2
        >>> print(max_sim > 0.8)
        True
    """
```

---

### core.domain_analysis

Domain-level analysis and cross-domain detection.

#### Functions

```python
def analyze_domain(
    accounts: list,
    domain_name: str,
    wordlists: dict
) -> dict:
    """Analyze all accounts in a domain.

    Args:
        accounts: List of account dictionaries
        domain_name: Domain name
        wordlists: Word lists dictionary

    Returns:
        Domain analysis dictionary with keys:
            - total_accounts: Total account count
            - cracked_accounts: Accounts with passwords
            - uncracked_accounts: Accounts without passwords
            - risk_distribution: Dict of risk level counts
            - average_score: Average risk score
            - policy_compliance: Compliance statistics
            - password_sharing: Password reuse analysis

    Example:
        >>> analysis = analyze_domain(accounts, "CORP.INT", wordlists)
        >>> print(analysis['risk_distribution'])
        {'Critical': 34, 'High': 89, 'Medium': 234, 'Low': 156}
    """

def find_shared_passwords(domains: dict) -> dict:
    """Find passwords shared across domains.

    Args:
        domains: Dictionary of domain_name -> account_list

    Returns:
        Dictionary mapping password -> list of accounts using it

    Example:
        >>> shared = find_shared_passwords(all_domains)
        >>> for pwd, accounts in shared.items():
        ...     if len(accounts) > 1:
        ...         print(f"{pwd}: {len(accounts)} accounts")
        Password123!: 5 accounts
        Welcome2024: 3 accounts
    """

def find_shared_hashes(domains: dict) -> dict:
    """Find identical NTLM hashes across domains.

    Args:
        domains: Dictionary of domain_name -> account_list

    Returns:
        Dictionary mapping ntlm_hash -> list of accounts with that hash

    Example:
        >>> shared = find_shared_hashes(all_domains)
        >>> for hash, accounts in shared.items():
        ...     if len(accounts) > 2:
        ...         print(f"Hash {hash[:8]}: {len(accounts)} accounts")
        Hash 8846F7EA: 8 accounts
    """

def calculate_domain_risk_level(domain_name: str) -> str:
    """Calculate inherent domain risk level.

    Args:
        domain_name: Domain name

    Returns:
        Risk level: "Low", "Medium", or "High"

    Example:
        >>> calculate_domain_risk_level("PROD.CORP.INT")
        'High'
        >>> calculate_domain_risk_level("DEV.CORP.INT")
        'Low'
    """
```

---

### core.scoring

CVSS-style three-component risk scoring.

#### Functions

```python
def calculate_risk_score(
    password: str,
    account: Account,
    domain_metadata: dict,
    analysis: dict,
    hibp_tier: int = 0,
    hibp_count: int = 0
) -> tuple[float, str, dict]:
    """Calculate comprehensive risk score.

    Args:
        password: Plaintext password
        account: Account object with BloodHound data
        domain_metadata: Domain-level metadata
        analysis: Password analysis dictionary
        hibp_tier: HIBP breach tier (0-6)
        hibp_count: HIBP breach count

    Returns:
        Tuple of (risk_score, risk_level, breakdown)
            - risk_score: Final score (0.0-10.0)
            - risk_level: Critical/High/Medium/Low
            - breakdown: Dictionary with score components

    Example:
        >>> score, level, breakdown = calculate_risk_score(
        ...     "Password123!",
        ...     account,
        ...     {},
        ...     analysis,
        ...     hibp_tier=6,
        ...     hibp_count=2400000
        ... )
        >>> print(f"{score:.1f} ({level})")
        9.5 (Critical)
    """

def calculate_base_score(
    password: str,
    analysis: dict,
    hibp_tier: int = 0
) -> tuple[float, dict]:
    """Calculate base risk score (password intrinsics).

    Args:
        password: Plaintext password
        analysis: Password analysis dictionary
        hibp_tier: HIBP breach tier (0-6)

    Returns:
        Tuple of (base_score, components)
            - base_score: Base score (0.0-10.0)
            - components: Dictionary of contributing factors

    Example:
        >>> base, components = calculate_base_score(
        ...     "Password123!",
        ...     analysis,
        ...     hibp_tier=6
        ... )
        >>> print(f"Base: {base:.1f}")
        Base: 8.2
    """

def calculate_temporal_score(
    base_score: float,
    password_age_days: Optional[int],
    password_never_expires: bool,
    policy: dict
) -> tuple[float, dict]:
    """Calculate temporal score (time-based factors).

    Args:
        base_score: Base score from calculate_base_score()
        password_age_days: Days since password change
        password_never_expires: True if password never expires
        policy: Password policy dictionary

    Returns:
        Tuple of (temporal_score, factors)
            - temporal_score: Temporal score (0.0-10.0)
            - factors: Dictionary of temporal multipliers

    Example:
        >>> temporal, factors = calculate_temporal_score(
        ...     8.0,
        ...     password_age_days=189,
        ...     password_never_expires=False,
        ...     policy={'max_password_age_days': 90}
        ... )
        >>> print(f"Temporal: {temporal:.1f}")
        Temporal: 8.9
    """

def calculate_environmental_score(
    temporal_score: float,
    privilege_factor: float,
    sharing_factor: float,
    domain_factor: float,
    hibp_factor: float
) -> tuple[float, dict]:
    """Calculate environmental score (organizational context).

    Args:
        temporal_score: Temporal score
        privilege_factor: Privilege multiplier (1.0-2.0)
        sharing_factor: Password sharing multiplier (1.0-1.5)
        domain_factor: Domain risk multiplier (1.0-1.3)
        hibp_factor: HIBP breach count multiplier (1.0-1.5)

    Returns:
        Tuple of (environmental_score, factors)
            - environmental_score: Final score (0.0-10.0)
            - factors: Dictionary of environmental multipliers

    Example:
        >>> env, factors = calculate_environmental_score(
        ...     8.9,
        ...     privilege_factor=1.8,  # High privilege
        ...     sharing_factor=1.2,    # Some sharing
        ...     domain_factor=1.2,     # High-risk domain
        ...     hibp_factor=1.5        # Extreme HIBP count
        ... )
        >>> print(f"Environmental: {env:.1f}")
        Environmental: 10.0
    """

def determine_risk_level(score: float, has_da_path: bool) -> str:
    """Determine categorical risk level from score.

    Args:
        score: Risk score (0.0-10.0)
        has_da_path: True if account has Domain Admin pathway

    Returns:
        Risk level: "Critical", "High", "Medium", or "Low"

    Note:
        Any account with DA pathway is automatically Critical

    Example:
        >>> determine_risk_level(8.5, has_da_path=False)
        'Critical'
        >>> determine_risk_level(5.2, has_da_path=True)
        'Critical'
        >>> determine_risk_level(5.2, has_da_path=False)
        'Medium'
    """

def calculate_privilege_factor(
    has_da_path: bool,
    controlled_objects: int
) -> float:
    """Calculate privilege risk multiplier.

    Args:
        has_da_path: True if account has Domain Admin pathway
        controlled_objects: Number of AD objects controlled

    Returns:
        Privilege factor (1.0-2.0)

    Example:
        >>> calculate_privilege_factor(True, 234)
        2.0
        >>> calculate_privilege_factor(False, 45)
        1.2
    """

def calculate_sharing_factor(shared_count: int) -> float:
    """Calculate password sharing risk multiplier.

    Args:
        shared_count: Number of accounts sharing this password/hash

    Returns:
        Sharing factor (1.0-1.5)

    Example:
        >>> calculate_sharing_factor(5)
        1.3
        >>> calculate_sharing_factor(1)
        1.0
    """

def calculate_hibp_factor(breach_count: int) -> float:
    """Calculate HIBP breach count risk multiplier.

    Args:
        breach_count: Number of times hash appears in HIBP

    Returns:
        HIBP factor (1.0-1.5)

    Example:
        >>> calculate_hibp_factor(2400000)
        1.5
        >>> calculate_hibp_factor(87)
        1.1
    """
```

---

### core.vector

Risk vector generation in CVSS-like notation.

#### Functions

```python
def generate_risk_vector(
    complexity_charsets: int,
    length: int,
    detections: list,
    similarity: int,
    hibp_tier: int,
    password_never_expires: bool,
    has_da_path: bool,
    controlled_objects: int,
    shared_count: int,
    domain_risk: str,
    hibp_count: int
) -> str:
    """Generate risk vector string.

    Format: C:X/L:X/D:X/SM:X/CM:X/EX:X/DA:X/CO:X/S:X/DR:X/HIBP:X

    Args:
        complexity_charsets: Character set count (0-5)
        length: Password length
        detections: List of detections (CO=common, DI=dictionary, etc.)
        similarity: Similar password count
        hibp_tier: HIBP tier (0-6)
        password_never_expires: True if never expires
        has_da_path: True if DA pathway exists
        controlled_objects: Controlled object count
        shared_count: Shared password count
        domain_risk: Domain risk level (L/M/H)
        hibp_count: HIBP breach count

    Returns:
        Risk vector string

    Example:
        >>> vector = generate_risk_vector(
        ...     complexity_charsets=2,
        ...     length=12,
        ...     detections=['CO', 'DI'],
        ...     similarity=3,
        ...     hibp_tier=6,
        ...     password_never_expires=True,
        ...     has_da_path=True,
        ...     controlled_objects=234,
        ...     shared_count=5,
        ...     domain_risk='H',
        ...     hibp_count=2400000
        ... )
        >>> print(vector)
        C:C2/L:M/D:CO+DI/SM:H/CM:C/EX:N/DA:Y/CO:VH/S:5/DR:H/HIBP:C
    """
```

---

### core.bloodhound_integration

BloodHound Enterprise API integration.

#### Classes

```python
class BloodHoundClient:
    """BloodHound Enterprise API client.

    Attributes:
        base_url: API base URL
        session: Requests session with auth

    Example:
        >>> from core.config import BHE_CONFIG
        >>> client = BloodHoundClient(BHE_CONFIG)
        >>> version = client.get_version()
        >>> print(version)
        '5.4.0'
    """

    def __init__(self, config: dict):
        """Initialize BloodHound client.

        Args:
            config: BloodHound configuration dictionary
        """

    def get_version(self) -> str:
        """Get BloodHound API version.

        Returns:
            Version string

        Raises:
            requests.RequestException: If API request fails
        """

    def search_user(self, username: str) -> Optional[dict]:
        """Search for user by UPN.

        Args:
            username: User principal name (user@DOMAIN.INT)

        Returns:
            User dictionary with id, name, properties
            None if user not found

        Example:
            >>> user = client.search_user("john@CORP.INT")
            >>> print(user['objectid'])
            'S-1-5-21-...'
        """

    def query_da_pathways(self, user_id: str) -> bool:
        """Check if user has pathway to Domain Admin.

        Args:
            user_id: BloodHound user object ID

        Returns:
            True if DA pathway exists

        Example:
            >>> has_da = client.query_da_pathways(user['objectid'])
            >>> print(has_da)
            True
        """

    def query_controllables(
        self,
        user_id: str,
        limit: int = 10
    ) -> int:
        """Get count of objects controlled by user.

        Args:
            user_id: BloodHound user object ID
            limit: Initial query limit

        Returns:
            Count of controlled objects

        Example:
            >>> count = client.query_controllables(user['objectid'])
            >>> print(count)
            234
        """


class BloodHoundEnricher:
    """High-level account enrichment orchestrator.

    Example:
        >>> from core.config import BHE_CONFIG
        >>> client = BloodHoundClient(BHE_CONFIG)
        >>> enricher = BloodHoundEnricher(client)
        >>> enriched_accounts = enricher.enrich_accounts(accounts)
    """

    def __init__(self, client: BloodHoundClient):
        """Initialize enricher.

        Args:
            client: Initialized BloodHound client
        """

    def enrich_accounts(self, accounts: list) -> list:
        """Enrich accounts with BloodHound data.

        Queries BloodHound in parallel for:
        - User search (object ID)
        - DA pathways
        - Controlled objects
        - Account properties

        Args:
            accounts: List of account dictionaries

        Returns:
            List of enriched account dictionaries

        Example:
            >>> enriched = enricher.enrich_accounts(accounts)
            >>> print(enriched[0]['has_da_path'])
            True
        """
```

---

### core.hibp_correlation

Have I Been Pwned hash correlation.

#### Classes

```python
class HIBPChecker:
    """HIBP NTLM hash checker with three-tier lookup.

    Architecture:
        Tier 1: In-memory cache (top N hashes)
        Tier 2: Index file (prefix → offset)
        Tier 3: Database file (sequential search)

    Example:
        >>> from core.config import HIBP_CONFIG
        >>> checker = HIBPChecker(HIBP_CONFIG)
        >>> is_breached, count = checker.check_ntlm_hash("8846F7...")
        >>> print(f"Breached: {is_breached}, Count: {count}")
        Breached: True, Count: 2400000
    """

    def __init__(self, config: dict):
        """Initialize HIBP checker.

        Loads cache and index on initialization.

        Args:
            config: HIBP configuration dictionary
        """

    def check_ntlm_hash(self, ntlm_hash: str) -> tuple[bool, int]:
        """Check if NTLM hash is in HIBP database.

        Args:
            ntlm_hash: NTLM hash (uppercase, 32 hex chars)

        Returns:
            Tuple of (is_breached, breach_count)

        Example:
            >>> is_breached, count = checker.check_ntlm_hash("8846F7...")
            >>> print(f"Found {count} times")
            Found 2400000 times
        """

    def get_hibp_tier(self, breach_count: int) -> int:
        """Get HIBP tier (0-6) from breach count.

        Tiers:
            0: Not breached
            1: 1-9 breaches
            2: 10-99 breaches
            3: 100-999 breaches
            4: 1,000-9,999 breaches
            5: 10,000-99,999 breaches
            6: 100,000+ breaches

        Args:
            breach_count: Number of breaches

        Returns:
            HIBP tier (0-6)

        Example:
            >>> tier = checker.get_hibp_tier(2400000)
            >>> print(tier)
            6
        """
```

---

### core.hashcat_integration

Hashcat automation (future expansion).

#### Classes

```python
class HashcatRunner:
    """Hashcat automation wrapper.

    Note: Currently in development. Basic functionality available.

    Example:
        >>> from core.config import HASHCAT_CONFIG
        >>> runner = HashcatRunner(HASHCAT_CONFIG)
        >>> # Future: runner.crack_hashes(...)
    """
```

## Models

### models.account

```python
@dataclass
class Account:
    """User account with analysis results.

    Attributes:
        username: User principal name
        domain: Domain name
        ntlm_hash: NTLM hash
        password: Plaintext password (optional)
        has_da_path: Has Domain Admin pathway
        da_domains: Domains with DA access
        controlled_objects: Controlled object count
        enabled: Account enabled status
        last_logon: Last logon timestamp
        password_age_days: Password age in days
        password_expires: Password expiration date
        analysis: Password analysis results
        risk_score: Final risk score
        risk_level: Risk level category
        risk_vector: Risk vector string
    """
```

## Report Library

### report_lib.standalone_html.report

```python
def generate_html_report(
    domain_data: dict,
    output_path: str,
    domain_name: str
) -> None:
    """Generate standalone HTML report.

    Args:
        domain_data: Domain analysis results
        output_path: Output HTML file path
        domain_name: Domain name

    Example:
        >>> generate_html_report(
        ...     analysis_results,
        ...     "reports/CORP/html/report.html",
        ...     "CORP.INT"
        ... )
    """
```

### report_lib.excel.report

```python
def generate_actionable_report(
    domain_data: dict,
    output_path: str,
    domain_name: str
) -> None:
    """Generate Excel actionable report.

    Args:
        domain_data: Domain analysis results
        output_path: Output Excel file path
        domain_name: Domain name

    Example:
        >>> generate_actionable_report(
        ...     analysis_results,
        ...     "reports/CORP/excel/actionable.xlsx",
        ...     "CORP.INT"
        ... )
    """
```

### report_lib.csv.report

```python
def generate_csv_report(
    domain_data: dict,
    output_path: str,
    domain_name: str
) -> None:
    """Generate CSV data export.

    Args:
        domain_data: Domain analysis results
        output_path: Output CSV file path
        domain_name: Domain name
    """
```

## Utilities

### utils.logging

```python
def setup_logging(log_dir: str = "output") -> None:
    """Setup logging configuration.

    Creates file and console handlers.

    Args:
        log_dir: Directory for log files
    """

def get_logger(name: str) -> logging.Logger:
    """Get logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Configured logger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing started")
    """
```

### utils.file_utils

```python
def ensure_directory(path: str) -> None:
    """Ensure directory exists, create if needed.

    Args:
        path: Directory path
    """

def generate_pdf_from_markdown(
    markdown_path: str,
    pdf_path: str
) -> bool:
    """Convert Markdown to PDF using pandoc.

    Args:
        markdown_path: Input Markdown file
        pdf_path: Output PDF file

    Returns:
        True if successful

    Raises:
        FileNotFoundError: If pandoc not installed
    """
```

## Related Documentation

- [Architecture Guide](ARCHITECTURE.md) - System design
- [Development Guide](DEVELOPMENT.md) - Contributing
- [Scoring System](SCORING_SYSTEM.md) - Scoring details
- [User Guide](USER_GUIDE.md) - Usage documentation

---

**API Questions?** Check the source code or open an issue on GitHub.
