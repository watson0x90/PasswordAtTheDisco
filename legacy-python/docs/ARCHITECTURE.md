# Architecture Documentation

System architecture and design decisions for Password!AtTheDisco.

## Table of Contents

- [System Overview](#system-overview)
- [Architecture Principles](#architecture-principles)
- [Module Architecture](#module-architecture)
- [Data Flow](#data-flow)
- [Integration Architecture](#integration-architecture)
- [Report Generation Pipeline](#report-generation-pipeline)
- [Performance Considerations](#performance-considerations)
- [Design Decisions](#design-decisions)

## System Overview

Password!AtTheDisco is a modular password auditing system that combines multiple analysis techniques to provide comprehensive security assessments.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                       │
│               (CLI, HTML Dashboard, Excel Reports)          │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                    Orchestration Layer                      │
│              (processor.py - Domain Processing)             │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────┼──────────┐
        │          │          │
┌───────▼────┐ ┌──▼─────┐ ┌──▼────────┐
│ Password   │ │BloodH. │ │   HIBP    │
│ Analysis   │ │Integr. │ │Correlation│
│            │ │        │ │           │
└───────┬────┘ └───┬────┘ └────┬──────┘
        │          │           │
        └──────────┼───────────┘
                   │
        ┌──────────▼──────────┐
        │   Scoring Engine    │
        │  (CVSS-style 3-comp)│
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │  Report Generation  │
        │(HTML/Excel/CSV/MD)  │
        └─────────────────────┘
```

### Core Components

1. **Orchestration Layer** (`processor.py`)
   - Manages workflow execution
   - Coordinates parallel processing
   - Handles progress tracking

2. **Analysis Layer** (`core/`)
   - Password complexity analysis
   - BloodHound integration
   - HIBP correlation
   - Risk scoring

3. **Data Layer** (`models/`)
   - Account data structures
   - Password analysis results
   - Domain metadata

4. **Presentation Layer** (`report_lib/`)
   - HTML dashboards
   - Excel reports
   - CSV exports
   - Markdown/PDF

5. **Integration Layer**
   - BloodHound Enterprise API
   - HIBP database access
   - Hashcat automation

## Architecture Principles

### 1. Modularity

Each component is self-contained with clear interfaces:

```python
# Clear input/output contracts
def analyze_password(password: str, wordlists: dict) -> dict:
    """Single responsibility: analyze one password."""
    pass

def calculate_risk_score(password: str, account: Account, analysis: dict) -> tuple:
    """Single responsibility: calculate risk score."""
    pass
```

**Benefits**:
- Easy to test in isolation
- Can be replaced/upgraded independently
- Clear dependencies

### 2. Separation of Concerns

Different aspects handled by different modules:

- **Data Loading**: `core/data.py`
- **Analysis**: `core/password_analysis.py`, `core/domain_analysis.py`
- **Scoring**: `core/scoring.py`, `core/vector.py`
- **Integration**: `core/bloodhound_integration.py`, `core/hibp_correlation.py`
- **Reporting**: `report_lib/*`

### 3. Configuration Over Code

All settings externalized to JSON files:

```python
# core/config.py loads from JSON files
BHE_CONFIG = load_json_config("config/bloodhound.json")
HIBP_CONFIG = load_json_config("config/hibp.json")
HASHCAT_CONFIG = load_json_config("config/hashcat.json")
```

**Benefits**:
- No code changes for configuration
- Easy to version control
- Environment-specific configs

### 4. Fail-Safe Design

Graceful degradation when components unavailable:

```python
# BloodHound integration optional
try:
    bh_client = BloodHoundClient(BHE_CONFIG)
    enricher = BloodHoundEnricher(bh_client)
except Exception as e:
    logger.warning(f"BloodHound unavailable: {e}")
    enricher = None  # Continue without BloodHound

# HIBP optional
if HIBP_CONFIG.get('enable_lookup', True):
    hibp_checker = HIBPChecker()
else:
    hibp_checker = None  # Continue without HIBP
```

### 5. Performance by Design

Built for large-scale audits:

- Parallel domain processing
- In-memory caching (HIBP, BloodHound)
- Indexed lookups (HIBP binary search)
- Batch processing (BloodHound queries)

## Module Architecture

### Core Analysis Modules

#### Password Analysis (`core/password_analysis.py`)

**Purpose**: Analyze individual password characteristics

**Key Functions**:
```python
def analyze_password(password: str, wordlists: dict) -> dict:
    """Main entry point for password analysis."""
    return {
        'complexity': assess_complexity(password),
        'length': len(password),
        'patterns': detect_patterns(password),
        'dictionary': check_dictionary(password, wordlists),
        'similarity': calculate_similarity(password, other_passwords)
    }
```

**Dependencies**:
- Word lists (forbidden, dictionary, common)
- Other domain passwords (for similarity)

**Output**: Analysis dictionary for scoring

#### Domain Analysis (`core/domain_analysis.py`)

**Purpose**: Domain-level analysis and cross-domain detection

**Key Functions**:
```python
def analyze_domain(accounts: list, domain_name: str) -> DomainMetadata:
    """Analyze all accounts in a domain."""
    pass

def find_shared_passwords(domains: dict) -> dict:
    """Find passwords shared across domains."""
    pass

def find_shared_hashes(domains: dict) -> dict:
    """Find identical hashes across domains."""
    pass
```

**Responsibilities**:
- Aggregate domain statistics
- Detect password/hash sharing
- Calculate domain risk level

#### Scoring Engine (`core/scoring.py`)

**Purpose**: CVSS-style three-component risk scoring

**Architecture**:
```
Base Score
    ↓ (temporal factors)
Temporal Score
    ↓ (environmental factors)
Environmental Score = Final Score
    ↓ (threshold mapping)
Risk Level (Low/Medium/High/Critical)
```

**Key Functions**:
```python
def calculate_base_score(password: str, analysis: dict, hibp_tier: int) -> float:
    """Calculate base score (0-10) from password intrinsics."""
    pass

def calculate_temporal_score(base: float, age: int, policy: dict) -> float:
    """Apply temporal factors to base score."""
    pass

def calculate_environmental_score(
    temporal: float,
    privilege_factor: float,
    sharing_factor: float,
    domain_factor: float,
    hibp_factor: float
) -> float:
    """Apply environmental factors to temporal score."""
    pass

def determine_risk_level(score: float, has_da_path: bool) -> str:
    """Map score to risk level (Critical/High/Medium/Low)."""
    pass
```

**Scoring Components**:

1. **Base Score Factors**:
   - Complexity: Character sets (0.0-2.0)
   - Length: Password length (0.0-1.0)
   - Dictionary: Dictionary/common words (0.0-2.0)
   - Similarity: Similar to other passwords (0.0-1.0)
   - HIBP Tier: Breach tier (0.0-10.0 direct contribution)

2. **Temporal Factors**:
   - Age: Days since change (1.0-1.5x multiplier)
   - Policy: Compliance (0.9-1.3x multiplier)
   - Expiration: Never expires (1.3x multiplier)

3. **Environmental Factors**:
   - Privilege: DA pathway, controlled objects (1.0-2.0x)
   - Sharing: Password reuse count (1.0-1.5x)
   - Domain Risk: Domain classification (1.0-1.3x)
   - HIBP: Breach count (1.0-1.5x)

### Integration Modules

#### BloodHound Integration (`core/bloodhound_integration.py`)

**Architecture**:
```
BloodHoundClient (API wrapper)
    ↓
BloodHoundEnricher (orchestration)
    ↓ (parallel queries)
Account enrichment with AD data
```

**Key Classes**:
```python
class BloodHoundClient:
    """Low-level BloodHound API client."""

    def __init__(self, config: dict):
        self.base_url = f"{config['scheme']}://{config['domain']}:{config['port']}"
        self.session = self._create_session(config)

    def search_user(self, username: str) -> Optional[dict]:
        """Search for user by UPN."""
        pass

    def query_da_pathways(self, user_id: str) -> bool:
        """Check if user has DA pathway."""
        pass

    def query_controllables(self, user_id: str, limit: int) -> int:
        """Get count of controlled objects."""
        pass


class BloodHoundEnricher:
    """High-level account enrichment orchestrator."""

    def __init__(self, client: BloodHoundClient):
        self.client = client
        self.cache = {}  # Avoid duplicate queries

    def enrich_accounts(self, accounts: list) -> list:
        """Enrich all accounts with BloodHound data."""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._enrich_account, acc): acc
                for acc in accounts
            }
            # Process results
        return enriched_accounts
```

**Caching Strategy**:
- Cache search results by username
- Cache DA pathway results by user_id
- Cache controllables by user_id
- Prevents redundant API calls

**Error Handling**:
- Retry with exponential backoff
- Fallback to defaults if API unavailable
- Log failures but continue processing

#### HIBP Correlation (`core/hibp_correlation.py`)

**Architecture**:
```
HIBPChecker
    ├─ In-Memory Cache (top N hashes)
    ├─ Index File (prefix → offset mapping)
    └─ Database File (42GB NTLM hashes)
```

**Three-Tier Lookup**:
```python
class HIBPChecker:
    """HIBP hash lookup with three-tier architecture."""

    def __init__(self, config: dict):
        self.hash_file = Path(config['ntlm_hash_file'])
        self.cache_size = config.get('cache_size', 1_000_000)

        # Tier 1: In-memory cache
        self.hash_cache = self._load_top_n_hashes(self.cache_size)

        # Tier 2: Index file
        self.index = self._load_or_build_index()

    def check_ntlm_hash(self, ntlm_hash: str) -> tuple[bool, int]:
        """Check if hash is in HIBP database.

        Returns:
            Tuple of (is_breached, breach_count)
        """
        # Tier 1: Check cache (<1ms)
        if ntlm_hash in self.hash_cache:
            return True, self.hash_cache[ntlm_hash]

        # Tier 2: Binary search using index (10-50ms)
        prefix = ntlm_hash[:5]
        if prefix in self.index:
            start_offset, end_offset = self.index[prefix]
            # Tier 3: Sequential search in range
            count = self._search_file_range(ntlm_hash, start_offset, end_offset)
            if count:
                return True, count

        return False, 0
```

**Index Structure**:
```
{
    "00000": (0, 2048),           # Lines 0-2048
    "00001": (2049, 4096),        # Lines 2049-4096
    ...
    "FFFFF": (41943040, 41943552) # Last range
}
```

**Performance**:
- Cache hit: <1ms (instant)
- Index hit: 10-50ms (binary search + sequential scan ~2000 lines)
- Miss: 10-50ms (binary search confirms absence)

### Data Models

#### Account Model (`models/account.py`)

```python
@dataclass
class Account:
    """Represents a user account."""
    username: str
    domain: str
    ntlm_hash: str
    password: Optional[str] = None

    # BloodHound data
    has_da_path: bool = False
    da_domains: list = field(default_factory=list)
    controlled_objects: int = 0
    enabled: bool = True
    last_logon: Optional[datetime] = None
    password_age_days: Optional[int] = None
    password_expires: Optional[datetime] = None

    # Analysis results
    analysis: Optional[dict] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    risk_vector: Optional[str] = None
```

#### Password Model (`models/password.py`)

```python
@dataclass
class PasswordAnalysis:
    """Results of password analysis."""
    complexity_label: str
    char_sets: list
    length: int
    dictionary_word: bool
    common_password: bool
    forbidden_words: list
    keyboard_pattern: bool
    similar_passwords: int
    similarity_score: float
```

### Report Generation Pipeline

#### Report Architecture

```
Domain Analysis Results
    ↓
Visualization Generation (Plotly)
    ↓
┌─────────┬─────────┬─────────┬─────────┐
│  HTML   │  Excel  │   CSV   │Markdown │
│(CoreUI) │(openpyxl│(stdlib) │(stdlib) │
└─────────┴─────────┴─────────┴─────────┘
    ↓
PDF Generation (Pandoc, optional)
```

#### HTML Report Generation (`report_lib/standalone_html/`)

**Architecture**:
```
generate_html_report()
    ↓
┌──────────────┬──────────────┬──────────────┐
│  Components  │    Styles    │   Scripts    │
│ (HTML parts) │    (CSS)     │ (JavaScript) │
└──────────────┴──────────────┴──────────────┘
    ↓
Single-file HTML (no external dependencies)
```

**Key Features**:
- **Standalone**: All CSS/JS embedded
- **CoreUI 5**: Modern Bootstrap-based framework
- **Plotly**: Interactive charts embedded as JSON
- **FlexSearch**: Client-side search (no server needed)
- **Dark Mode**: CSS variable-based theming

**Components**:
```python
# report_lib/standalone_html/components.py
def generate_navbar(domain_name: str) -> str:
    """Generate CoreUI navigation bar."""
    pass

def generate_sidebar(sections: list) -> str:
    """Generate sidebar navigation."""
    pass

def generate_data_table(data: list, columns: list) -> str:
    """Generate responsive data table."""
    pass

def generate_chart_container(chart_json: str, chart_id: str) -> str:
    """Generate Plotly chart container."""
    pass
```

**Data Embedding**:
```javascript
// Embed password data as JSON
<script>
const passwordData = {{ password_data_json }};
const searchIndex = new FlexSearch.Document({
    tokenize: "forward",
    document: {
        id: "username",
        index: ["username", "password", "risk_level"]
    }
});
searchIndex.add(passwordData);
</script>
```

## Data Flow

### Single Domain Audit Flow

```
1. User runs: python main.py -d "CORP:cracked.txt:uncracked.txt"
    ↓
2. cli.py parses arguments
    ↓
3. processor.py orchestrates:
    ├─ Load word lists (forbidden, dictionary, common)
    ├─ Load configuration (BloodHound, HIBP, policy)
    └─ Call process_single_domain()
        ↓
4. Parse input files (data.py)
    ├─ Parse cracked.txt → accounts with passwords
    ├─ Parse uncracked.txt → accounts with hashes only
    └─ Create Account objects
        ↓
5. BloodHound enrichment (parallel)
    ├─ Search for each account
    ├─ Query DA pathways
    ├─ Query controlled objects
    └─ Extract account properties
        ↓
6. Password analysis (parallel)
    ├─ For each password:
    │   ├─ Assess complexity
    │   ├─ Check dictionary
    │   ├─ Detect patterns
    │   ├─ Check HIBP
    │   └─ Calculate similarity
    ↓
7. Risk scoring (sequential)
    ├─ Calculate base score
    ├─ Apply temporal factors
    ├─ Apply environmental factors
    └─ Determine risk level
        ↓
8. Generate visualizations
    ├─ Risk distribution charts
    ├─ Complexity analysis
    ├─ Password sharing networks
    └─ Export as Plotly JSON
        ↓
9. Generate reports (parallel)
    ├─ HTML (standalone with embedded data)
    ├─ Excel (prioritized sheets)
    ├─ CSV (raw data export)
    ├─ Markdown (detailed analysis)
    └─ PDF (if pandoc installed)
        ↓
10. Save to reports/DOMAIN-TIMESTAMP/
    └─ Update reports/latest symlink
```

### Multi-Domain Audit Flow

```
1. User runs with multiple domains
    ↓
2. processor.py creates process pool
    ↓
3. For each domain (in parallel):
    ├─ process_single_domain()
    └─ Return domain results
        ↓
4. Collect all domain results
    ↓
5. Cross-domain analysis:
    ├─ Find shared passwords
    ├─ Find shared hashes
    ├─ Identify lateral movement risks
    └─ Calculate combined metrics
        ↓
6. Generate combined reports:
    ├─ Combined HTML dashboard
    ├─ Combined Excel report
    ├─ Combined CSV export
    └─ Combined Markdown report
```

## Performance Considerations

### Parallel Processing

**Domain-Level Parallelism**:
```python
# processor.py
with ProcessPoolExecutor(max_workers=cpu_count) as executor:
    futures = {
        executor.submit(process_single_domain, domain_spec): domain_spec
        for domain_spec in domains
    }
    results = [future.result() for future in as_completed(futures)]
```

**Account-Level Parallelism** (within domain):
```python
# bloodhound_integration.py
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = {executor.submit(enrich_account, acc): acc for acc in accounts}
    enriched = [future.result() for future in as_completed(futures)]
```

### Caching Strategies

**BloodHound Cache**:
- Key: username (UPN)
- Value: BloodHound data
- Lifetime: Per audit run
- Size: Unlimited (one audit run)

**HIBP Cache**:
- Key: NTLM hash
- Value: breach count
- Lifetime: Until process exit
- Size: Configurable (default 1M hashes = ~50MB)

### Memory Management

**Memory Usage**:
- Base tool: ~100MB
- Word lists: ~50MB
- HIBP cache: ~50MB (1M hashes)
- BloodHound cache: ~10MB (typical)
- Visualizations: ~20MB
- **Total**: ~230MB for typical audit

**Large Audits** (100K+ accounts):
- Use `enable_animation: false` for max parallelism
- Increase HIBP cache if RAM available
- Consider batch processing domains

### I/O Optimization

**HIBP Database**:
- SSD vs HDD: 10x performance difference
- Sequential reads: Optimized with index
- Cache reduces file I/O by 90%+

**Report Generation**:
- Parallel report writing (different formats)
- Buffered file writes
- Lazy JSON serialization

## Design Decisions

### Why CVSS-Style Scoring?

**Problem**: Need standardized, reproducible risk scores

**Solution**: Three-component scoring (Base/Temporal/Environmental)

**Benefits**:
- Industry-standard methodology
- Clear score breakdown
- Temporal factors handle password aging
- Environmental factors include organizational context

### Why Standalone HTML Reports?

**Problem**: Users don't want to run servers

**Solution**: Single-file HTML with embedded data/scripts

**Benefits**:
- No dependencies (opens in any browser)
- No server required
- Portable (email, USB, etc.)
- Fast (client-side search <100ms)

**Trade-offs**:
- Large file size (10-50MB for big audits)
- No real-time updates

### Why Three-Tier HIBP Lookup?

**Problem**: 42GB database, billions of lookups needed

**Solution**: Cache + Index + File

**Benefits**:
- Cache: 90%+ hit rate, instant
- Index: Fast binary search
- File: Only for cache misses

**Trade-offs**:
- Initial index build: 5-10 minutes
- Memory usage: 50-500MB (configurable)

### Why Parallel Domain Processing?

**Problem**: Multi-domain audits are slow

**Solution**: Process domains in parallel

**Benefits**:
- Linear speedup with CPU cores
- Efficient resource utilization
- Faster time to results

**Trade-offs**:
- Higher memory usage (N × single domain)
- Animation limited to 4 workers

### Why JSON Configuration?

**Problem**: Need flexible, secure configuration

**Solution**: External JSON files

**Benefits**:
- No code changes for config
- Easy to version control
- Environment-specific configs
- Secure (can exclude from git)

**Alternative Considered**: Environment variables
**Why JSON**: Better structure for complex configs (policies, lists)

## Related Documentation

- [Development Guide](DEVELOPMENT.md) - Contributing
- [API Reference](API_REFERENCE.md) - Module documentation
- [Configuration Guide](CONFIGURATION.md) - Config options
- [Scoring System](SCORING_SYSTEM.md) - Scoring details

---

**Architecture Questions?** Open an issue or discussion on GitHub.
