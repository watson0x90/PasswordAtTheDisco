# Development Guide

Guide for developers contributing to Password!AtTheDisco.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Adding Features](#adding-features)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)

## Getting Started

### Prerequisites

- Python 3.9+ (3.11+ recommended for development)
- Git
- Text editor or IDE (VS Code, PyCharm recommended)
- Virtual environment tool (venv, conda, or virtualenv)

### Setting Up Development Environment

**1. Fork and Clone**:
```bash
# Fork the repository on GitHub first
git clone https://github.com/YOUR_USERNAME/PasswordAtTheDisco.git
cd PasswordAtTheDisco

# Add upstream remote
git remote add upstream https://github.com/watson0x90/PasswordAtTheDisco.git
```

**2. Create Virtual Environment**:
```bash
# Using venv
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
.\\venv\\Scripts\\activate  # Windows

# Using conda
conda create -n patd-dev python=3.11
conda activate patd-dev
```

**3. Install Dependencies**:
```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt  # If exists
# Or manually:
pip install pytest pytest-cov black flake8 mypy
```

**4. Configure Development Settings**:
```bash
# Copy example configs
cp config/bloodhound.json.example config/bloodhound.json
cp config/hibp.json.example config/hibp.json
cp config/hashcat.json.example config/hashcat.json
cp config/application.json.example config/application.json

# Edit with your development credentials
# For BloodHound, you can use a local test instance
```

**5. Verify Setup**:
```bash
# Run tests (if available)
pytest

# Try running the tool
python main.py --help
python main.py --test-bh
```

## Development Environment

### Recommended IDE Setup

**VS Code**:
```json
// .vscode/settings.json
{
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": ["--line-length=100"],
    "editor.formatOnSave": true,
    "python.testing.pytestEnabled": true,
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true
    }
}
```

**PyCharm**:
- Set interpreter to virtual environment
- Enable Black formatter (Settings → Tools → Black)
- Configure pytest as test runner
- Mark `core/`, `models/`, `utils/` as source roots

### Git Configuration

**Branch Strategy**:
```bash
# Main branch (stable releases)
main

# Development branch
develop

# Feature branches
feature/your-feature-name

# Bug fix branches
fix/issue-description

# Documentation branches
docs/what-you-are-documenting
```

**Commit Message Convention**:
```
type(scope): subject

body (optional)

footer (optional)
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```bash
feat(scoring): add HIBP tier-based environmental multiplier

Implements 7-tier HIBP categorization with environmental score
multipliers ranging from 1.0x (not breached) to 1.5x (100k+ breaches).

Closes #42
```

```bash
fix(bloodhound): handle missing controllables gracefully

When BloodHound API returns no controllables, default to 0 instead
of raising KeyError.

Fixes #38
```

## Project Structure

### Module Organization

```
PasswordAtTheDisco/
├── main.py                    # Entry point
├── cli.py                     # CLI argument parsing
├── processor.py               # Main orchestration
│
├── core/                      # Core analysis modules
│   ├── config.py              # Configuration management
│   ├── data.py                # Data loading and parsing
│   ├── domain_analysis.py     # Domain-level analysis
│   ├── password_analysis.py   # Password-level analysis
│   ├── scoring.py             # Risk scoring engine
│   ├── vector.py              # Risk vector generation
│   ├── bloodhound_integration.py  # BloodHound API client
│   ├── hashcat_integration.py     # Hashcat automation
│   └── hibp_correlation.py    # HIBP lookup
│
├── models/                    # Data models
│   ├── account.py             # Account data structures
│   ├── password.py            # Password analysis models
│   ├── domain.py              # Domain metadata
│   └── risk.py                # Risk scoring models
│
├── report_lib/                # Report generation
│   ├── csv/                   # CSV export
│   ├── excel/                 # Excel reports
│   ├── markdown/              # Markdown reports
│   ├── standalone_html/       # HTML reports (CoreUI 5)
│   └── sqlite/                # SQLite database (experimental)
│
├── visualizations/            # Chart generation
│   ├── core.py                # Visualization orchestration
│   ├── charts.py              # Standard charts (Plotly)
│   ├── networks.py            # Network graphs
│   ├── risk.py                # Risk visualizations
│   └── cross_domain_attacks.py # Attack path visualizations
│
├── utils/                     # Utility modules
│   ├── logging.py             # Logging configuration
│   ├── file_utils.py          # File operations
│   ├── terminal_animation.py  # Progress animation
│   └── branding.py            # ASCII art branding
│
├── lists/                     # Word lists and policies
│   ├── forbidden_words.txt
│   ├── common_passwords.txt
│   ├── dictionary_words.txt
│   ├── keyboard_patterns.txt
│   └── password_policy.json
│
├── config/                    # Configuration files
│   ├── bloodhound.json
│   ├── hibp.json
│   ├── hashcat.json
│   └── application.json
│
└── docs/                      # Documentation
    ├── README.md
    ├── GETTING_STARTED.md
    ├── INSTALLATION.md
    ├── USER_GUIDE.md
    └── ...
```

### Key Modules

**Entry Points**:
- `main.py:main()` - Sets up logging, calls processor
- `processor.py:process_domains()` - Orchestrates entire workflow
- `cli.py:parse_arguments()` - Parses command-line arguments

**Core Analysis**:
- `password_analysis.py:analyze_password()` - Single password analysis
- `domain_analysis.py:analyze_domain()` - Domain-wide analysis
- `scoring.py:calculate_risk_score()` - CVSS-style scoring
- `vector.py:generate_risk_vector()` - Vector string generation

**Integrations**:
- `bloodhound_integration.py:BloodHoundClient` - API wrapper
- `hibp_correlation.py:HIBPChecker` - Hash lookup with caching
- `hashcat_integration.py:HashcatRunner` - Automation wrapper

**Report Generation**:
- `report_lib/standalone_html/report.py:generate_html_report()`
- `report_lib/excel/report.py:generate_actionable_report()`
- `report_lib/csv/report.py:generate_csv_report()`

## Coding Standards

### Python Style Guide

Follow **PEP 8** with these specific guidelines:

**Line Length**: 100 characters (not 79)
```python
# Good
def calculate_environmental_score(
    base_score, privilege_factor, sharing_factor, domain_factor, hibp_factor
):
    pass

# Bad (exceeds 100 chars)
def calculate_environmental_score(base_score, privilege_factor, sharing_factor, domain_factor, hibp_factor):
    pass
```

**Imports**: Organized in groups
```python
# Standard library
import os
import sys
from pathlib import Path

# Third-party
import requests
from plotly import graph_objects as go

# Local
from core.config import BHE_CONFIG
from models.account import Account
from utils.logging import get_logger
```

**Type Hints**: Use where helpful
```python
def calculate_risk_score(
    password: str,
    account: Account,
    domain_metadata: dict
) -> tuple[float, str, dict]:
    """Calculate risk score for password.

    Args:
        password: Plaintext password
        account: Account object with BloodHound data
        domain_metadata: Domain-level metadata

    Returns:
        Tuple of (score, risk_level, breakdown)
    """
    pass
```

**Docstrings**: Google style
```python
def analyze_password(password: str, wordlists: dict) -> dict:
    """Analyze password complexity and patterns.

    Performs comprehensive analysis including complexity assessment,
    dictionary word detection, pattern matching, and similarity analysis.

    Args:
        password: Plaintext password to analyze
        wordlists: Dictionary containing loaded word lists:
            - forbidden_words: Set of banned words
            - dictionary: Set of dictionary words
            - common_passwords: Set of common passwords
            - keyboard_patterns: List of keyboard patterns

    Returns:
        Dictionary containing analysis results:
            - complexity: Complexity label (Best/Better/Good/etc.)
            - length: Password length
            - char_sets: List of character sets present
            - dictionary_word: Boolean indicating dictionary word
            - common_password: Boolean indicating common password
            - forbidden_words: List of forbidden words found
            - keyboard_pattern: Boolean indicating keyboard pattern

    Example:
        >>> wordlists = load_wordlists()
        >>> result = analyze_password("Password123!", wordlists)
        >>> print(result['complexity'])
        'Low'
    """
    pass
```

**Error Handling**: Explicit and informative
```python
# Good
try:
    data = load_file(filepath)
except FileNotFoundError:
    logger.error(f"File not found: {filepath}")
    raise
except json.JSONDecodeError as e:
    logger.error(f"Invalid JSON in {filepath}: {e}")
    return None

# Bad
try:
    data = load_file(filepath)
except Exception:
    pass  # Silent failure
```

**Logging**: Use appropriate levels
```python
from utils.logging import get_logger

logger = get_logger(__name__)

# Debug: Detailed diagnostic information
logger.debug(f"Processing account: {username}")

# Info: Informational messages
logger.info(f"Loaded {count} accounts from {filename}")

# Warning: Warning messages (recoverable issues)
logger.warning(f"BloodHound query failed for {username}, using defaults")

# Error: Error messages (serious issues)
logger.error(f"Failed to parse file {filename}: {error}")

# Critical: Critical issues (application crash)
logger.critical(f"Database file missing: {filepath}")
```

### Code Formatting

**Black**: Automatic formatter
```bash
# Format single file
black core/scoring.py

# Format entire project
black .

# Check without modifying
black --check .
```

**Flake8**: Linter
```bash
# Run linter
flake8 core/ models/ utils/

# Configuration in .flake8 or setup.cfg
[flake8]
max-line-length = 100
exclude = .git,__pycache__,venv
ignore = E203,W503  # Black compatibility
```

**isort**: Import sorting
```bash
# Sort imports
isort core/ models/ utils/

# Configuration in .isort.cfg
[isort]
profile = black
line_length = 100
```

## Testing

### Test Structure

```
tests/
├── test_scoring.py           # Scoring engine tests
├── test_password_analysis.py # Password analysis tests
├── test_vector.py            # Risk vector tests
├── test_bloodhound.py        # BloodHound integration tests
├── test_hibp.py              # HIBP integration tests
└── fixtures/                 # Test data
    ├── sample_cracked.txt
    ├── sample_uncracked.txt
    └── mock_bloodhound.json
```

### Writing Tests

**Unit Tests**: Test individual functions
```python
import pytest
from core.scoring import calculate_complexity_factor

def test_complexity_factor_all_charsets():
    """Test complexity factor with all character sets."""
    password = "Abc123!@#"
    factor = calculate_complexity_factor(password)
    assert factor == 0.0  # Best complexity

def test_complexity_factor_lowercase_only():
    """Test complexity factor with lowercase only."""
    password = "abcdefgh"
    factor = calculate_complexity_factor(password)
    assert factor == 2.0  # Low complexity
```

**Integration Tests**: Test module interactions
```python
def test_end_to_end_analysis():
    """Test complete password analysis workflow."""
    from core.password_analysis import analyze_password
    from core.scoring import calculate_risk_score

    wordlists = load_test_wordlists()
    account = create_test_account()

    analysis = analyze_password("Password123!", wordlists)
    score, level, breakdown = calculate_risk_score(
        "Password123!", account, {}, analysis
    )

    assert score >= 7.0  # High risk
    assert level == "High" or level == "Critical"
    assert "dictionary" in breakdown
```

**Fixtures**: Reusable test data
```python
@pytest.fixture
def sample_wordlists():
    """Load sample word lists for testing."""
    return {
        'forbidden_words': {'password', 'admin', 'test'},
        'dictionary': {'hello', 'world'},
        'common_passwords': {'Password123', 'Welcome1'},
        'keyboard_patterns': ['qwerty', 'asdfgh']
    }

@pytest.fixture
def mock_bloodhound_data():
    """Mock BloodHound API response."""
    return {
        'username': 'test@CORP.INT',
        'has_da_path': True,
        'controlled_objects': 234,
        'enabled': True
    }
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scoring.py

# Run specific test
pytest tests/test_scoring.py::test_complexity_factor_all_charsets

# Run with coverage
pytest --cov=core --cov=models --cov-report=html

# Run with verbose output
pytest -v

# Run only fast tests (skip integration)
pytest -m "not integration"
```

## Adding Features

### Feature Development Workflow

**1. Create Feature Branch**:
```bash
git checkout develop
git pull upstream develop
git checkout -b feature/your-feature-name
```

**2. Implement Feature**:
- Write code following coding standards
- Add type hints and docstrings
- Add logging statements
- Handle errors gracefully

**3. Add Tests**:
- Write unit tests for new functions
- Write integration tests if needed
- Ensure >80% code coverage

**4. Update Documentation**:
- Update relevant docs in `docs/`
- Add code comments
- Update CHANGELOG.md

**5. Test Locally**:
```bash
# Run tests
pytest

# Run linters
black --check .
flake8 core/ models/ utils/

# Test with real data
python main.py -d "TEST:test_cracked.txt:test_uncracked.txt"
```

**6. Commit and Push**:
```bash
git add .
git commit -m "feat(scope): description"
git push origin feature/your-feature-name
```

**7. Create Pull Request**:
- Open PR against `develop` branch
- Fill out PR template
- Link related issues
- Request review

### Example: Adding a New Risk Factor

**1. Update Scoring Module** (`core/scoring.py`):
```python
def calculate_new_risk_factor(password: str, account: Account) -> float:
    """Calculate new risk factor.

    Args:
        password: Plaintext password
        account: Account object

    Returns:
        Risk factor multiplier (1.0-2.0)
    """
    # Your logic here
    if some_condition:
        return 1.5
    return 1.0
```

**2. Integrate into Scoring**:
```python
def calculate_environmental_score(
    temporal_score: float,
    privilege_factor: float,
    sharing_factor: float,
    domain_factor: float,
    hibp_factor: float,
    new_factor: float  # Add new parameter
) -> float:
    """Calculate environmental score."""
    combined_factor = (
        privilege_factor *
        sharing_factor *
        domain_factor *
        hibp_factor *
        new_factor  # Include new factor
    )
    return temporal_score * combined_factor
```

**3. Update Vector Generation** (`core/vector.py`):
```python
def generate_risk_vector(..., new_value: str) -> str:
    """Generate risk vector string."""
    components = [
        # ... existing components
        f"NEW:{new_value}"
    ]
    return "/".join(components)
```

**4. Add Tests** (`tests/test_scoring.py`):
```python
def test_new_risk_factor():
    """Test new risk factor calculation."""
    account = create_test_account()
    factor = calculate_new_risk_factor("test", account)
    assert 1.0 <= factor <= 2.0
```

**5. Update Documentation**:
- Add to `docs/SCORING_SYSTEM.md`
- Add example to `docs/SCORING_EXAMPLES.md`
- Update `docs/API_REFERENCE.md`

## Documentation

### Documentation Standards

**Markdown Files**:
- Use GitHub Flavored Markdown
- Include table of contents for long docs
- Use code fences with language specifiers
- Include practical examples
- Cross-reference related docs

**Code Comments**:
```python
# Good: Explain WHY, not WHAT
# Use cache to avoid redundant BloodHound queries for same account
if username in cache:
    return cache[username]

# Bad: Obvious comment
# Check if username is in cache
if username in cache:
    return cache[username]
```

**README Updates**:
- Update main README.md for significant features
- Keep feature list current
- Update screenshots if UI changes

### Building Documentation

```bash
# Generate API documentation (if using Sphinx)
cd docs
make html

# Preview locally
python -m http.server 8000 -d docs/_build/html
```

## Pull Request Process

### Before Submitting

**Checklist**:
- [ ] Code follows project coding standards
- [ ] All tests pass locally
- [ ] New code has tests (>80% coverage)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Commit messages follow convention
- [ ] Branch is up to date with develop

**Run Full Test Suite**:
```bash
# Format code
black .

# Sort imports
isort .

# Run linters
flake8 core/ models/ utils/

# Run tests with coverage
pytest --cov=core --cov=models --cov-report=term-missing

# Test on real data
python main.py -d "TEST:test_cracked.txt:test_uncracked.txt"
```

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Testing
Describe testing performed:
- Unit tests added/updated
- Integration tests added/updated
- Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added and passing
- [ ] CHANGELOG.md updated

## Related Issues
Closes #(issue number)
```

### Review Process

**What Reviewers Look For**:
1. Code quality and style compliance
2. Test coverage and quality
3. Documentation completeness
4. Performance implications
5. Security considerations
6. Breaking changes

**Addressing Feedback**:
```bash
# Make requested changes
git add .
git commit -m "fix: address review feedback"
git push origin feature/your-feature-name

# PR automatically updates
```

### Merging

**After Approval**:
1. Squash commits if many small commits
2. Update commit message if needed
3. Merge to develop (maintainer does this)
4. Delete feature branch
5. Pull latest develop

```bash
git checkout develop
git pull upstream develop
git branch -d feature/your-feature-name
```

## Related Documentation

- [Architecture Guide](ARCHITECTURE.md) - System design
- [API Reference](API_REFERENCE.md) - Module reference
- [Configuration Guide](CONFIGURATION.md) - Config options
- [User Guide](USER_GUIDE.md) - Usage documentation

---

**Questions?** Open an issue or discussion on GitHub.
