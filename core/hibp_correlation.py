"""
HaveIBeenPwned (HIBP) Correlation Module

This module provides integration with the HaveIBeenPwned NTLM hash database to:
- Check if cracked passwords have been exposed in breaches
- Provide breach frequency information
- Enhance risk scoring based on breach exposure
- Generate breach correlation reports

Usage:
    from core.hibp_correlation import HIBPChecker

    checker = HIBPChecker()
    is_breached, count = checker.check_ntlm_hash('8846F7EAEE8FB117AD06BDD830B7586C')
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.config import HIBP_CONFIG
from utils.logging import get_logger

logger = get_logger('hibp')


def plaintext_to_ntlm(password: str) -> str:
    """
    Convert a plaintext password to NTLM hash.

    NTLM hashing uses MD4 hash of UTF-16LE encoded password.

    Args:
        password: Plaintext password string

    Returns:
        NTLM hash as uppercase hexadecimal string (32 characters)

    Examples:
        >>> plaintext_to_ntlm("Password123!")
        '2B576ACBE6BCFDA7294D6BD18041B8FE'
    """
    try:
        # Use passlib (recommended - works with Python 3.11+)
        from passlib.hash import nthash
        return nthash.hash(password).upper()
    except ImportError:
        # Fallback: Pure Python MD4 implementation
        import struct

        def md4(data):
            """Pure Python MD4 implementation for NTLM hashing."""
            # MD4 Constants
            K = [0x00000000, 0x5A827999, 0x6ED9EBA1]

            # MD4 Helper functions
            def F(x, y, z): return (x & y) | (~x & z)
            def G(x, y, z): return (x & y) | (x & z) | (y & z)
            def H(x, y, z): return x ^ y ^ z

            def ROTLEFT(value, shift):
                return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

            # Initialize MD4 state
            A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

            # Pre-processing
            msg_len = len(data)
            data += b'\x80'
            data += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
            data += struct.pack('<Q', msg_len * 8)

            # Process message in 512-bit chunks
            for offset in range(0, len(data), 64):
                X = list(struct.unpack('<16I', data[offset:offset+64]))
                AA, BB, CC, DD = A, B, C, D

                # Round 1
                indices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                shifts = [3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19]
                for i in range(16):
                    k = indices[i]
                    s = shifts[i]
                    A = ROTLEFT((A + F(B, C, D) + X[k] + K[0]) & 0xFFFFFFFF, s)
                    A, B, C, D = D, A, B, C

                # Round 2
                indices = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
                shifts = [3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13]
                for i in range(16):
                    k = indices[i]
                    s = shifts[i]
                    A = ROTLEFT((A + G(B, C, D) + X[k] + K[1]) & 0xFFFFFFFF, s)
                    A, B, C, D = D, A, B, C

                # Round 3
                indices = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
                shifts = [3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15]
                for i in range(16):
                    k = indices[i]
                    s = shifts[i]
                    A = ROTLEFT((A + H(B, C, D) + X[k] + K[2]) & 0xFFFFFFFF, s)
                    A, B, C, D = D, A, B, C

                # Add this chunk's hash to result so far
                A = (A + AA) & 0xFFFFFFFF
                B = (B + BB) & 0xFFFFFFFF
                C = (C + CC) & 0xFFFFFFFF
                D = (D + DD) & 0xFFFFFFFF

            # Produce the final hash
            return struct.pack('<4I', A, B, C, D)

        # NTLM uses MD4 of UTF-16LE encoded password
        utf16le_password = password.encode('utf-16le')
        hash_bytes = md4(utf16le_password)
        return hash_bytes.hex().upper()


@dataclass
class BreachInfo:
    """Information about a password breach."""
    ntlm_hash: str
    breach_count: int
    is_breached: bool


class HIBPChecker:
    """Check NTLM hashes against HaveIBeenPwned database."""

    def __init__(self, hibp_file: Optional[Path] = None, cache_size: int = None, enable_index: bool = True):
        """
        Initialize HIBP checker.

        Args:
            hibp_file: Path to HIBP NTLM hash file (uses config default if None)
            cache_size: Number of hashes to cache (uses config default if None)
            enable_index: Enable indexed file search for cache misses (default: True)
        """
        self.hibp_file = hibp_file or HIBP_CONFIG["NTLM_HASH_FILE"]
        self.cache_size = cache_size or HIBP_CONFIG.get("CACHE_SIZE", 1000000)
        self.enable_index = enable_index

        # Hash cache: {hash: count}
        self.hash_cache = {}

        # Index for binary search
        self.index = []
        self.indexer = None

        # Statistics
        self.total_hashes = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.file_lookups = 0
        self.index_lookups = 0

        # Check if file exists
        if not self.hibp_file.exists():
            logger.warning(f"HIBP file not found at {self.hibp_file}")
            self.enabled = False
        else:
            self.enabled = HIBP_CONFIG.get("ENABLE_LOOKUP", True)
            if self.enabled:
                self._load_cache()
                if self.enable_index:
                    self._initialize_index()

    def _load_cache(self) -> None:
        """Load frequently breached hashes into memory cache."""
        logger.info(f"Loading HIBP hash cache from {self.hibp_file}...")

        try:
            loaded = 0

            with open(self.hibp_file, 'r') as f:
                for line in f:
                    if loaded >= self.cache_size:
                        break

                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split(':')
                    if len(parts) == 2:
                        hash_value, count = parts
                        self.hash_cache[hash_value.upper()] = int(count)
                        loaded += 1

            self.total_hashes = loaded
            logger.info(f"Loaded {loaded:,} HIBP hashes into cache")

        except Exception as e:
            logger.error(f"Error loading HIBP cache: {e}")
            self.enabled = False

    def _initialize_index(self) -> None:
        """Initialize or build the prefix-based index for fast lookups."""
        prefix_length = HIBP_CONFIG.get("PREFIX_LENGTH", 5)
        self.indexer = HIBPPrefixSearcher(self.hibp_file, prefix_length=prefix_length)

        # Try to load existing index
        self.index = self.indexer.load_index()

        # If index doesn't exist, build it
        if not self.index:
            logger.info(f"No prefix index found. Building {prefix_length}-character "
                        "prefix index (this may take 3-5 minutes)...")
            self.indexer.build_index()
            self.index = self.indexer.load_index()

        if self.index:
            logger.info(f"HIBP prefix index ready with {len(self.index):,} entries")

    def _binary_search_file(self, ntlm_hash: str) -> Tuple[bool, int]:
        """
        Search for a hash in the HIBP file using prefix-based index.

        Args:
            ntlm_hash: NTLM hash to search for (uppercase)

        Returns:
            Tuple of (is_breached, breach_count)
        """
        if not self.indexer or not self.index:
            return False, 0

        self.index_lookups += 1

        # Use the prefix searcher's efficient lookup
        try:
            is_breached, count = self.indexer.lookup_hash(ntlm_hash)

            if is_breached:
                self.file_lookups += 1
                # Add to cache for future lookups
                self.hash_cache[ntlm_hash] = count
                return True, count

        except Exception as e:
            logger.error(f"Error during prefix search: {e}")
            return False, 0

        return False, 0

    def check_ntlm_hash(self, ntlm_hash: str) -> Tuple[bool, int]:
        """
        Check if an NTLM hash exists in HIBP database.

        Args:
            ntlm_hash: NTLM hash to check (case-insensitive)

        Returns:
            Tuple of (is_breached, breach_count)
        """
        if not self.enabled:
            return False, 0

        ntlm_hash = ntlm_hash.upper()

        # Check cache first
        if ntlm_hash in self.hash_cache:
            self.cache_hits += 1
            return True, self.hash_cache[ntlm_hash]

        self.cache_misses += 1

        # Cache miss - use binary search if index is available
        if self.enable_index and self.index:
            return self._binary_search_file(ntlm_hash)

        # No index available, cannot search
        return False, 0

    def check_password_batch(self, accounts: List[Dict]) -> List[Dict]:
        """
        Check a batch of accounts for HIBP correlation.

        Args:
            accounts: List of account dictionaries with 'ntlm_hash' field

        Returns:
            List of accounts with added 'hibp_breached' and 'hibp_count' fields
        """
        if not self.enabled:
            return accounts

        enriched_accounts = []

        for account in accounts:
            ntlm_hash = account.get('hash') or account.get('ntlm_hash', '')

            if ntlm_hash:
                is_breached, count = self.check_ntlm_hash(ntlm_hash)

                account['hibp_breached'] = is_breached
                account['hibp_count'] = count
            else:
                account['hibp_breached'] = False
                account['hibp_count'] = 0

            enriched_accounts.append(account)

        return enriched_accounts

    def get_statistics(self) -> Dict:
        """
        Get HIBP checker statistics.

        Returns:
            Dictionary with statistics
        """
        total_checks = self.cache_hits + self.cache_misses

        return {
            'enabled': self.enabled,
            'cached_hashes': len(self.hash_cache),
            'index_entries': len(self.index) if self.index else 0,
            'total_checks': total_checks,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'index_lookups': self.index_lookups,
            'file_lookups': self.file_lookups,
            'cache_hit_rate': self.cache_hits / total_checks if total_checks > 0 else 0.0
        }

    def generate_breach_report(self, accounts: List[Dict]) -> Dict:
        """
        Generate a breach correlation report.

        Args:
            accounts: List of accounts with HIBP data

        Returns:
            Dictionary with breach statistics
        """
        breached_accounts = [acc for acc in accounts if acc.get('hibp_breached', False)]

        # Group by breach count
        breach_count_distribution = {}
        for account in breached_accounts:
            count = account.get('hibp_count', 0)

            # Categorize
            if count >= 10000:
                category = '10,000+'
            elif count >= 1000:
                category = '1,000-9,999'
            elif count >= 100:
                category = '100-999'
            elif count >= 10:
                category = '10-99'
            else:
                category = '1-9'

            breach_count_distribution[category] = breach_count_distribution.get(category, 0) + 1

        # Top breached accounts
        top_breached = sorted(
            breached_accounts,
            key=lambda x: x.get('hibp_count', 0),
            reverse=True
        )[:20]

        return {
            'total_accounts': len(accounts),
            'breached_accounts': len(breached_accounts),
            'breach_rate': len(breached_accounts) / len(accounts) if accounts else 0.0,
            'breach_count_distribution': breach_count_distribution,
            'top_breached': top_breached,
            'total_breach_exposure': sum(acc.get('hibp_count', 0) for acc in breached_accounts)
        }


class HIBPPrefixSearcher:
    """
    Efficient HIBP hash searcher using prefix-based indexing.

    Uses 5-character hex prefixes (00000-FFFFF) to create a 1M-entry
    index mapping prefixes to byte offsets in the sorted hash file.
    """

    def __init__(self, hibp_file: Path, prefix_length: int = 5):
        """
        Initialize HIBP prefix searcher.

        Args:
            hibp_file: Path to HIBP hash file
            prefix_length: Length of hash prefix to index (default: 5)
        """
        self.hibp_file = hibp_file
        self.prefix_length = prefix_length
        self.index_file = hibp_file.parent / f"{hibp_file.name}.index{prefix_length}"

        # Index: {prefix: byte_offset}
        self.index: Dict[str, int] = {}

    def build_index(self, progress_interval: int = 10000) -> None:
        """
        Build the prefix index by scanning through the hash file.

        This is a one-time operation that takes 3-5 minutes for a 43GB file.

        Args:
            progress_interval: Update progress every N lines (default: 10000)
        """
        logger.info(f"Building {self.prefix_length}-character prefix index for "
                    f"{self.hibp_file.name} (this will take approximately 3-5 minutes)...")

        current_prefix = None
        byte_offset = 0
        line_count = 0
        index_entries = {}

        try:
            with open(self.hibp_file, 'r', encoding='utf-8') as f:
                while True:
                    # Track position before reading line
                    line_start = byte_offset
                    line = f.readline()

                    if not line:
                        break

                    # Update byte offset
                    line_bytes = len(line.encode('utf-8'))
                    byte_offset += line_bytes
                    line_count += 1

                    # Extract hash (first part before ':')
                    hash_value = line.split(':')[0].upper()

                    if len(hash_value) < self.prefix_length:
                        continue

                    # Get prefix
                    prefix = hash_value[:self.prefix_length]

                    # New prefix encountered - record its starting position
                    if prefix != current_prefix:
                        index_entries[prefix] = line_start
                        current_prefix = prefix

                    # Progress update
                    if line_count % progress_interval == 0:
                        logger.debug(f"Processed {line_count:,} lines, "
                                     f"{len(index_entries):,} prefixes...")

            # Write index to file
            logger.info(f"Writing index to {self.index_file}...")
            with open(self.index_file, 'w') as f:
                for prefix in sorted(index_entries.keys()):
                    f.write(f"{prefix}:{index_entries[prefix]}\n")

            avg_lines_per_prefix = line_count // len(index_entries) if index_entries else 0

            logger.info(
                f"Index build complete: {line_count:,} lines processed, "
                f"{len(index_entries):,} prefixes indexed "
                f"(avg {avg_lines_per_prefix:,} lines/prefix) -> {self.index_file}"
            )

        except Exception as e:
            logger.error(f"Error building index: {e}")
            raise

    def load_index(self) -> Dict[str, int]:
        """
        Load the prefix index from file.

        Returns:
            Dictionary of {prefix: byte_offset}
        """
        if not self.index_file.exists():
            logger.warning(f"Index file not found: {self.index_file}. "
                           "Run build_index() first to create the index.")
            return {}

        try:
            with open(self.index_file, 'r') as f:
                for line in f:
                    prefix, offset = line.strip().split(':')
                    self.index[prefix] = int(offset)

            logger.info(f"Loaded prefix index with {len(self.index):,} entries")
            return self.index

        except Exception as e:
            logger.error(f"Error loading index: {e}")
            return {}

    def lookup_hash(self, ntlm_hash: str) -> Tuple[bool, int]:
        """
        Look up an exact NTLM hash in the database.

        Args:
            ntlm_hash: The NTLM hash to search for (32 hex characters)

        Returns:
            Tuple of (found, breach_count)
        """
        ntlm_hash = ntlm_hash.upper().strip()

        # Validate hash
        if len(ntlm_hash) != 32:
            return False, 0

        if not self.index:
            return False, 0

        # Get prefix and find starting position
        prefix = ntlm_hash[:self.prefix_length]

        if prefix not in self.index:
            # Prefix doesn't exist - hash not in database
            return False, 0

        # Get starting offset for this prefix
        start_offset = self.index[prefix]

        # Find end offset (next prefix or end of file)
        sorted_prefixes = sorted(self.index.keys())
        prefix_idx = sorted_prefixes.index(prefix)

        if prefix_idx < len(sorted_prefixes) - 1:
            next_prefix = sorted_prefixes[prefix_idx + 1]
            end_offset = self.index[next_prefix]
        else:
            end_offset = None  # Read to end of file

        # Search within the prefix range
        try:
            with open(self.hibp_file, 'r') as f:
                f.seek(start_offset)

                while True:
                    # Check if we've passed the end offset
                    if end_offset and f.tell() >= end_offset:
                        break

                    line = f.readline()
                    if not line:
                        break

                    # Parse line
                    parts = line.strip().split(':')
                    if len(parts) != 2:
                        continue

                    file_hash, count_str = parts
                    file_hash = file_hash.upper()

                    # Check for match
                    if file_hash == ntlm_hash:
                        # Found it!
                        return True, int(count_str)
                    elif file_hash > ntlm_hash:
                        # We've passed it alphabetically - not in database
                        break

        except Exception as e:
            logger.error(f"Error during lookup: {e}")
            return False, 0

        # Not found
        return False, 0


# Backwards compatibility alias
HIBPIndexer = HIBPPrefixSearcher


def analyze_hibp_correlation(cracked_file: Path, output_file: Path = None) -> Dict:
    """
    Analyze HIBP correlation for cracked passwords.

    Args:
        cracked_file: Path to cracked passwords file (SecretsDump format)
        output_file: Optional output file for detailed report

    Returns:
        Dictionary with analysis results
    """
    print(f"\nAnalyzing HIBP correlation for {cracked_file}...")

    checker = HIBPChecker()

    # Parse cracked file
    accounts = []
    try:
        with open(cracked_file, 'r') as f:
            for line in f:
                parts = line.strip().split(':')

                if len(parts) >= 4:
                    username = parts[0]
                    ntlm_hash = parts[3] if len(parts) > 3 else ''

                    accounts.append({
                        'username': username,
                        'ntlm_hash': ntlm_hash
                    })

    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return {}

    # Check all accounts
    enriched = checker.check_password_batch(accounts)

    # Generate report
    report = checker.generate_breach_report(enriched)

    # Add checker stats
    report['checker_stats'] = checker.get_statistics()

    # Print summary
    print(f"\n{'='*70}")
    print("HIBP Correlation Analysis Results")
    print(f"{'='*70}")
    print(f"Total accounts analyzed: {report['total_accounts']}")
    print(f"Breached accounts: {report['breached_accounts']} ({report['breach_rate']*100:.1f}%)")
    print(f"Total breach exposure: {report['total_breach_exposure']:,} times")
    print()

    if report['breach_count_distribution']:
        print("Breach Count Distribution:")
        for category, count in sorted(report['breach_count_distribution'].items()):
            print(f"  {category:>15}: {count:>5} accounts")
        print()

    if report['top_breached']:
        print("Top 10 Most Breached Accounts:")
        for i, account in enumerate(report['top_breached'][:10], 1):
            print(f"  {i:2}. {account['username']:30} - {account['hibp_count']:>8,} breaches")
        print()

    # Write detailed report if requested
    if output_file:
        with open(output_file, 'w') as f:
            f.write("# HIBP Correlation Analysis Report\n\n")
            f.write(f"**File:** {cracked_file}\n\n")

            f.write("## Summary\n\n")
            f.write(f"- Total Accounts: {report['total_accounts']}\n")
            f.write(f"- Breached Accounts: {report['breached_accounts']}\n")
            f.write(f"- Breach Rate: {report['breach_rate']*100:.1f}%\n\n")

            f.write("## Breached Accounts\n\n")
            f.write("| Username | NTLM Hash | Breach Count |\n")
            f.write("|----------|-----------|-------------|\n")

            for account in [a for a in enriched if a.get('hibp_breached')]:
                f.write(f"| {account['username']} | {account['ntlm_hash']} | {account['hibp_count']:,} |\n")

        print(f"✓ Detailed report written to {output_file}")

    return report


def categorize_hibp_risk(breach_count: int) -> str:
    """
    Categorize HIBP breach count into risk levels.

    Args:
        breach_count: Number of times hash appears in breaches

    Returns:
        Risk level string (None, Low, Medium, High, Very High, Extreme)
    """
    if breach_count == 0:
        return "None"
    elif breach_count < 10:
        return "Low"
    elif breach_count < 100:
        return "Medium"
    elif breach_count < 1000:
        return "High"
    elif breach_count < 10000:
        return "Very High"
    else:
        return "Extreme"


def calculate_hibp_factor(breach_count: int) -> float:
    """
    Calculate HIBP environmental risk factor based on breach count.

    Args:
        breach_count: Number of times hash appears in breaches

    Returns:
        Multiplier for environmental score (1.0 - 1.5)
    """
    if breach_count == 0:
        return 1.0
    elif breach_count < 100:
        return 1.1
    elif breach_count < 1000:
        return 1.2
    elif breach_count < 10000:
        return 1.3
    elif breach_count < 100000:
        return 1.4
    else:
        return 1.5


if __name__ == '__main__':
    # Demo usage
    print("="*70)
    print("HIBP Correlation Module")
    print("="*70 + "\n")

    checker = HIBPChecker()
    print(f"HIBP Checker enabled: {checker.enabled}")
    print(f"Cached hashes: {len(checker.hash_cache):,}")
    print()

    # Test some common breached hashes
    test_hashes = [
        ('8846F7EAEE8FB117AD06BDD830B7586C', 'password'),
        ('5F4DCC3B5AA765D61D8327DEB882CF99', 'password'),
        ('E19CCF75EE54E06B06A5907AF13CEF42', 'pass'),
    ]

    print("Testing known breached hashes:")
    for ntlm_hash, password_hint in test_hashes:
        is_breached, count = checker.check_ntlm_hash(ntlm_hash)
        status = f"BREACHED ({count:,} times)" if is_breached else "NOT FOUND"
        print(f"  {password_hint:12} {ntlm_hash}: {status}")
    print()

    # Show stats
    stats = checker.get_statistics()
    print("Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
