"""
Hashcat 7.1.2 Integration Module

This module provides advanced integration with Hashcat 7.1.2, including:
- JSON status output parsing
- Brain mode (distributed cracking) support
- Real-time progress monitoring
- Advanced attack mode configuration
- Potfile management

Usage:
    from core.hashcat_integration import HashcatRunner

    runner = HashcatRunner()
    result = runner.crack_ntlm_hashes('hashes.txt', 'wordlist.txt')
"""

import os
import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from core.config import HASHCAT_CONFIG


@dataclass
class HashcatStatus:
    """Represents the current status of a Hashcat session."""
    session: str
    time_start: int
    estimated_stop: int
    speed_msec_all: int
    recovered: int
    recovered_percent: float
    progress: int
    progress_percent: float
    runtime_msec: int
    estimated_msec: int
    guess_base: str
    guess_mod: str
    device_status: List[Dict]

    @classmethod
    def from_json(cls, data: Dict) -> 'HashcatStatus':
        """Create HashcatStatus from JSON data."""
        return cls(
            session=data.get('session', 'unknown'),
            time_start=data.get('time_start', 0),
            estimated_stop=data.get('estimated_stop', 0),
            speed_msec_all=data.get('speed_msec_all', 0),
            recovered=data.get('recovered', 0),
            recovered_percent=data.get('recovered_percent', 0.0),
            progress=data.get('progress', 0),
            progress_percent=data.get('progress_percent', 0.0),
            runtime_msec=data.get('runtime_msec', 0),
            estimated_msec=data.get('estimated_msec', 0),
            guess_base=data.get('guess', {}).get('guess_base', ''),
            guess_mod=data.get('guess', {}).get('guess_mod', ''),
            device_status=data.get('devices', [])
        )


@dataclass
class HashcatResult:
    """Results from a Hashcat cracking session."""
    success: bool
    cracked_count: int
    total_hashes: int
    crack_rate: float
    runtime_seconds: float
    output_file: Optional[Path]
    potfile: Optional[Path]
    errors: List[str]
    status_updates: List[HashcatStatus]


class HashcatRunner:
    """Run and manage Hashcat 7.1.2 cracking sessions."""

    def __init__(self, hashcat_binary: Optional[Path] = None):
        """
        Initialize Hashcat runner.

        Args:
            hashcat_binary: Path to hashcat binary (uses config default if None)
        """
        self.hashcat_binary = hashcat_binary or HASHCAT_CONFIG["BINARY_PATH"]

        if not self.hashcat_binary.exists():
            raise FileNotFoundError(f"Hashcat binary not found: {self.hashcat_binary}")

    def verify_installation(self) -> Tuple[bool, str]:
        """
        Verify Hashcat installation and version.

        Returns:
            Tuple of (success, version_string)
        """
        try:
            result = subprocess.run(
                [str(self.hashcat_binary), '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                return True, version
            else:
                return False, "Failed to get version"

        except Exception as e:
            return False, str(e)

    def build_command(self, hash_file: Path, attack_config: Dict) -> List[str]:
        """
        Build hashcat command with specified configuration.

        Args:
            hash_file: Path to hash file
            attack_config: Attack configuration dictionary

        Returns:
            Command as list of strings
        """
        cmd = [str(self.hashcat_binary)]

        # Hash mode (default: 1000 for NTLM)
        cmd.extend(['-m', str(attack_config.get('hash_mode', 1000))])

        # Attack mode (default: 0 for dictionary)
        cmd.extend(['-a', str(attack_config.get('attack_mode', 0))])

        # Workload profile
        if HASHCAT_CONFIG.get("DEFAULT_WORKLOAD_PROFILE"):
            cmd.extend(['-w', str(HASHCAT_CONFIG["DEFAULT_WORKLOAD_PROFILE"])])

        # Optimized kernel
        if HASHCAT_CONFIG.get("ENABLE_OPTIMIZED_KERNEL"):
            cmd.append('-O')

        # Potfile
        if attack_config.get('potfile'):
            cmd.extend(['--potfile-path', str(attack_config['potfile'])])

        # Session name
        if attack_config.get('session'):
            cmd.extend(['--session', attack_config['session']])

        # Output file
        if attack_config.get('outfile'):
            cmd.extend(['-o', str(attack_config['outfile'])])

        # Output format (username, hash, plaintext)
        if attack_config.get('outfile_format'):
            cmd.extend(['--outfile-format', attack_config['outfile_format']])

        # Username handling
        if attack_config.get('username', True):
            cmd.append('--username')

        # Show mode (display cracked)
        if attack_config.get('show_mode'):
            cmd.append('--show')

        # Left mode (display uncracked)
        if attack_config.get('left_mode'):
            cmd.append('--left')

        # Keep guessing (find all variants)
        if attack_config.get('keep_guessing'):
            cmd.append('--keep-guessing')

        # Status and JSON output
        if HASHCAT_CONFIG.get("ENABLE_JSON_STATUS") and not attack_config.get('show_mode') and not attack_config.get('left_mode'):
            cmd.append('--status')
            cmd.append('--status-json')
            if HASHCAT_CONFIG.get("STATUS_TIMER"):
                cmd.extend(['--status-timer', str(HASHCAT_CONFIG["STATUS_TIMER"])])

        # Brain mode
        if HASHCAT_CONFIG.get("ENABLE_BRAIN_MODE"):
            if attack_config.get('brain_server'):
                cmd.append('--brain-server')
            elif attack_config.get('brain_client'):
                cmd.append('--brain-client')
                cmd.extend(['--brain-host', HASHCAT_CONFIG.get("BRAIN_HOST", "127.0.0.1")])
                cmd.extend(['--brain-port', str(HASHCAT_CONFIG.get("BRAIN_PORT", 6863))])

            if attack_config.get('brain_password'):
                cmd.extend(['--brain-password', attack_config['brain_password']])
            elif HASHCAT_CONFIG.get("BRAIN_PASSWORD"):
                cmd.extend(['--brain-password', HASHCAT_CONFIG["BRAIN_PASSWORD"]])

        # Runtime limit
        if attack_config.get('runtime'):
            cmd.extend(['--runtime', str(attack_config['runtime'])])

        # Rules
        if attack_config.get('rules'):
            for rule_file in attack_config['rules']:
                cmd.extend(['-r', str(rule_file)])

        # Hash file
        cmd.append(str(hash_file))

        # Dictionary/mask/directory
        if attack_config.get('wordlist'):
            cmd.append(str(attack_config['wordlist']))
        elif attack_config.get('mask'):
            cmd.append(attack_config['mask'])

        return cmd

    def crack_ntlm_hashes(self, hash_file: Path, wordlist: Path = None,
                         session_name: str = None, potfile: Path = None,
                         runtime: int = None, rules: List[Path] = None,
                         keep_guessing: bool = False) -> HashcatResult:
        """
        Crack NTLM hashes using dictionary attack.

        Args:
            hash_file: Path to file containing NTLM hashes
            wordlist: Path to wordlist (uses rockyou.txt if None)
            session_name: Session name for resume capability
            potfile: Path to potfile (auto-generated if None)
            runtime: Maximum runtime in seconds
            rules: List of rule files to apply
            keep_guessing: Find all password variants

        Returns:
            HashcatResult with cracking results
        """
        # Default wordlist
        if wordlist is None:
            wordlist = HASHCAT_CONFIG["WORDLISTS_DIR"] / 'rockyou.txt'

        # Default session name
        if session_name is None:
            session_name = f"patd_{int(time.time())}"

        # Default potfile
        if potfile is None:
            potfile = HASHCAT_CONFIG["POTFILE_DIR"] / f"{session_name}.pot"

        # Build attack configuration
        attack_config = {
            'hash_mode': 1000,  # NTLM
            'attack_mode': 0,   # Dictionary
            'session': session_name,
            'potfile': potfile,
            'username': True,
            'keep_guessing': keep_guessing,
        }

        if runtime:
            attack_config['runtime'] = runtime

        if rules:
            attack_config['rules'] = rules

        attack_config['wordlist'] = wordlist

        # Build command
        cmd = self.build_command(hash_file, attack_config)

        # Run hashcat
        print(f"Running hashcat: {' '.join(str(c) for c in cmd)}")

        status_updates = []
        errors = []
        start_time = time.time()

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Monitor output for JSON status
            for line in process.stdout:
                line = line.strip()

                # Try to parse JSON status
                if line.startswith('{') and HASHCAT_CONFIG.get("ENABLE_JSON_STATUS"):
                    try:
                        status_data = json.loads(line)
                        status = HashcatStatus.from_json(status_data)
                        status_updates.append(status)

                        # Print progress
                        print(f"Progress: {status.progress_percent:.1f}% | "
                              f"Recovered: {status.recovered}/{status.recovered_percent:.1f}% | "
                              f"Speed: {status.speed_msec_all/1000:.1f} kH/s")

                    except json.JSONDecodeError:
                        pass

            # Wait for completion
            process.wait()

        except Exception as e:
            errors.append(f"Execution error: {str(e)}")
            return HashcatResult(
                success=False,
                cracked_count=0,
                total_hashes=0,
                crack_rate=0.0,
                runtime_seconds=time.time() - start_time,
                output_file=None,
                potfile=potfile,
                errors=errors,
                status_updates=status_updates
            )

        runtime_seconds = time.time() - start_time

        # Get cracked results using --show
        cracked_count, total_hashes = self._get_crack_statistics(hash_file, potfile)

        return HashcatResult(
            success=True,
            cracked_count=cracked_count,
            total_hashes=total_hashes,
            crack_rate=cracked_count / total_hashes if total_hashes > 0 else 0.0,
            runtime_seconds=runtime_seconds,
            output_file=None,
            potfile=potfile,
            errors=errors,
            status_updates=status_updates
        )

    def extract_cracked(self, hash_file: Path, potfile: Path, output_file: Path) -> int:
        """
        Extract cracked passwords from potfile.

        Args:
            hash_file: Original hash file
            potfile: Potfile with cracked hashes
            output_file: Output file for cracked passwords

        Returns:
            Number of cracked hashes
        """
        attack_config = {
            'hash_mode': 1000,
            'potfile': potfile,
            'show_mode': True,
            'username': True,
            'outfile': output_file,
            'outfile_format': '2'  # hash:plain
        }

        cmd = self.build_command(hash_file, attack_config)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Count lines in output
            if output_file.exists():
                with open(output_file, 'r') as f:
                    return sum(1 for _ in f)

            return 0

        except Exception as e:
            print(f"Error extracting cracked: {e}")
            return 0

    def extract_uncracked(self, hash_file: Path, potfile: Path, output_file: Path) -> int:
        """
        Extract uncracked hashes.

        Args:
            hash_file: Original hash file
            potfile: Potfile with cracked hashes
            output_file: Output file for uncracked hashes

        Returns:
            Number of uncracked hashes
        """
        attack_config = {
            'hash_mode': 1000,
            'potfile': potfile,
            'left_mode': True,
            'username': True,
            'outfile': output_file
        }

        cmd = self.build_command(hash_file, attack_config)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Count lines in output
            if output_file.exists():
                with open(output_file, 'r') as f:
                    return sum(1 for _ in f)

            return 0

        except Exception as e:
            print(f"Error extracting uncracked: {e}")
            return 0

    def _get_crack_statistics(self, hash_file: Path, potfile: Path) -> Tuple[int, int]:
        """
        Get crack statistics from potfile.

        Args:
            hash_file: Original hash file
            potfile: Potfile

        Returns:
            Tuple of (cracked_count, total_count)
        """
        # Count total hashes
        total = 0
        try:
            with open(hash_file, 'r') as f:
                total = sum(1 for line in f if line.strip())
        except:
            pass

        # Count cracked (lines in potfile)
        cracked = 0
        if potfile.exists():
            try:
                with open(potfile, 'r') as f:
                    cracked = sum(1 for line in f if line.strip())
            except:
                pass

        return cracked, total


def demo_hashcat_features():
    """Demonstrate Hashcat 7.1.2 features."""
    print("="*70)
    print("Hashcat 7.1.2 Feature Demonstration")
    print("="*70 + "\n")

    runner = HashcatRunner()

    # Verify installation
    success, version = runner.verify_installation()
    if success:
        print(f"✓ Hashcat Version: {version}\n")
    else:
        print(f"✗ Hashcat verification failed: {version}\n")
        return

    # Display configuration
    print("Configuration:")
    print(f"  Binary: {HASHCAT_CONFIG['BINARY_PATH']}")
    print(f"  Wordlists: {HASHCAT_CONFIG['WORDLISTS_DIR']}")
    print(f"  Rules: {HASHCAT_CONFIG['RULES_DIR']}")
    print(f"  JSON Status: {'Enabled' if HASHCAT_CONFIG['ENABLE_JSON_STATUS'] else 'Disabled'}")
    print(f"  Brain Mode: {'Enabled' if HASHCAT_CONFIG['ENABLE_BRAIN_MODE'] else 'Disabled'}")
    print(f"  Workload Profile: {HASHCAT_CONFIG['DEFAULT_WORKLOAD_PROFILE']}")
    print()


if __name__ == '__main__':
    demo_hashcat_features()
