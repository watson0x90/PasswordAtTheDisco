# models/password.py
"""
Password model for representing passwords in security analysis.
"""

from typing import Any, Dict, List, Optional, Set

from core.config import policy

# Optional import for Levenshtein (not required for basic functionality)
try:
    import Levenshtein
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False

class Password:
    """
    Represents a password with its security characteristics and analysis results.
    """
    
    def __init__(self, value: Optional[str], is_cracked: bool = False, hash_value: Optional[str] = None):
        """
        Initialize a Password object.
        
        Args:
            value (str, optional): The clear-text password value (None for uncracked)
            is_cracked (bool): Whether the password has been cracked
            hash_value (str, optional): The hash representation of the password
        """
        self.value = value
        self.is_cracked = is_cracked
        self.hash_value = hash_value
        
        # Analysis attributes
        self.length = len(value) if value else 0
        self.complexity_label = 'N/A'
        self.contains_unicode = False
        self.meets_policy = False
        self.policy_violations = []
        self.forbidden_words = []
        self.keyboard_patterns = []
        self.is_common = False
        self.is_dictionary_word = False
        self.similar_passwords = []  # List of (password, similarity_score) tuples
        
        # Sharing attributes
        self.shared_with_count = 0
        self.domains_shared = set()
        
        # Risk scoring attributes
        self.base_score = 0.0
        self.temporal_score = 0.0
        self.environmental_score = 0.0
        self.final_score = 0.0
        self.risk_level = 'Unknown'
        self.risk_vector = ''
        self.score_breakdown = {}
    
    def analyze(self, forbidden_words: Set[str], keyboard_patterns: Set[str], 
               common_passwords: Set[str], dictionary_words: Set[str]) -> None:
        """
        Analyze the password for security issues.
        
        Args:
            forbidden_words (set): Set of forbidden words
            keyboard_patterns (set): Set of keyboard patterns
            common_passwords (set): Set of common passwords 
            dictionary_words (set): Set of dictionary words
        """
        if not self.is_cracked or not self.value:
            return
            
        # Basic checks
        self._check_complexity()
        self._check_unicode()
        
        # Dictionary checks
        self.forbidden_words = [word for word in forbidden_words 
                               if word in self.value.lower()]
        self.keyboard_patterns = [pattern for pattern in keyboard_patterns 
                                 if pattern in self.value.lower()]
        self.is_common = self.value.lower() in common_passwords
        self.is_dictionary_word = self.value.lower() in dictionary_words
        
        # Policy compliance
        self.meets_policy, self.policy_violations = self._check_policy()
    
    def _check_complexity(self) -> None:
        """Determine the complexity category of password based on character types."""
        if not self.value:
            return
            
        has_lower_result = self.has_lower()
        has_upper_result = self.has_upper()
        has_digit_result = self.has_digit()
        has_special_result = self.has_special()
        
        if has_lower_result and not has_upper_result and not has_digit_result and not has_special_result:
            self.complexity_label = 'loweralpha'
        elif has_upper_result and not has_lower_result and not has_digit_result and not has_special_result:
            self.complexity_label = 'upperalpha'
        elif has_digit_result and not has_lower_result and not has_upper_result and not has_special_result:
            self.complexity_label = 'numeric'
        elif has_special_result and not has_lower_result and not has_upper_result and not has_digit_result:
            self.complexity_label = 'special'
        elif has_lower_result and has_digit_result and not has_upper_result and not has_special_result:
            self.complexity_label = 'loweralphanum'
        elif has_upper_result and has_digit_result and not has_lower_result and not has_special_result:
            self.complexity_label = 'upperalphanum'
        elif has_lower_result and has_upper_result and not has_digit_result and not has_special_result:
            self.complexity_label = 'mixedalpha'
        elif has_lower_result and has_special_result and not has_upper_result and not has_digit_result:
            self.complexity_label = 'loweralphaspecial'
        elif has_upper_result and has_special_result and not has_lower_result and not has_digit_result:
            self.complexity_label = 'upperalphaspecial'
        elif has_special_result and has_digit_result and not has_lower_result and not has_upper_result:
            self.complexity_label = 'specialnum'
        elif has_lower_result and has_upper_result and has_digit_result and not has_special_result:
            self.complexity_label = 'mixedalphanum'
        elif has_lower_result and has_digit_result and has_special_result and not has_upper_result:
            self.complexity_label = 'loweralphaspecialnum'
        elif has_lower_result and has_upper_result and has_special_result and not has_digit_result:
            self.complexity_label = 'mixedalphaspecial'
        elif has_upper_result and has_digit_result and has_special_result and not has_lower_result:
            self.complexity_label = 'upperalphaspecialnum'
        elif has_lower_result and has_upper_result and has_digit_result and has_special_result:
            self.complexity_label = 'mixedalphaspecialnum'
        else:
            self.complexity_label = 'none'
    
    def _check_unicode(self) -> None:
        """Check if password has Unicode characters (non-ASCII)."""
        if not self.value:
            return
            
        self.contains_unicode = any(ord(c) > 127 for c in self.value)
    
    def _check_policy(self) -> tuple:
        """Check if password meets the specified policy requirements."""
        if not self.value:
            return False, ["No password value"]
            
        min_length = policy.get('min_length', 8)
        require_lowercase = policy.get('require_lowercase', True)
        require_uppercase = policy.get('require_uppercase', True)
        require_digits = policy.get('require_digits', True)
        require_special = policy.get('require_special', True)
    
        meets_policy = True
        violations = []
    
        if self.length < min_length:
            meets_policy = False
            violations.append(f"Length < {min_length}")
        if require_lowercase and not self.has_lower():
            meets_policy = False
            violations.append("No lowercase")
        if require_uppercase and not self.has_upper():
            meets_policy = False
            violations.append("No uppercase")
        if require_digits and not self.has_digit():
            meets_policy = False
            violations.append("No digits")
        if require_special and not self.has_special():
            meets_policy = False
            violations.append("No special character")
    
        return meets_policy, violations
    
    def calculate_similarity(self, other_passwords: List[str]) -> None:
        """
        Calculate similarity to other passwords.
        
        Args:
            other_passwords (list): List of passwords to compare against
        """
        if not self.value or not other_passwords:
            return
            
        self.similar_passwords = []
        if LEVENSHTEIN_AVAILABLE:
            for other_pw in other_passwords:
                if other_pw == self.value:
                    continue
                # Calculate Levenshtein ratio (0-1 scale where 1 is identical)
                similarity = Levenshtein.ratio(self.value, other_pw)
                if similarity >= 0.7:  # 70% similar or higher
                    self.similar_passwords.append((other_pw, similarity))
        else:
            # Fallback: simple exact match detection only
            for other_pw in other_passwords:
                if other_pw == self.value:
                    self.similar_passwords.append((other_pw, 1.0))
        
        # Sort by similarity (highest first)
        self.similar_passwords.sort(key=lambda x: x[1], reverse=True)
    
    def has_lower(self) -> bool:
        """Check if password has lowercase characters."""
        return any(c.islower() for c in self.value) if self.value else False
    
    def has_upper(self) -> bool:
        """Check if password has uppercase characters."""
        return any(c.isupper() for c in self.value) if self.value else False
    
    def has_digit(self) -> bool:
        """Check if password has numeric characters."""
        return any(c.isdigit() for c in self.value) if self.value else False
    
    def has_special(self) -> bool:
        """Check if password has special characters."""
        return any(not c.isalnum() for c in self.value) if self.value else False
    
    def to_string(self) -> str:
        """Return the password value, if available."""
        return self.value if self.value else self.hash_value
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert password to dictionary representation.
        
        Returns:
            dict: Dictionary representation of password analysis
        """
        if not self.is_cracked or not self.value:
            return {'hash': self.hash_value, 'is_cracked': False}
            
        # Format similar password info for display
        similar_password_info = []
        for similar_pw, similarity_score in self.similar_passwords[:3]:  # Top 3 similar passwords
            similarity_percent = round(similarity_score * 100)
            similar_password_info.append(f"{similar_pw} ({similarity_percent}%)")
        
        similar_password_text = ", ".join(similar_password_info) if similar_password_info else "None"
        
        return {
            'Password': self.value,
            'Password Hash': self.hash_value,
            'Password Length': self.length,
            'Complexity Label': self.complexity_label,
            'Contains Unicode': 'Yes' if self.contains_unicode else 'No',
            'Meets Policy': 'Yes' if self.meets_policy else 'No',
            'Policy Violations': ', '.join(self.policy_violations),
            'Forbidden Words': ', '.join(self.forbidden_words),
            'Keyboard Patterns': ', '.join(self.keyboard_patterns),
            'Common Password': 'Yes' if self.is_common else 'No',
            'Is Exactly Dictionary Word': 'Yes' if self.is_dictionary_word else 'No',
            'Similar Passwords': similar_password_text,
            'Shared With': self.shared_with_count,
            'Domains Shared': ', '.join(self.domains_shared),
            'Risk Level': self.risk_level,
            'Risk Score': self.final_score,
            'Risk Vector': self.risk_vector
        }