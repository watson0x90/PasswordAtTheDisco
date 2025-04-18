# core/password_analysis.py
"""
Password analysis module for evaluating password security.
Provides functions to check password complexity, policy compliance, and similarity.
"""

import Levenshtein
from core.config import policy

def has_lower(pw):
    """Check if password has lowercase characters."""
    return any(c.islower() for c in pw)

def has_upper(pw):
    """Check if password has uppercase characters."""
    return any(c.isupper() for c in pw)

def has_digit(pw):
    """Check if password has numeric characters."""
    return any(c.isdigit() for c in pw)

def has_special(pw):
    """Check if password has special characters."""
    return any(not c.isalnum() for c in pw)

def has_unicode(pw):
    """Check if password has Unicode characters (non-ASCII)."""
    return any(ord(c) > 127 for c in pw)

def check_password_complexity(pw):
    """
    Determine the complexity category of a password based on character types.
    
    Args:
        pw (str): The password to analyze
        
    Returns:
        str: Complexity category label
    """
    has_lower_result = has_lower(pw)
    has_upper_result = has_upper(pw)
    has_digit_result = has_digit(pw)
    has_special_result = has_special(pw)
    
    if has_lower_result and not has_upper_result and not has_digit_result and not has_special_result:
        return 'loweralpha'
    elif has_upper_result and not has_lower_result and not has_digit_result and not has_special_result:
        return 'upperalpha'
    elif has_digit_result and not has_lower_result and not has_upper_result and not has_special_result:
        return 'numeric'
    elif has_special_result and not has_lower_result and not has_upper_result and not has_digit_result:
        return 'special'
    elif has_lower_result and has_digit_result and not has_upper_result and not has_special_result:
        return 'loweralphanum'
    elif has_upper_result and has_digit_result and not has_lower_result and not has_special_result:
        return 'upperalphanum'
    elif has_lower_result and has_upper_result and not has_digit_result and not has_special_result:
        return 'mixedalpha'
    elif has_lower_result and has_special_result and not has_upper_result and not has_digit_result:
        return 'loweralphaspecial'
    elif has_upper_result and has_special_result and not has_lower_result and not has_digit_result:
        return 'upperalphaspecial'
    elif has_special_result and has_digit_result and not has_lower_result and not has_upper_result:
        return 'specialnum'
    elif has_lower_result and has_upper_result and has_digit_result and not has_special_result:
        return 'mixedalphanum'
    elif has_lower_result and has_digit_result and has_special_result and not has_upper_result:
        return 'loweralphaspecialnum'
    elif has_lower_result and has_upper_result and has_special_result and not has_digit_result:
        return 'mixedalphaspecial'
    elif has_upper_result and has_digit_result and has_special_result and not has_lower_result:
        return 'upperalphaspecialnum'
    elif has_lower_result and has_upper_result and has_digit_result and has_special_result:
        return 'mixedalphaspecialnum'
    else:
        return 'none'

def check_policy(pw, custom_policy=None):
    """
    Check if password meets the specified policy requirements.
    
    Args:
        pw (str): The password to check
        custom_policy (dict, optional): Custom policy settings, defaults to global policy
        
    Returns:
        tuple: (meets_policy, violations) whether policy is met and list of violations
    """
    if custom_policy is None:
        custom_policy = policy
        
    min_length = custom_policy.get('min_length', 8)
    require_lowercase = custom_policy.get('require_lowercase', True)
    require_uppercase = custom_policy.get('require_uppercase', True)
    require_digits = custom_policy.get('require_digits', True)
    require_special = custom_policy.get('require_special', True)

    meets_policy = True
    violations = []

    if len(pw) < min_length:
        meets_policy = False
        violations.append(f"Length < {min_length}")
    if require_lowercase and not has_lower(pw):
        meets_policy = False
        violations.append("No lowercase")
    if require_uppercase and not has_upper(pw):
        meets_policy = False
        violations.append("No uppercase")
    if require_digits and not has_digit(pw):
        meets_policy = False
        violations.append("No digits")
    if require_special and not has_special(pw):
        meets_policy = False
        violations.append("No special character")

    return meets_policy, violations

def calculate_password_similarity(password, other_passwords):
    """
    Calculate similarity to other passwords.
    
    Args:
        password (str): Password to check similarity for
        other_passwords (list): List of other passwords to compare against
        
    Returns:
        list: List of tuples (similar_password, similarity_score) sorted by similarity
    """
    similar_passwords = []
    for other_pw in other_passwords:
        if other_pw == password:
            continue
        # Calculate Levenshtein ratio (0-1 scale where 1 is identical)
        similarity = Levenshtein.ratio(password, other_pw)
        if similarity >= 0.7:  # 70% similar or higher
            similar_passwords.append((other_pw, similarity))
    
    # Sort by similarity (highest first)
    return sorted(similar_passwords, key=lambda x: x[1], reverse=True)

def check_forbidden_words(password, forbidden_words):
    """
    Check if password contains any forbidden words.
    
    Args:
        password (str): Password to check
        forbidden_words (set): Set of forbidden words
        
    Returns:
        list: List of forbidden words found in the password
    """
    password_lower = password.lower()
    return [word for word in forbidden_words if word in password_lower]

def check_keyboard_patterns(password, keyboard_patterns):
    """
    Check if password contains any keyboard patterns.
    
    Args:
        password (str): Password to check
        keyboard_patterns (set): Set of known keyboard patterns
        
    Returns:
        list: List of keyboard patterns found in the password
    """
    password_lower = password.lower()
    return [pattern for pattern in keyboard_patterns if pattern in password_lower]

def is_common_password(password, common_passwords):
    """
    Check if password is in the list of common passwords.
    
    Args:
        password (str): Password to check
        common_passwords (set): Set of common passwords
        
    Returns:
        bool: True if password is common, False otherwise
    """
    return password.lower() in common_passwords

def is_dictionary_word(password, dictionary_words):
    """
    Check if password is exactly a dictionary word.
    
    Args:
        password (str): Password to check
        dictionary_words (set): Set of dictionary words
        
    Returns:
        bool: True if password is exactly a dictionary word, False otherwise
    """
    return password.lower() in dictionary_words

def analyze_password(password, forbidden_words, keyboard_patterns, common_passwords, dictionary_words, compare_passwords=None):
    """
    Perform comprehensive analysis of a password.
    
    Args:
        password (str): Password to analyze
        forbidden_words (set): Set of forbidden words
        keyboard_patterns (set): Set of keyboard patterns
        common_passwords (set): Set of common passwords
        dictionary_words (set): Set of dictionary words
        compare_passwords (list, optional): List of passwords to compare for similarity
        
    Returns:
        dict: Comprehensive password analysis results
    """
    if not password:
        return None
        
    # Basic properties
    password_length = len(password)
    complexity_label = check_password_complexity(password)
    meets_policy_result, policy_violations = check_policy(password)
    contains_unicode = has_unicode(password)
    
    # Lists of issues
    banned_words_found = check_forbidden_words(password, forbidden_words)
    keyboard_patterns_found = check_keyboard_patterns(password, keyboard_patterns)
    
    # Boolean checks
    is_common = is_common_password(password, common_passwords)
    is_dictionary = is_dictionary_word(password, dictionary_words)
    
    # Similarity analysis
    similar_passwords = []
    if compare_passwords:
        similar_passwords = calculate_password_similarity(password, compare_passwords)
    
    # Assemble results
    analysis = {
        'password_length': password_length,
        'complexity_label': complexity_label,
        'meets_policy': meets_policy_result,
        'policy_violations': policy_violations,
        'contains_unicode': contains_unicode,
        'banned_words': banned_words_found,
        'keyboard_patterns': keyboard_patterns_found,
        'is_common': is_common,
        'is_exactly_dictionary_word': is_dictionary,
        'similar_passwords': similar_passwords,
    }
    
    return analysis