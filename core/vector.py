# core/vector.py
"""
Risk vector handling module for CVSS-style risk notation.
Converts risk factors into compact vector string representation.
"""

import math

def generate_risk_vector(password_analysis, shared_with, da_domains, controlled_object_count, 
                        similar_passwords=None, domain_risk_level=None):
    """
    Create a CVSS-like vector string representation of the password risk.
    
    Args:
        password_analysis (dict): Analysis of password characteristics
        shared_with (int): Number of accounts sharing this password
        da_domains (list/str): Domain admin pathways
        controlled_object_count (int/str): Number of objects controlled
        similar_passwords (list, optional): List of similar passwords
        domain_risk_level (str, optional): Risk level of the domain
        
    Returns:
        str: Risk vector string in format "C:X/L:Y/D:Z/SM:W/CM:V/EX:U/DA:T/CO:S/S:R/DR:Q"
    """
    # Extract needed values from analysis
    complexity_label = password_analysis.get('complexity_label', 'none')
    password_length = password_analysis.get('password_length', 0)
    is_common = password_analysis.get('is_common', False)
    is_dictionary_word = password_analysis.get('is_exactly_dictionary_word', False)
    banned_words_count = len(password_analysis.get('banned_words', []))
    keyboard_patterns_count = len(password_analysis.get('keyboard_patterns', []))
    days_out_of_compliance = password_analysis.get('days_out_of_compliance', 'Unknown')
    password_set_to_expire = password_analysis.get('password_set_to_expire', 'Unknown')
    
    if similar_passwords is None:
        similar_passwords = []
    
    # Map complexity to vector format
    complexity_map = {
        'mixedalphaspecialnum': 'C1',  # Best
        'mixedalphaspecial': 'C2',
        'upperalphaspecialnum': 'C3',
        'loweralphaspecialnum': 'C4',
        'mixedalphanum': 'C5',
        'specialnum': 'C6',
        'mixedalpha': 'C6',
        'upperalphaspecial': 'C6',
        'loweralphaspecial': 'C7',
        'upperalphanum': 'C7',
        'loweralphanum': 'C8',
        'special': 'C8',
        'upperalpha': 'C9',
        'loweralpha': 'C9',
        'numeric': 'C10',  # Worst
        'none': 'C10'
    }
    
    # Build vector components
    vector = []
    vector.append(f"C:{complexity_map.get(complexity_label, 'C10')}")
    
    # Length category
    if password_length >= 16:
        vector.append("L:VL")  # Very Long (low risk)
    elif password_length >= 12:
        vector.append("L:L")   # Long
    elif password_length >= 8:
        vector.append("L:M")   # Medium
    elif password_length >= 6:
        vector.append("L:S")   # Short (high risk)
    else:
        vector.append("L:VS")  # Very Short (highest risk)
    
    # Dictionary issues
    dict_issues = []
    if is_common:
        dict_issues.append("CO")  # Common password
    if is_dictionary_word:
        dict_issues.append("DW")  # Dictionary word
    if banned_words_count > 0:
        dict_issues.append("BW")  # Banned words
    if keyboard_patterns_count > 0:
        dict_issues.append("KP")  # Keyboard patterns
    
    if dict_issues:
        vector.append(f"D:{'+'.join(dict_issues)}")
    else:
        vector.append("D:N")  # None
    
    # Similarity component
    if similar_passwords:
        # Get max similarity
        max_similarity = similar_passwords[0][1] if similar_passwords else 0
        if max_similarity >= 0.9:
            vector.append("SM:VH")  # Very High similarity
        elif max_similarity >= 0.8:
            vector.append("SM:H")   # High similarity
        elif max_similarity >= 0.7:
            vector.append("SM:M")   # Medium similarity
        else:
            vector.append("SM:N")   # No significant similarity
    else:
        vector.append("SM:N")
    
    # Compliance - with logarithmic scale
    if days_out_of_compliance not in ("Unknown", "N/A"):
        try:
            days = int(days_out_of_compliance)
            if days <= 0:
                vector.append("CM:N")   # None
            elif days <= 30:
                vector.append("CM:L")   # Low
            elif days <= 90:
                vector.append("CM:M")   # Medium
            elif days <= 365:
                vector.append("CM:H")   # High
            elif days <= 730:  # 2 years
                vector.append("CM:VH")  # Very High
            else:
                vector.append("CM:E")   # Extreme (>2 years)
            
        except (ValueError, TypeError):
            vector.append("CM:U")       # Unknown
    else:
        vector.append("CM:U")           # Unknown
    
    # Expiration
    if password_set_to_expire == "No":
        vector.append("EX:N")  # No expiration
    elif password_set_to_expire == "Yes":
        vector.append("EX:Y")  # Expires
    else:
        vector.append("EX:U")  # Unknown
    
    # Domain admin path - to consider path type
    has_da_path = da_domains and da_domains not in ('None', 'Unknown', [])
    if isinstance(da_domains, list) and len(da_domains) > 2:
        vector.append("DA:M")  # Multiple paths
    elif has_da_path:
        vector.append("DA:Y")  # Single path
    else:
        vector.append("DA:N")  # No path
    
    # Controlled objects - with more granular scale
    if controlled_object_count != 'Unknown':
        try:
            obj_count = int(controlled_object_count)
            if obj_count > 1000:
                vector.append("CO:E")   # Extreme (>1000)
            elif obj_count > 500:
                vector.append("CO:VH")  # Very High (501-1000)
            elif obj_count > 100:
                vector.append("CO:H")   # High (101-500)
            elif obj_count > 50:
                vector.append("CO:M+")  # Medium-High (51-100)
            elif obj_count > 10:
                vector.append("CO:M")   # Medium (11-50)
            else:
                vector.append("CO:L")   # Low (1-10)
        except (ValueError, TypeError):
            vector.append("CO:U")       # Unknown
    else:
        vector.append("CO:U")           # Unknown
    
    # Sharing - Using logarithmic scale
    share_count = int(shared_with) if isinstance(shared_with, (int, str)) and shared_with != 'Unknown' else 0
    if share_count == 0:
        vector.append("S:0")
    else:
        # Use log10 scale: S:1 = 1-9, S:2 = 10-99, S:3 = 100-999, S:4 = 1000+
        log_scale = min(4, 1 + int(math.log10(share_count)))
        vector.append(f"S:{log_scale}")
    
    # Domain risk level
    if domain_risk_level:
        domain_risk_map = {
            "Critical": "DR:C",
            "High": "DR:H",
            "Medium": "DR:M",
            "Low": "DR:L",
            "Unknown": "DR:U"
        }
        vector.append(domain_risk_map.get(domain_risk_level, "DR:U"))
    else:
        vector.append("DR:U")
    
    return "/".join(vector)


def parse_risk_vector(vector_string):
    """
    Parse a risk vector string into its component values.
    
    Args:
        vector_string (str): Risk vector in format "C:X/L:Y/D:Z/..."
        
    Returns:
        dict: Dictionary of parsed risk components
    """
    components = {}
    
    try:
        parts = vector_string.split('/')
        for part in parts:
            key, value = part.split(':')
            components[key] = value
    except Exception:
        # Return empty dict if parsing fails
        return {}
    
    return components


def explain_risk_vector(vector_string):
    """
    Generate a human-readable explanation of a risk vector.
    
    Args:
        vector_string (str): Risk vector string
        
    Returns:
        str: Human-readable explanation
    """
    components = parse_risk_vector(vector_string)
    if not components:
        return "Invalid risk vector format"
    
    explanations = []
    
    # Complexity
    complexity = components.get('C', 'C10')
    if complexity == 'C1':
        explanations.append("Excellent password complexity (mixed case, numbers, symbols)")
    elif complexity in ('C2', 'C3', 'C4'):
        explanations.append("Good password complexity")
    elif complexity in ('C5', 'C6', 'C7'):
        explanations.append("Moderate password complexity")
    elif complexity in ('C8', 'C9'):
        explanations.append("Weak password complexity")
    elif complexity == 'C10':
        explanations.append("Very weak password complexity")
    
    # Length
    length = components.get('L', 'VS')
    if length == 'VL':
        explanations.append("Very long password (16+ characters)")
    elif length == 'L':
        explanations.append("Long password (12-15 characters)")
    elif length == 'M':
        explanations.append("Medium length password (8-11 characters)")
    elif length == 'S':
        explanations.append("Short password (6-7 characters)")
    elif length == 'VS':
        explanations.append("Very short password (<6 characters)")
    
    # Dictionary issues
    dict_issues = components.get('D', 'N')
    if dict_issues != 'N':
        issues = []
        if 'CO' in dict_issues:
            issues.append("common password")
        if 'DW' in dict_issues:
            issues.append("dictionary word")
        if 'BW' in dict_issues:
            issues.append("banned word(s)")
        if 'KP' in dict_issues:
            issues.append("keyboard pattern(s)")
        
        if issues:
            explanations.append(f"Contains {', '.join(issues)}")
    
    # Similarity
    similarity = components.get('SM', 'N')
    if similarity == 'VH':
        explanations.append("Very high similarity to other passwords (90%+)")
    elif similarity == 'H':
        explanations.append("High similarity to other passwords (80-89%)")
    elif similarity == 'M':
        explanations.append("Moderate similarity to other passwords (70-79%)")
    
    # Compliance
    compliance = components.get('CM', 'U')
    if compliance == 'E':
        explanations.append("Extremely out of compliance (>2 years)")
    elif compliance == 'VH':
        explanations.append("Very high compliance violation (1-2 years)")
    elif compliance == 'H':
        explanations.append("High compliance violation (3-12 months)")
    elif compliance == 'M':
        explanations.append("Moderate compliance violation (1-3 months)")
    elif compliance == 'L':
        explanations.append("Low compliance violation (<1 month)")
    
    # Expiration
    expiration = components.get('EX', 'U')
    if expiration == 'N':
        explanations.append("Password never expires")
    
    # Domain Admin pathway
    da_path = components.get('DA', 'N')
    if da_path == 'M':
        explanations.append("Multiple Domain Admin pathways")
    elif da_path == 'Y':
        explanations.append("Has Domain Admin pathway")
    elif da_path == 'S':
        explanations.append("Shared with Domain Admin account")
    
    # Controlled Objects
    controlled = components.get('CO', 'U')
    if controlled == 'E':
        explanations.append("Controls extreme number of objects (>1000)")
    elif controlled == 'VH':
        explanations.append("Controls very high number of objects (501-1000)")
    elif controlled == 'H':
        explanations.append("Controls high number of objects (101-500)")
    elif controlled == 'M+':
        explanations.append("Controls medium-high number of objects (51-100)")
    elif controlled == 'M':
        explanations.append("Controls medium number of objects (11-50)")
    elif controlled == 'L':
        explanations.append("Controls low number of objects (1-10)")
    
    # Sharing
    sharing = components.get('S', '0')
    if sharing == '4':
        explanations.append("Extremely widely shared (1000+ accounts)")
    elif sharing == '3':
        explanations.append("Widely shared (100-999 accounts)")
    elif sharing == '2':
        explanations.append("Moderately shared (10-99 accounts)")
    elif sharing == '1':
        explanations.append("Shared with few accounts (1-9)")
    
    # Domain Risk
    domain_risk = components.get('DR', 'U')
    if domain_risk == 'C':
        explanations.append("Critical risk domain")
    elif domain_risk == 'H':
        explanations.append("High risk domain")
    elif domain_risk == 'M':
        explanations.append("Medium risk domain")
    elif domain_risk == 'L':
        explanations.append("Low risk domain")
    
    return ". ".join(explanations)