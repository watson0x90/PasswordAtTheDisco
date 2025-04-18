# core/scoring.py
"""
CVSS-style risk scoring system for password security assessment.
Implements the base, temporal, and environmental score components.
"""

import math

def calculate_base_score(complexity_label, password_length, is_common, is_dictionary_word, 
                         banned_words_count, keyboard_patterns_count, similar_passwords):
    """
    Calculate the base score component (0-10) based on password intrinsic qualities.
    
    Args:
        complexity_label (str): Password complexity category
        password_length (int): Length of the password
        is_common (bool): Whether the password is in common password list
        is_dictionary_word (bool): Whether the password is a dictionary word
        banned_words_count (int): Number of banned words found in password
        keyboard_patterns_count (int): Number of keyboard patterns in password
        similar_passwords (list): List of similar passwords with similarity scores
        
    Returns:
        tuple: (base_score, complexity_factor, length_factor, dictionary_factor, similarity_factor)
    """
    # Complexity factor mapping (smaller is better)
    complexity_factors = {
        'mixedalphaspecialnum': 0.2,  # Best complexity
        'mixedalphaspecial': 0.3,
        'upperalphaspecialnum': 0.4,
        'loweralphaspecialnum': 0.5,
        'mixedalphanum': 0.6,
        'specialnum': 0.7,
        'mixedalpha': 0.7,
        'upperalphaspecial': 0.7,
        'loweralphaspecial': 0.8,
        'upperalphanum': 0.8,
        'loweralphanum': 0.9,
        'special': 0.9,
        'upperalpha': 0.95,
        'loweralpha': 0.95,
        'numeric': 1.0,
        'none': 1.0    # Worst complexity
    }
    complexity_factor = complexity_factors.get(complexity_label, 1.0)
    
    # Length factor using sigmoid function
    length_factor = 1.0 / (1.0 + math.exp((password_length - 10) / 2))
    
    # Dictionary factor
    dictionary_factor = min(1.0, 
                           (0.7 if is_common else 0) +
                           (0.5 if is_dictionary_word else 0) +
                           (min(0.8, 0.2 * banned_words_count)) +
                           (min(0.5, 0.1 * keyboard_patterns_count)))
    
    # Similarity factor
    similarity_factor = 0
    if similar_passwords:
        # Take the highest similarity score, scale it (0.7-1.0 becomes 0.0-0.5)
        max_similarity = similar_passwords[0][1]
        if max_similarity >= 0.9:  # 90% or more similar
            similarity_factor = 0.6
        elif max_similarity >= 0.8:  # 80-89% similar
            similarity_factor = 0.4
        elif max_similarity >= 0.7:  # 70-79% similar
            similarity_factor = 0.2
    
    # Combined factor calculation
    combined_factor = ((complexity_factor * length_factor) + 
                       dictionary_factor + 
                       similarity_factor)
    
    # Scale to 0-10 range
    base_score = combined_factor * (10.0/4.0)  # Adjusted for new similarity factor
    
    return min(10.0, base_score), complexity_factor, length_factor, dictionary_factor, similarity_factor


def calculate_temporal_score(base_score, days_out_of_compliance, password_set_to_expire):
    """
    Calculate the temporal score component (0-10) based on time-related factors.
    
    Args:
        base_score (float): The base score (0-10)
        days_out_of_compliance (int/str): Days past compliance period
        password_set_to_expire (str): Whether password is set to expire
        
    Returns:
        tuple: (temporal_score, compliance_factor, expiration_factor)
    """
    # Compliance factor (0.6-1.0)
    if days_out_of_compliance in ("Unknown", "N/A"):
        compliance_factor = 0.8  # Middle risk if unknown
    else:
        try:
            days = int(days_out_of_compliance) if isinstance(days_out_of_compliance, (int, str)) else 0
            compliance_factor = min(1.0, 0.6 + (0.4 * min(1.0, days / 180.0)))
        except (ValueError, TypeError):
            compliance_factor = 0.8  # Middle risk if error
    
    # Expiration factor (0.85-1.0)
    if password_set_to_expire == "Unknown":
        expiration_factor = 0.925  # Middle value if unknown
    else:
        expiration_factor = 1.0 if password_set_to_expire == 'No' else 0.85
    
    temporal_score = base_score * compliance_factor * expiration_factor
    return min(10.0, temporal_score), compliance_factor, expiration_factor


def calculate_environmental_score(temporal_score, has_da_path, controlled_object_count, shared_with, 
                                  domain_risk_level=None):
    """
    Calculate the environmental score component (0-10) based on context factors.
    
    Args:
        temporal_score (float): The temporal score (0-10)
        has_da_path (bool): Whether account has domain admin pathway
        controlled_object_count (int/str): Number of objects controlled
        shared_with (int): Number of accounts sharing this password
        domain_risk_level (str, optional): Risk level of the domain
        
    Returns:
        tuple: (environmental_score, privilege_factor, share_factor, domain_factor)
    """
    # Privilege factor (1.0-1.8)
    privilege_factor = 1.0
    if has_da_path:
        privilege_factor += 0.5
    
    if controlled_object_count != 'Unknown':
        try:
            obj_count = int(controlled_object_count)
            if obj_count > 1000:
                privilege_factor += 0.5  # Extreme control
            elif obj_count > 500:
                privilege_factor += 0.4  # Very high control
            elif obj_count > 100:
                privilege_factor += 0.3  # High control
            elif obj_count > 50:
                privilege_factor += 0.2  # Medium-high control
            elif obj_count > 10:
                privilege_factor += 0.1  # Medium control
        except (ValueError, TypeError):
            pass
    
    # Share factor (logarithmic scale)
    share_count = int(shared_with) if isinstance(shared_with, (int, str)) and shared_with != 'Unknown' else 0
    share_factor = 1.0
    if share_count > 0:
        if share_count >= 1000:  # S:4 - Extreme sharing
            share_factor += 0.5
        elif share_count >= 100:  # S:3 - Critical sharing
            share_factor += 0.4
        elif share_count >= 10:   # S:2 - High sharing
            share_factor += 0.3
        else:                     # S:1 - Low sharing
            share_factor += 0.2
    
    # Domain risk factor
    domain_factor = 1.0
    if domain_risk_level:
        domain_risk_map = {
            "Critical": 1.3,
            "High": 1.2,
            "Medium": 1.1,
            "Low": 1.0,
            "Unknown": 1.0
        }
        domain_factor = domain_risk_map.get(domain_risk_level, 1.0)
    
    # Combined environmental calculation
    environmental_score = temporal_score * privilege_factor * share_factor * domain_factor
    return min(10.0, environmental_score), privilege_factor, share_factor, domain_factor


def calculate_password_risk_score(password_analysis, shared_with, da_domains, controlled_object_count,
                                 similar_passwords=None, domain_risk_level=None):
    """
    Calculate the final CVSS-style risk score (0-10) for a password.
    
    Args:
        password_analysis (dict): Analysis of password characteristics
        shared_with (int): Number of accounts sharing this password
        da_domains (list/str): Domain admin pathways
        controlled_object_count (int/str): Number of objects controlled
        similar_passwords (list, optional): List of similar passwords
        domain_risk_level (str, optional): Risk level of the domain
        
    Returns:
        tuple: (final_score, score_breakdown, has_da_path)
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
    
    # Calculate base score
    base_score, complexity_factor, length_factor, dictionary_factor, similarity_factor = calculate_base_score(
        complexity_label, password_length, is_common, is_dictionary_word,
        banned_words_count, keyboard_patterns_count, similar_passwords
    )
    
    # Calculate temporal score
    temporal_score, compliance_factor, expiration_factor = calculate_temporal_score(
        base_score, days_out_of_compliance, password_set_to_expire
    )
    
    # Calculate environmental score
    has_da_path = da_domains and da_domains not in ('None', 'Unknown', [])
    final_score, privilege_factor, share_factor, domain_factor = calculate_environmental_score(
        temporal_score, has_da_path, controlled_object_count, shared_with, domain_risk_level
    )
    
    # Create score breakdown
    score_breakdown = {
        "base_score": round(base_score, 1),
        "base_components": {
            "complexity_factor": round(complexity_factor, 2),
            "length_factor": round(length_factor, 2),
            "dictionary_factor": round(dictionary_factor, 2),
            "similarity_factor": round(similarity_factor, 2),
        },
        "temporal_score": round(temporal_score, 1),
        "temporal_components": {
            "compliance_factor": round(compliance_factor, 2),
            "expiration_factor": round(expiration_factor, 2),
        },
        "environmental_score": round(final_score, 1),
        "environmental_components": {
            "privilege_factor": round(privilege_factor, 2),
            "share_factor": round(share_factor, 2),
            "domain_factor": round(domain_factor, 2)
        }
    }
    
    # Final score rounded to one decimal place
    return round(final_score, 1), score_breakdown, has_da_path


def compute_risk_level(score, has_da_path=False):
    """
    Convert 0-10 CVSS-style score to risk level.
    
    Args:
        score (float): Risk score (0-10)
        has_da_path (bool, optional): Whether account has domain admin pathway
        
    Returns:
        str: Risk level category (Critical, High, Medium, or Low)
    """
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