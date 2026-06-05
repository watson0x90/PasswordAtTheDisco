# core/domain_analysis.py
"""
Domain analysis module for evaluating password security across a domain.
Implements comprehensive domain-wide analysis and cross-domain sharing detection.
"""

import concurrent.futures
import logging
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Note: handle_bhe_data, extract_da_domains and extract_controllable_count are
# (re)defined locally below; only fetch_bhe_data is used from this import.
from core.bloodhound_integration import fetch_bhe_data
from core.config import policy
from core.hibp_correlation import HIBPChecker, categorize_hibp_risk
from core.password_analysis import analyze_password
from core.scoring import calculate_password_risk_score, compute_risk_level
from core.vector import generate_risk_vector
from utils.logging import get_logger

logger = get_logger('domain_analysis')

# Global shutdown event for graceful exit
shutdown_event = threading.Event()

# Initialize HIBP checker once at module level
# This will load the cache and index on first import
hibp_checker = None

def _get_hibp_checker():
    """Lazy initialization of HIBP checker."""
    global hibp_checker
    if hibp_checker is None:
        try:
            hibp_checker = HIBPChecker()
        except Exception as e:
            logger.warning(f"Could not initialize HIBP checker: {e}")
            # Create a disabled checker
            hibp_checker = type('obj', (object,), {'enabled': False, 'check_ntlm_hash': lambda self, h: (False, 0)})()
    return hibp_checker


def normalize_username(username: str, domain: str) -> str:
    """
    Ensure username has domain suffix, but only once.

    Handles usernames that may already include the domain suffix to prevent
    double-suffixing (e.g., user@DOMAIN.COM@DOMAIN.COM).

    Args:
        username (str): Username that may or may not include @DOMAIN suffix
        domain (str): Domain name to append if not already present

    Returns:
        str: Username with single domain suffix (e.g., user@DOMAIN.COM)
    """
    if '@' not in username:
        return f"{username}@{domain}"
    return username


def handle_bhe_data(bhe_data):
    """Helper function to safely extract BloodHound data regardless of format"""
    if isinstance(bhe_data, list) and bhe_data:
        bhe_item = bhe_data[0]
        return bhe_item.get('props', [{}])[0] if isinstance(bhe_item, dict) else {}
    elif isinstance(bhe_data, dict):
        return bhe_data.get('props', [{}])[0]
    return {}

def extract_da_domains(bhe_data):
    """Helper function to extract DA domains safely"""
    if isinstance(bhe_data, list) and bhe_data:
        bhe_item = bhe_data[0]
        if isinstance(bhe_item, dict):
            return [c['domain'] for c in bhe_item.get('controllables', []) 
                   if isinstance(c, dict) and c.get('labels', {}).get('has_da_path') is True] or 'None'
    elif isinstance(bhe_data, dict):
        return [c['domain'] for c in bhe_data.get('controllables', []) 
               if isinstance(c, dict) and c.get('labels', {}).get('has_da_path') is True] or 'None'
    return 'None'

def extract_controllable_count(bhe_data):
    """Helper function to extract controllable count safely"""
    controllables = []
    if isinstance(bhe_data, list) and bhe_data:
        bhe_item = bhe_data[0]
        if isinstance(bhe_item, dict):
            controllables = bhe_item.get('controllables', [])
    elif isinstance(bhe_data, dict):
        controllables = bhe_data.get('controllables', [])
    
    # Sum up controlled objects safely
    total = 0
    for c in controllables:
        if isinstance(c, dict):
            for k, v in c.get('labels', {}).items():
                if k != 'has_da_path' and str(v).isdigit():
                    total += int(v)
    return total


def analyze_domain(domain, cracked_accounts, uncracked_accounts, password_to_users_domain,
                  hash_to_users_domain, forbidden_words, keyboard_patterns,
                  common_passwords, dictionary_words, logger=None, domain_policy=None):
    """
    Main function to analyze password security for a domain.
    
    Args:
        domain (str): Domain name
        cracked_accounts (list): List of cracked account dictionaries
        uncracked_accounts (list): List of uncracked account dictionaries
        password_to_users_domain (dict): Mapping of passwords to usernames within domain
        hash_to_users_domain (dict): Mapping of password hashes to usernames within domain
        forbidden_words (set): Set of forbidden words
        keyboard_patterns (set): Set of keyboard patterns
        common_passwords (set): Set of common passwords
        dictionary_words (set): Set of dictionary words
        logger (Logger, optional): Logger instance
        
    Returns:
        dict: Comprehensive domain analysis results
    """
    try:
        # Initialize counters and tracking
        risk_counter = Counter()
        issues_counter = Counter()
        password_lengths = []
        complexity_counter = Counter()
        banned_word_counter = Counter()

        # Initialize HIBP checker
        checker = _get_hibp_checker()
        
        # Pre-compute shared counts
        shared_with_cracked = {acc['password']: len(password_to_users_domain[acc['password']]) - 1 
                              for acc in cracked_accounts}
        shared_with_uncracked = {acc['hash']: len(hash_to_users_domain[acc['hash']]) - 1 
                                for acc in uncracked_accounts}

        # Select accounts for BloodHound data (cracked + shared uncracked)
        bhe_targets = cracked_accounts + [acc for acc in uncracked_accounts
                                         if shared_with_uncracked[acc['hash']] > 0]
        usernames = [normalize_username(acc['username'], domain) for acc in bhe_targets]
        bhe_data_cache = {}

        # Collect all passwords for similarity analysis
        all_passwords = [acc['password'] for acc in cracked_accounts]

        # Fetch BloodHound data only if we have targets
        if bhe_targets and len(bhe_targets) > 0:
            # Single executor with shutdown handling
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(bhe_targets))) as executor:
                futures = {executor.submit(fetch_bhe_data, username, logger): username for username in usernames}
                for future in concurrent.futures.as_completed(futures):
                    if shutdown_event.is_set():
                        executor.shutdown(wait=False, cancel_futures=True)
                        if logger:
                            logger.info(f"Shutdown signal received, cancelling BloodHound data collection for {domain}")
                        break
                    username = futures[future]
                    try:
                        bhe_data_cache[username] = future.result()
                    except Exception as e:
                        if logger:
                            logger.error(f"Error fetching BloodHound data for {username}: {str(e)}")
                        bhe_data_cache[username] = {}

        password_cache = {}
        similarity_cache = {}
        output_rows = []
        enriched_cracked = []
        current_date = datetime.now(timezone.utc)

        # Use domain-specific policy or fall back to global policy
        active_policy = domain_policy if domain_policy is not None else policy
        max_password_age_days = active_policy.get('max_password_age_days', 90)

        # Process cracked accounts
        for acc in cracked_accounts:
            try:
                if shutdown_event.is_set():
                    if logger:
                        logger.info(f"Shutdown signal received, stopping cracked account processing for {domain}")
                    break
                
                pw = acc['password']
                username_key = normalize_username(acc['username'], domain)
                bhe_data = bhe_data_cache.get(username_key, {})

                # Check for password similarity
                if pw not in similarity_cache:
                    similarity_cache[pw] = calculate_password_similarity(pw, all_passwords)

                # Get or create password analysis
                if pw in password_cache:
                    analysis_result = password_cache[pw]
                else:
                    analysis_result = analyze_password(
                        pw, forbidden_words, keyboard_patterns,
                        common_passwords, dictionary_words, policy=active_policy)
                    password_cache[pw] = analysis_result

                # Extract analysis results
                password_length = analysis_result['password_length']
                complexity_label = analysis_result['complexity_label']
                meets_policy = analysis_result['meets_policy']
                policy_violations = analysis_result['policy_violations']
                banned_words_found = analysis_result['banned_words']
                keyboard_patterns_found = analysis_result['keyboard_patterns']
                is_common = analysis_result['is_common']
                is_exactly_dictionary_word = analysis_result['is_exactly_dictionary_word']

                # Update statistics
                password_lengths.append(password_length)
                complexity_counter[complexity_label] += 1
                issues_counter.update(policy_violations)
                banned_word_counter.update(banned_words_found)

                # Extract BloodHound data
                props = handle_bhe_data(bhe_data)
                pwd_last_set = props.get('pwdlastset', 'Unknown')
                pwd_never_expires = props.get('pwdneverexpires', 'Unknown')
                enabled = props.get('enabled', 'Unknown')
                when_created = props.get('whencreated', 'Unknown')
                last_logon = props.get('lastlogon', 'Unknown')
                last_logon_timestamp = props.get('lastlogontimestamp', 'Unknown')
                password_cant_change = props.get('passwordcantchange', 'Unknown')
                
                # Calculate days out of compliance
                days_out_of_compliance = "Unknown"
                if pwd_last_set != 'Unknown' and isinstance(pwd_last_set, (int, float)):
                    pwd_last_set_date = datetime.fromtimestamp(pwd_last_set, tz=timezone.utc)
                    days_since_set = (current_date - pwd_last_set_date).days
                    days_out_of_compliance = max(0, days_since_set - max_password_age_days)
                    pwd_last_set = pwd_last_set_date.strftime('%Y-%m-%d')
                else:
                    pwd_last_set_date = "Unknown"

                # Format dates
                when_created = datetime.fromtimestamp(when_created, tz=timezone.utc).strftime('%Y-%m-%d') if when_created != 'Unknown' and isinstance(when_created, (int, float)) else "Unknown"
                last_logon = datetime.fromtimestamp(last_logon, tz=timezone.utc).strftime('%Y-%m-%d') if last_logon != 'Unknown' and isinstance(last_logon, (int, float)) else "Unknown"
                last_logon_timestamp = datetime.fromtimestamp(last_logon_timestamp, tz=timezone.utc).strftime('%Y-%m-%d') if last_logon_timestamp != 'Unknown' and isinstance(last_logon_timestamp, (int, float)) else "Unknown"
                password_expires = 'No' if pwd_never_expires is True else 'Yes' if pwd_never_expires is False else 'Unknown'

                # Add time-based factors to analysis
                analysis_result['days_out_of_compliance'] = days_out_of_compliance
                analysis_result['password_set_to_expire'] = password_expires

                # Get DA domains and controlled objects
                shared_with = shared_with_cracked[pw]
                da_domains = extract_da_domains(bhe_data)
                controlled_object_count = extract_controllable_count(bhe_data)

                # Get similarity info for risk scoring
                similar_passwords = similarity_cache.get(pw, [])

                # Check HIBP for breach exposure
                ntlm_hash = acc['hash']
                is_breached, breach_count = checker.check_ntlm_hash(ntlm_hash) if checker.enabled else (False, 0)

                # Calculate CVSS-style risk score (with HIBP data)
                score, score_breakdown, has_da_path = calculate_password_risk_score(
                    analysis_result, shared_with, da_domains, controlled_object_count,
                    similar_passwords, hibp_breach_count=breach_count
                )
                risk = compute_risk_level(score, has_da_path)

                # Generate risk vector (with HIBP data)
                risk_vector = generate_risk_vector(
                    analysis_result, shared_with, da_domains, controlled_object_count,
                    similar_passwords, hibp_breach_count=breach_count
                )

                # Update risk counter
                risk_counter[risk] += 1

                # Format similar password info for display
                similar_password_info = []
                for similar_pw, similarity_score in similar_passwords[:3]:  # Top 3 similar passwords
                    similarity_percent = round(similarity_score * 100)
                    similar_password_info.append(f"{similar_pw} ({similarity_percent}%)")
                
                similar_password_text = ", ".join(similar_password_info) if similar_password_info else "None"

                # Create output row
                row = {
                    'Domain': domain,
                    'Username': acc['username'],
                    'Type': 'Cracked',
                    'Password': pw,
                    'Password Length': password_length,
                    'Complexity Label': complexity_label,
                    'Contains Unicode': 'Yes' if analysis_result['contains_unicode'] else 'No',
                    'Meets Policy': 'Yes' if meets_policy else 'No',
                    'Policy Violations': ', '.join(policy_violations),
                    'Forbidden Words': ', '.join(banned_words_found),
                    'Keyboard Patterns': ', '.join(keyboard_patterns_found),
                    'Common Password': 'Yes' if is_common else 'No',
                    'Is Exactly Dictionary Word': 'Yes' if is_exactly_dictionary_word else 'No',
                    'Similar Passwords': similar_password_text,
                    'Shared With': shared_with,
                    'HIBP Breached': 'Yes' if is_breached else 'No',
                    'HIBP Breach Count': breach_count if is_breached else 0,
                    'HIBP Risk Level': categorize_hibp_risk(breach_count),
                    'Risk Level': risk,
                    'Score': score,
                    'Score Breakdown': score_breakdown,
                    'Risk Vector': risk_vector,
                    'DA Domains': da_domains if isinstance(da_domains, str) else ', '.join(da_domains) if da_domains != 'None' else 'None',
                    'Controlled Object Count': controlled_object_count,
                    'Days Out of Compliance': days_out_of_compliance,
                    'Last Password Set': pwd_last_set,
                    'Password Set to Expire': password_expires,
                    'Enabled': 'Yes' if enabled is True else 'No' if enabled is False else 'Unknown',
                    'When Created': when_created,
                    'Last Logon': last_logon,
                    'Last Logon Timestamp': last_logon_timestamp,
                    'Password Cant Change': str(password_cant_change)
                }
                output_rows.append(row)
                enriched_cracked.append(row)
            except Exception as e:
                if logger:
                    logger.error(f"Error processing cracked account {acc['username']}: {str(e)}", exc_info=True)
                # Continue processing other accounts

        # Process uncracked accounts
        for acc in uncracked_accounts:
            try:
                if shutdown_event.is_set():
                    if logger:
                        logger.info(f"Shutdown signal received, stopping uncracked account processing for {domain}")
                    break
                
                h = acc['hash']
                shared_with = shared_with_uncracked[h]
                if shared_with > 0:
                    username_key = normalize_username(acc['username'], domain)
                    bhe_data = bhe_data_cache.get(username_key, {})
                    da_domains = extract_da_domains(bhe_data)
                    controlled_object_count = extract_controllable_count(bhe_data)
                else:
                    da_domains = 'None'
                    controlled_object_count = "Unknown"
                    bhe_data = {}

                # Check HIBP for uncracked hash
                ntlm_hash = h
                is_breached, breach_count = checker.check_ntlm_hash(ntlm_hash) if checker.enabled else (False, 0)

                # For uncracked passwords, use a simplified scoring based on sharing and privileges
                has_da_path = da_domains and da_domains not in ('None', 'Unknown', [])

                # Base score for uncracked hash is 5.0 (medium)
                temporal_score = 5.0

                # Calculate simplified environmental score (with HIBP)
                privilege_factor = 1.0
                if has_da_path:
                    privilege_factor += 0.5

                share_factor = 1.0
                if shared_with > 0:
                    if shared_with >= 1000:
                        share_factor += 0.5
                    elif shared_with >= 100:
                        share_factor += 0.4
                    elif shared_with >= 10:
                        share_factor += 0.3
                    else:
                        share_factor += 0.2

                # HIBP factor for uncracked hashes
                hibp_factor = 1.0
                if breach_count > 0:
                    if breach_count >= 100000:
                        hibp_factor = 1.5
                    elif breach_count >= 10000:
                        hibp_factor = 1.4
                    elif breach_count >= 1000:
                        hibp_factor = 1.3
                    elif breach_count >= 100:
                        hibp_factor = 1.2
                    else:
                        hibp_factor = 1.1

                final_score = temporal_score * privilege_factor * share_factor * hibp_factor
                score = round(min(10.0, final_score), 1)
                risk = compute_risk_level(score, has_da_path)

                # Simplified risk vector for uncracked hashes (with HIBP)
                hibp_level = "N"
                if breach_count >= 100000:
                    hibp_level = "C"
                elif breach_count >= 10000:
                    hibp_level = "E"
                elif breach_count >= 1000:
                    hibp_level = "VH"
                elif breach_count >= 100:
                    hibp_level = "H"
                elif breach_count >= 10:
                    hibp_level = "M"
                elif breach_count > 0:
                    hibp_level = "L"

                risk_vector = f"UNCRACKED/DA:{'Y' if has_da_path else 'N'}/CO:{'H' if controlled_object_count != 'Unknown' and int(controlled_object_count) > 50 else 'M' if controlled_object_count != 'Unknown' and int(controlled_object_count) > 10 else 'L'}/S:{min(9, shared_with)}/HIBP:{hibp_level}"
                
                row = {
                    'Domain': domain,
                    'Username': acc['username'],
                    'Type': 'Uncracked',
                    'Password': h,
                    'Password Length': 'N/A',
                    'Complexity Label': 'N/A',
                    'Contains Unicode': 'N/A',
                    'Meets Policy': 'N/A',
                    'Policy Violations': 'N/A',
                    'Forbidden Words': 'N/A',
                    'Keyboard Patterns': 'N/A',
                    'Common Password': 'N/A',
                    'Is Exactly Dictionary Word': 'N/A',
                    'Similar Passwords': 'N/A',
                    'Shared With': shared_with,
                    'HIBP Breached': 'Yes' if is_breached else 'No',
                    'HIBP Breach Count': breach_count if is_breached else 0,
                    'HIBP Risk Level': categorize_hibp_risk(breach_count),
                    'Risk Level': risk,
                    'Score': score,
                    'Risk Vector': risk_vector,
                    'DA Domains': da_domains if isinstance(da_domains, str) else ', '.join(da_domains) if da_domains != 'None' else 'None',
                    'Controlled Object Count': controlled_object_count,
                    'Days Out of Compliance': 'Unknown',
                    'Last Password Set': 'Unknown',
                    'Password Set to Expire': 'Unknown',
                    'Enabled': 'Unknown',  # Changed this line
                    'When Created': 'Unknown',
                    'Last Logon': 'Unknown',
                    'Last Logon Timestamp': 'Unknown',
                    'Password Cant Change': 'Unknown'
                }
                output_rows.append(row)
                risk_counter[risk] += 1
            except Exception as e:
                if logger:
                    logger.error(f"Error processing uncracked account {acc['username']}: {str(e)}", exc_info=True)
                # Continue processing other accounts
        
        # Post-processing: Identify passwords used by accounts with DA pathway
        da_passwords = {row['Password'] for row in output_rows 
                       if row['Password Length'] != 'N/A' and 
                       row.get('DA Domains', 'None') not in ('None', 'Unknown', [])}
        
        # Create a mapping of passwords to maximum controllable objects
        password_to_max_controllables = {}
        for row in output_rows:
            if row['Password Length'] != 'N/A':  # Only for cracked accounts
                password = row['Password']
                controllable_count = row.get('Controlled Object Count', 'Unknown')
                
                # Convert to integer if possible
                if controllable_count != 'Unknown':
                    try:
                        count_value = int(controllable_count)
                        
                        # Update maximum if this is higher
                        current_max = password_to_max_controllables.get(password, 0)
                        password_to_max_controllables[password] = max(current_max, count_value)
                    except (ValueError, TypeError):
                        pass
        
        # Update risk levels and scores based on shared passwords
        for row in output_rows:
            try:
                if row['Password Length'] != 'N/A':
                    password = row['Password']
                    previous_risk = row['Risk Level']
                    update_needed = False
                    
                    # Check if password is shared with DA account
                    if password in da_passwords and row.get('DA Domains', 'None') in ('None', 'Unknown', []):
                        row['Risk Level'] = "Critical"
                        row['Score'] = max(row['Score'], 8.0)
                        update_needed = True
                        
                        # Update risk vector to indicate DA password sharing
                        parts = row['Risk Vector'].split('/')
                        for i, part in enumerate(parts):
                            if part.startswith("DA:"):
                                parts[i] = "DA:S"  # Indicates shared with DA account
                        row['Risk Vector'] = '/'.join(parts)
                    
                    # Check if password is shared with high-privilege account (many controllables)
                    max_controllables = password_to_max_controllables.get(password, 0)
                    current_controllables = 0
                    
                    if row.get('Controlled Object Count', 'Unknown') != 'Unknown':
                        try:
                            current_controllables = int(row['Controlled Object Count'])
                        except (ValueError, TypeError):
                            pass
                    
                    # If this account shares password with another account that has significantly more privileges
                    if max_controllables > 0 and max_controllables > current_controllables * 2:
                        # Increase the environmental score component 
                        original_score = row['Score']
                        
                        # Increase score proportionally to the difference in privilege
                        privilege_boost = min(1.5, 1.0 + (max_controllables - current_controllables) / 100)
                        new_score = min(10.0, original_score * privilege_boost)
                        
                        # Round to one decimal place
                        row['Score'] = round(new_score, 1)
                        
                        # Update risk level based on new score
                        new_risk = compute_risk_level(new_score, False)
                        
                        if new_risk != previous_risk:
                            row['Risk Level'] = new_risk
                            update_needed = True
                            
                            # Update risk vector to indicate shared privileges
                            parts = row['Risk Vector'].split('/')
                            for i, part in enumerate(parts):
                                if part.startswith("CO:"):
                                    parts[i] = f"CO:S{part[3:]}"  # Indicates shared privileges
                            row['Risk Vector'] = '/'.join(parts)
                    
                    # Update risk counter if risk level changed
                    if update_needed and previous_risk != row['Risk Level']:
                        risk_counter[previous_risk] -= 1
                        risk_counter[row['Risk Level']] += 1
            except Exception as e:
                if logger:
                    logger.error(f"Error updating risk for {row.get('Username', 'unknown')}: {str(e)}", exc_info=True)
                # Continue processing other rows

        # Calculate domain-wide risk metrics
        domain_risk = calculate_domain_risk({
            "output_rows": output_rows,
            "risk_counter": risk_counter
        })

        return {
            'output_rows': output_rows,
            'risk_counter': risk_counter,
            'issues_counter': issues_counter,
            'password_lengths': password_lengths,
            'complexity_counter': complexity_counter,
            'banned_word_counter': banned_word_counter,
            'enriched_cracked': enriched_cracked,
            'domain_risk': domain_risk
        }
    except Exception as e:
        if logger:
            logger.error(f"Critical error analyzing domain {domain}: {str(e)}", exc_info=True)
        # Return minimal data in case of critical failure
        return {
            'output_rows': [],
            'risk_counter': Counter(),
            'issues_counter': Counter(),
            'password_lengths': [],
            'complexity_counter': Counter(),
            'banned_word_counter': Counter(),
            'enriched_cracked': [],
            'domain_risk': {}
        }


def calculate_password_similarity(password, other_passwords):
    """
    Calculate similarity to other passwords.

    Args:
        password (str): The password to check
        other_passwords (list): List of passwords to compare against

    Returns:
        list: List of similar passwords with similarity scores
    """
    # Optional import for Levenshtein
    try:
        import Levenshtein
        levenshtein_available = True
    except ImportError:
        levenshtein_available = False

    similar_passwords = []
    if levenshtein_available:
        for other_pw in other_passwords:
            if other_pw == password:
                continue
            # Calculate Levenshtein ratio (0-1 scale where 1 is identical)
            similarity = Levenshtein.ratio(password, other_pw)
            if similarity >= 0.7:  # 70% similar or higher
                similar_passwords.append((other_pw, similarity))
    else:
        # Fallback: simple exact match detection only
        for other_pw in other_passwords:
            if other_pw == password:
                similar_passwords.append((other_pw, 1.0))

    # Sort by similarity (highest first)
    return sorted(similar_passwords, key=lambda x: x[1], reverse=True)


def calculate_domain_risk(data):
    """
    Calculate aggregate risk metrics for an entire domain.
    
    Args:
        data (dict): Domain data including output_rows and risk_counter
        
    Returns:
        dict: Domain risk metrics
    """
    output_rows = data.get('output_rows', [])
    
    # Get the risk counter from data, or calculate from output rows if not provided
    if 'risk_counter' in data and data['risk_counter']:
        risk_counter = data['risk_counter']
    else:
        # Calculate risk counter from output rows
        risk_counter = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for row in output_rows:
            if row.get('Password Length', 'N/A') != 'N/A':  # Only count cracked passwords
                risk_level = row.get('Risk Level', 'Unknown')
                if risk_level in risk_counter:
                    risk_counter[risk_level] += 1
    
    # Extract scores for cracked passwords only
    cracked_rows = [row for row in output_rows if row.get('Password Length', 'N/A') != 'N/A']
    scores = [row.get('Score', 0) for row in cracked_rows]
    
    # Calculate average and maximum scores
    avg_score = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0
    
    # Calculate weighted domain risk
    # Weighted by severity: Critical=1.0, High=0.6, Medium=0.25, Low=0.05
    weights = {"Critical": 1.0, "High": 0.6, "Medium": 0.25, "Low": 0.05}
    total_accounts = sum(risk_counter.values())
    if total_accounts > 0:
        weighted_sum = sum(weights[level] * count for level, count in risk_counter.items())
        domain_risk_score = min(10.0, (weighted_sum / total_accounts) * 10)
    else:
        domain_risk_score = 0
    
    # Determine overall risk level for domain
    overall_risk_level = compute_risk_level(domain_risk_score)
    
    # Calculate percentages based on the total number of cracked accounts
    risk_percentage = {}
    for level, count in risk_counter.items():
        risk_percentage[level] = round((count/total_accounts)*100, 1) if total_accounts > 0 else 0
    
    return {
        "avg_score": round(avg_score, 1),
        "max_score": round(max_score, 1),
        "risk_distribution": risk_counter,
        "risk_percentage": risk_percentage,
        "overall_risk_level": overall_risk_level,
        "risk_score": round(domain_risk_score, 1)
    }


def analyze_cross_domain_sharing(all_cracked, all_uncracked, domains):
    """
    Analyze password sharing across domains.
    
    Args:
        all_cracked (list): List of all cracked accounts across domains
        all_uncracked (list): List of all uncracked accounts across domains
        domains (list): List of domain names
        
    Returns:
        tuple: (combined_rows, global_password_to_users, global_hash_to_users)
    """
    try:
        if shutdown_event.is_set():
            return [], defaultdict(list), defaultdict(list)
        
        global_password_to_users = defaultdict(list)
        global_hash_to_users = defaultdict(list)
        combined_rows = []
        
        # Collect domain risk levels to enhance cross-domain risk assessment
        
        # First pass: gather all cracked and uncracked accounts
        for acc in all_cracked:
            try:
                domain = acc.get('Domain', acc.get('domain', 'Unknown'))
                global_password_to_users[acc['password']].append(
                    (acc['username'], domain, acc.get('Score', 0), acc.get('Risk Level', 'Unknown')))
            except Exception as e:
                logging.error(f"Error processing cracked account: {str(e)}")
                
        for acc in all_uncracked:
            try:
                domain = acc.get('Domain', acc.get('domain', 'Unknown'))
                global_hash_to_users[acc['hash']].append(
                    (acc['username'], domain, 0, 'Unknown'))
            except Exception as e:
                logging.error(f"Error processing uncracked account: {str(e)}")
        
        # Second pass: analyze shared credentials
        for acc in all_cracked:
            try:
                pw = acc['password']
                domain = acc.get('Domain', acc.get('domain', 'Unknown'))
                users = global_password_to_users[pw]
                shared_with = len(users) - 1
                
                if shared_with > 0:
                    # Identify domains where this password is shared
                    shared_domains = set()
                    for _, user_domain, _, _ in users:
                        if user_domain != domain:
                            shared_domains.add(user_domain)
                    
                    domains_shared = ', '.join(sorted(shared_domains))
                    
                    # Identify if password is shared with DA accounts
                    is_shared_with_da = False
                    for _, _, _, risk_level in users:
                        if risk_level == "Critical":
                            is_shared_with_da = True
                            break
                    
                    # Apply cross-domain risk assessment
                    cross_domain_risk_modifier = 1.0
                    if len(shared_domains) >= 3:  # Shared across 3+ domains
                        cross_domain_risk_modifier = 1.3
                    elif len(shared_domains) == 2:  # Shared across 2 domains
                        cross_domain_risk_modifier = 1.2
                    
                    # Adjust score for cross-domain sharing
                    base_score = acc.get('Score', 5.0)  # Default to medium if no score
                    modified_score = min(10.0, base_score * cross_domain_risk_modifier)
                    risk_level = compute_risk_level(modified_score, is_shared_with_da)
                    
                    row = {
                        'Domain': domain,
                        'Username': acc['username'],
                        'Password': pw,
                        'Shared With': shared_with,
                        'Domains Shared': domains_shared,
                        'Score': modified_score,
                        'Risk Level': risk_level,
                        'Risk Vector': acc.get('Risk Vector', 'Unknown'),
                        'DA Domains': acc.get('DA Domains', 'None'),
                        'Controlled Object Count': acc.get('Controlled Object Count', 'Unknown'),
                        'Days Out of Compliance': acc.get('Days Out of Compliance', 'Unknown'),
                        'Last Password Set': acc.get('Last Password Set', 'Unknown'),
                        'Password Set to Expire': acc.get('Password Set to Expire', 'Unknown'),
                        'Enabled': acc.get('Enabled', 'Unknown'),
                        'When Created': acc.get('When Created', 'Unknown'),
                        'Last Logon': acc.get('Last Logon', 'Unknown'),
                        'Last Logon Timestamp': acc.get('Last Logon Timestamp', 'Unknown'),
                        'Password Cant Change': acc.get('Password Cant Change', 'Unknown')
                    }
                    combined_rows.append(row)
            except Exception as e:
                logging.error(f"Error analyzing cracked account in cross-domain: {str(e)}")
        
        # Process uncracked accounts with shared hashes
        for acc in all_uncracked:
            try:
                h = acc['hash']
                domain = acc.get('Domain', acc.get('domain', 'Unknown'))
                users = global_hash_to_users[h]
                shared_with = len(users) - 1
                
                if shared_with > 0:
                    # Identify domains where this hash is shared
                    shared_domains = set()
                    for _, user_domain, _, _ in users:
                        if user_domain != domain:
                            shared_domains.add(user_domain)
                    
                    domains_shared = ', '.join(sorted(shared_domains))
                    
                    # Apply cross-domain risk assessment
                    cross_domain_risk_modifier = 1.0
                    if len(shared_domains) >= 3:  # Shared across 3+ domains
                        cross_domain_risk_modifier = 1.3
                    elif len(shared_domains) == 2:  # Shared across 2 domains
                        cross_domain_risk_modifier = 1.2
                    
                    # Base score for uncracked hash is 5.0 (medium)
                    base_score = 5.0
                    modified_score = min(10.0, base_score * cross_domain_risk_modifier)
                    
                    row = {
                        'Domain': domain,
                        'Username': acc['username'],
                        'Password': h,
                        'Shared With': shared_with,
                        'Domains Shared': domains_shared,
                        'Score': modified_score,
                        'Risk Level': compute_risk_level(modified_score),
                        'Risk Vector': f"UNCRACKED/S:{min(9, shared_with)}/CD:{len(shared_domains)}",
                        'DA Domains': acc.get('DA Domains', 'Unknown'),
                        'Controlled Object Count': acc.get('Controlled Object Count', 'Unknown'),
                        'Days Out of Compliance': 'Unknown',
                        'Last Password Set': 'Unknown',
                        'Password Set to Expire': 'Unknown',
                        'Enabled': acc.get('Enabled', 'Unknown'),
                        'When Created': 'Unknown',
                        'Last Logon': 'Unknown',
                        'Last Logon Timestamp': 'Unknown',
                        'Password Cant Change': 'Unknown'
                    }
                    combined_rows.append(row)
            except Exception as e:
                logging.error(f"Error analyzing uncracked account in cross-domain: {str(e)}")
        
        # Calculate cross-domain risk metrics
        cross_domain_risk = calculate_domain_risk({"output_rows": combined_rows})
        for row in combined_rows:
            row['Cross Domain Risk Score'] = cross_domain_risk['risk_score']
            row['Cross Domain Risk Level'] = cross_domain_risk['overall_risk_level']
        
        return combined_rows, global_password_to_users, global_hash_to_users
    except Exception as e:
        logging.error(f"Critical error in cross-domain analysis: {str(e)}")
        return [], defaultdict(list), defaultdict(list)