from collections import Counter
import concurrent.futures
from core.bloodhound_client import get_user_data
from collections import defaultdict
from core.config import policy
from datetime import datetime, timezone
import logging
import threading
import string

# Global shutdown event for graceful exit
shutdown_event = threading.Event()

def fetch_bhe_data(username, logger=None):
    if shutdown_event.is_set():
        return {}
    result = get_user_data(username, logger=logger)
    return result[0] if result else {}

def has_lower(pw):
    return any(c.islower() for c in pw)

def has_upper(pw):
    return any(c.isupper() for c in pw)

def has_digit(pw):
    return any(c.isdigit() for c in pw)

def has_special(pw):
    return any(not c.isalnum() for c in pw)

def has_unicode(pw):
    return any(ord(c) > 127 for c in pw)

def check_password_complexity(pw):
    """Determine the complexity category of a password based on character types."""
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

def check_policy(pw, policy):
    min_length = policy.get('min_length', 8)
    require_lowercase = policy.get('require_lowercase', True)
    require_uppercase = policy.get('require_uppercase', True)
    require_digits = policy.get('require_digits', True)
    require_special = policy.get('require_special', True)

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

def calculate_cracked_score(pw, analysis, shared_with, da_domains, controlled_object_count):
    score = 0
    min_length = policy.get('min_length', 8)
    if analysis['password_length'] < 8:
        score += 20
    elif analysis['password_length'] < min_length:
        score += 10
    
    if not analysis['meets_policy']:
        score += 10
    score += len(analysis['policy_violations']) * 5
    
    if analysis['is_common']:
        score += 20
    if analysis['is_exactly_dictionary_word']:
        score += 15
    score += len(analysis['banned_words']) * 10
    score += len(analysis['keyboard_patterns']) * 5

    if da_domains and da_domains not in ('None', 'Unknown', []):
        score += 25
    
    if controlled_object_count != 'Unknown':
        controllable_count = int(controlled_object_count)
        if controllable_count > 50:
            score += 20
        elif controllable_count > 10:
            score += 10
    
    if shared_with > 0:
        score += min(20, shared_with * 5)

    return min(100, score)

def calculate_uncracked_score(shared_with, da_domains, controlled_object_count):
    score = 0
    if shared_with > 0:
        score += min(25, shared_with * 5)
    if da_domains and da_domains not in ('None', 'Unknown', []):
        score += 30
    if controlled_object_count != 'Unknown':
        controllable_count = int(controlled_object_count)
        if controllable_count > 50:
            score += 25
        elif controllable_count > 10:
            score += 15
    return min(100, score)

def compute_risk(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

def analyze_domain(domain, cracked_accounts, uncracked_accounts, password_to_users_domain, hash_to_users_domain, forbidden_words, keyboard_patterns, common_passwords, dictionary_words, logger=None):
    risk_counter = Counter()
    issues_counter = Counter()
    password_lengths = []
    complexity_counter = Counter()
    banned_word_counter = Counter()
    
    # Pre-compute shared counts
    shared_with_cracked = {acc['password']: len(password_to_users_domain[acc['password']]) - 1 for acc in cracked_accounts}
    shared_with_uncracked = {acc['hash']: len(hash_to_users_domain[acc['hash']]) - 1 for acc in uncracked_accounts}

    # Select accounts for BloodHound data (cracked + shared uncracked)
    bhe_targets = cracked_accounts + [acc for acc in uncracked_accounts if shared_with_uncracked[acc['hash']] > 0]
    usernames = [f"{acc['username']}@{domain}" for acc in bhe_targets]
    bhe_data_cache = {}

    # Single executor with shutdown handling
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(bhe_targets))) as executor:
        futures = {executor.submit(fetch_bhe_data, username, logger): username for username in usernames}
        for future in concurrent.futures.as_completed(futures):
            if shutdown_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                logger.info(f"Shutdown signal received, cancelling BloodHound data collection for {domain}")
                break
            username = futures[future]
            try:
                bhe_data_cache[username] = future.result()
            except Exception as e:
                logger.error(f"Error fetching BloodHound data for {username}: {str(e)}")
                bhe_data_cache[username] = {}

    password_cache = {}
    output_rows = []
    enriched_cracked = []
    current_date = datetime.now(timezone.utc)
    max_password_age_days = policy.get('max_password_age_days', 90)

    # Process cracked accounts
    for acc in cracked_accounts:
        if shutdown_event.is_set():
            logger.info(f"Shutdown signal received, stopping cracked account processing for {domain}")
            break
        
        pw = acc['password']
        username_key = f"{acc['username']}@{domain}"
        bhe_data = bhe_data_cache.get(username_key, {})

        if pw in password_cache:
            (password_length, complexity_label, meets_policy, policy_violations, 
             banned_words_found, keyboard_patterns_found, is_common, 
             is_exactly_dictionary_word, score, risk) = password_cache[pw]
        else:
            password_length = len(pw)
            complexity_label = check_password_complexity(pw)  # Updated to use new function
            meets_policy, policy_violations = check_policy(pw, policy)
            banned_words_found = [w for w in forbidden_words if w in pw.lower()]
            keyboard_patterns_found = [p for p in keyboard_patterns if p in pw.lower()]
            is_common = pw in common_passwords
            is_exactly_dictionary_word = pw.lower() in dictionary_words
            
            analysis = {
                'password_length': password_length,
                'meets_policy': meets_policy,
                'policy_violations': policy_violations,
                'banned_words': banned_words_found,
                'keyboard_patterns': keyboard_patterns_found,
                'is_common': is_common,
                'is_exactly_dictionary_word': is_exactly_dictionary_word,
            }
            shared_with = shared_with_cracked[pw]
            da_domains = [c['domain'] for c in bhe_data.get('controllables', []) if c['labels'].get('has_da_path') == True] or 'None'
            controlled_object_count = sum(
                int(v) for c in bhe_data.get('controllables', []) 
                for k, v in c['labels'].items() if k != 'has_da_path' and str(v).isdigit()
            ) if bhe_data.get('controllables') else "Unknown"

            score = calculate_cracked_score(pw, analysis, shared_with, da_domains, controlled_object_count)
            risk = compute_risk(score)
            password_cache[pw] = (password_length, complexity_label, meets_policy, policy_violations, 
                                  banned_words_found, keyboard_patterns_found, is_common, 
                                  is_exactly_dictionary_word, score, risk)

        if logger:
            logger.debug(f"User: {acc['username']}, Score: {score}, Risk: {risk}")

        password_lengths.append(password_length)
        complexity_counter[complexity_label] += 1
        risk_counter[risk] += 1
        issues_counter.update(policy_violations)
        banned_word_counter.update(banned_words_found)

        props = bhe_data.get('props', [{}])[0]
        pwd_last_set = props.get('pwdlastset', 'Unknown')
        pwd_never_expires = props.get('pwdneverexpires', 'Unknown')
        enabled = props.get('enabled', 'Unknown')
        when_created = props.get('whencreated', 'Unknown')
        last_logon = props.get('lastlogon', 'Unknown')
        last_logon_timestamp = props.get('lastlogontimestamp', 'Unknown')
        password_cant_change = props.get('passwordcantchange', 'Unknown')
        
        days_out_of_compliance = "Unknown"
        if pwd_last_set != 'Unknown' and isinstance(pwd_last_set, (int, float)):
            pwd_last_set_date = datetime.fromtimestamp(pwd_last_set, tz=timezone.utc)
            days_since_set = (current_date - pwd_last_set_date).days
            days_out_of_compliance = max(0, days_since_set - max_password_age_days)
            pwd_last_set = pwd_last_set_date.strftime('%Y-%m-%d')
        else:
            pwd_last_set_date = "Unknown"

        when_created = datetime.fromtimestamp(when_created, tz=timezone.utc).strftime('%Y-%m-%d') if when_created != 'Unknown' and isinstance(when_created, (int, float)) else "Unknown"
        last_logon = datetime.fromtimestamp(last_logon, tz=timezone.utc).strftime('%Y-%m-%d') if last_logon != 'Unknown' and isinstance(last_logon, (int, float)) else "Unknown"
        last_logon_timestamp = datetime.fromtimestamp(last_logon_timestamp, tz=timezone.utc).strftime('%Y-%m-%d') if last_logon_timestamp != 'Unknown' and isinstance(last_logon_timestamp, (int, float)) else "Unknown"
        password_expires = 'No' if pwd_never_expires is True else 'Yes' if pwd_never_expires is False else 'Unknown'

        row = {
            'Domain': domain,
            'Username': acc['username'],
            'Password': pw,
            'Password Length': password_length,
            'Complexity Label': complexity_label,
            'Contains Unicode': 'Yes' if has_unicode(pw) else 'No',
            'Meets Policy': 'Yes' if meets_policy else 'No',
            'Policy Violations': ', '.join(policy_violations),
            'Forbidden Words': ', '.join(banned_words_found),
            'Keyboard Patterns': ', '.join(keyboard_patterns_found),
            'Common Password': 'Yes' if is_common else 'No',
            'Is Exactly Dictionary Word': 'Yes' if is_exactly_dictionary_word else 'No',
            'Shared With': shared_with,
            'Risk Level': risk,
            'Score': score,
            'DA Domains': da_domains if isinstance(da_domains, str) else ', '.join(da_domains) if da_domains != 'None' else 'None',
            'Controlled Object Count': controlled_object_count,
            'Days Out of Compliance': days_out_of_compliance,
            'Last Password Set': pwd_last_set,
            'Password Set to Expire': password_expires,
            'Enabled': str(enabled),
            'When Created': when_created,
            'Last Logon': last_logon,
            'Last Logon Timestamp': last_logon_timestamp,
            'Password Cant Change': str(password_cant_change)
        }
        output_rows.append(row)
        acc.update(row)
        enriched_cracked.append(acc)

    # Process uncracked accounts
    for acc in uncracked_accounts:
        if shutdown_event.is_set():
            logger.info(f"Shutdown signal received, stopping uncracked account processing for {domain}")
            break
        
        h = acc['hash']
        shared_with = shared_with_uncracked[h]
        if shared_with > 0:
            username_key = f"{acc['username']}@{domain}"
            bhe_data = bhe_data_cache.get(username_key, {})
            da_domains = [c['domain'] for c in bhe_data.get('controllables', []) if c['labels'].get('has_da_path') == True] or 'None'
            controlled_object_count = sum(
                int(v) for c in bhe_data.get('controllables', []) 
                for k, v in c['labels'].items() if k != 'has_da_path' and str(v).isdigit()
            ) if bhe_data.get('controllables') else "Unknown"
        else:
            da_domains = 'None'
            controlled_object_count = "Unknown"
            bhe_data = {}

        score = calculate_uncracked_score(shared_with, da_domains, controlled_object_count)
        risk = compute_risk(score)
        
        row = {
            'Domain': domain,
            'Username': acc['username'],
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
            'Shared With': shared_with,
            'Risk Level': risk,
            'Score': score,
            'DA Domains': da_domains if isinstance(da_domains, str) else ', '.join(da_domains) if da_domains != 'None' else 'None',
            'Controlled Object Count': controlled_object_count,
            'Days Out of Compliance': 'Unknown',
            'Last Password Set': 'Unknown',
            'Password Set to Expire': 'Unknown',
            'Enabled': str(bhe_data.get('props', [{}])[0].get('enabled', 'Unknown')) if shared_with > 0 else 'Unknown',
            'When Created': 'Unknown',
            'Last Logon': 'Unknown',
            'Last Logon Timestamp': 'Unknown',
            'Password Cant Change': 'Unknown'
        }
        output_rows.append(row)
        risk_counter[risk] += 1

    if logger:
        logger.info(f"Final risk counter for {domain}: {dict(risk_counter)}")
    
    return {
        'output_rows': output_rows,
        'risk_counter': risk_counter,
        'issues_counter': issues_counter,
        'password_lengths': password_lengths,
        'complexity_counter': complexity_counter,
        'banned_word_counter': banned_word_counter,
        'enriched_cracked': enriched_cracked
    }

def analyze_cross_domain_sharing(all_cracked, all_uncracked, domains):
    if shutdown_event.is_set():
        return [], defaultdict(list), defaultdict(list)
    
    global_password_to_users = defaultdict(list)
    global_hash_to_users = defaultdict(list)
    combined_rows = []
    
    for acc in all_cracked:
        global_password_to_users[acc['password']].append((acc['username'], acc['Domain'], acc['Score'], acc['Risk Level']))
    for acc in all_uncracked:
        global_hash_to_users[acc['hash']].append((acc['username'], acc['Domain'], 0, 'Unknown'))
    
    for acc in all_cracked:
        pw = acc['password']
        users = global_password_to_users[pw]
        shared_with = len(users) - 1
        if shared_with > 0:
            domains_shared = ', '.join(sorted(set(x[1] for x in users)))
            row = {
                'Domain': acc['Domain'],
                'Username': acc['username'],
                'Password': pw,
                'Shared With': shared_with,
                'Domains Shared': domains_shared,
                'Score': acc['Score'],
                'Risk Level': acc['Risk Level'],
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
    
    for acc in all_uncracked:
        h = acc['hash']
        users = global_hash_to_users[h]
        shared_with = len(users) - 1
        if shared_with > 0:
            domains_shared = ', '.join(sorted(set(x[1] for x in users)))
            row = {
                'Domain': acc['Domain'],
                'Username': acc['username'],
                'Password': h,
                'Shared With': shared_with,
                'Domains Shared': domains_shared,
                'Score': 0,
                'Risk Level': 'Unknown',
                'DA Domains': 'Unknown',
                'Controlled Object Count': 'Unknown',
                'Days Out of Compliance': 'Unknown',
                'Last Password Set': 'Unknown',
                'Password Set to Expire': 'Unknown',
                'Enabled': 'Unknown',
                'When Created': 'Unknown',
                'Last Logon': 'Unknown',
                'Last Logon Timestamp': 'Unknown',
                'Password Cant Change': 'Unknown'
            }
            combined_rows.append(row)
    
    return combined_rows, global_password_to_users, global_hash_to_users