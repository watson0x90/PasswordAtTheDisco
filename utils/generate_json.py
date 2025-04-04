import json
import os
from collections import defaultdict
from core.config import reports_folder
from core.data import process_domain
from core.analysis import analyze_domain, analyze_cross_domain_sharing
from utils.file_utils import load_list
from utils.logging import setup_logger

def generate_json(domains, output_file, logger=None):
    if not logger:
        logger = setup_logger()

    try:
        forbidden_words = load_list('lists/forbidden_words.txt')
        keyboard_patterns = load_list('lists/keyboard_patterns.txt')
        common_passwords = load_list('lists/common_passwords.txt')
        dictionary_words = load_list('lists/dictionary_words.txt')
    except Exception as e:
        logger.error(f"Error loading word lists: {str(e)}")
        return

    all_data = {"domains": {}, "combined": {}}
    all_cracked = []
    all_uncracked = []
    domain_list = [d.split(':')[0] for d in domains]

    for domain_entry in domains:
        try:
            domain, cracked_file, uncracked_file = domain_entry.split(':')
            cracked_accounts, uncracked_accounts = process_domain(domain, cracked_file, uncracked_file)
            domain_data = {
                'cracked': cracked_accounts,
                'uncracked': uncracked_accounts,
                'password_to_users': defaultdict(list),
                'hash_to_users': defaultdict(list)
            }
            for acc in cracked_accounts:
                domain_data['password_to_users'][acc['password']].append(acc['username'])
            for acc in uncracked_accounts:
                domain_data['hash_to_users'][acc['hash']].append(acc['username'])

            result = analyze_domain(domain, domain_data['cracked'], domain_data['uncracked'], 
                                  domain_data['password_to_users'], domain_data['hash_to_users'], 
                                  forbidden_words, keyboard_patterns, common_passwords, dictionary_words, logger)
            
            all_data['domains'][domain] = {
                'output_rows': result['output_rows'],
                'password_lengths': result['password_lengths'],
                'risk_counter': dict(result['risk_counter']),
                'issues_counter': dict(result['issues_counter']),
                'complexity_counter': dict(result['complexity_counter']),
                'banned_word_counter': dict(result['banned_word_counter'])
            }

            for acc in cracked_accounts:
                acc['Domain'] = domain
            for acc in uncracked_accounts:
                acc['Domain'] = domain
            all_cracked.extend(cracked_accounts)
            all_uncracked.extend(uncracked_accounts)
        except Exception as e:
            logger.error(f"Error processing domain {domain_entry}: {str(e)}")

    try:
        combined_rows, global_password_to_users, global_hash_to_users = analyze_cross_domain_sharing(all_cracked, all_uncracked, domain_list)
        all_data['combined'] = {
            'combined_rows': combined_rows,
            'global_password_to_users': {k: list(v) for k, v in global_password_to_users.items()},
            'global_hash_to_users': {k: list(v) for k, v in global_hash_to_users.items()},
            'all_cracked': all_cracked,
            'all_uncracked': all_uncracked
        }
    except Exception as e:
        logger.error(f"Error generating combined data: {str(e)}")

    os.makedirs(reports_folder, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_data, f, indent=2)
    logger.info(f"Generated JSON data file: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python generate_json.py <domain1:cracked_file1:uncracked_file1> <domain2:cracked_file2:uncracked_file2> ...")
        sys.exit(1)
    generate_json(sys.argv[1:], reports_folder / 'password_data.json')