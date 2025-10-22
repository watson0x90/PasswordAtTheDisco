# core/data.py
"""
Data processing module for the password audit tool.
Handles loading and processing of password data files.
"""

from utils.file_utils import decode_hex
from models.account import Account
from models.password import Password


def process_domain(domain, cracked_file, uncracked_file):
    """
    Process password data files for a domain.

    Supports two formats:
    1. Simple format: username:hash:password
    2. SecretsDump format: username:rid:lm_hash:ntlm_hash::::password

    Args:
        domain (str): The domain name
        cracked_file (str): Path to the file containing cracked passwords
        uncracked_file (str): Path to the file containing uncracked passwords

    Returns:
        tuple: Lists of cracked and uncracked account dictionaries
    """
    cracked_accounts = []
    with open(cracked_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')

            # SecretsDump format: username:rid:lm_hash:ntlm_hash::::password
            if len(parts) >= 8:
                username = parts[0]
                ntlm_hash = parts[3]  # NTLM hash is at index 3
                password = parts[-1]   # Password is last field

                # Skip if no password (empty field)
                if not password:
                    continue

                password = decode_hex(password)
                cracked_accounts.append({
                    'username': username,
                    'hash': ntlm_hash,
                    'password': password,
                    'domain': domain
                })
            # Simple format: username:hash:password
            elif len(parts) == 3:
                username, hash_, password = parts
                password = decode_hex(password)
                cracked_accounts.append({
                    'username': username,
                    'hash': hash_,
                    'password': password,
                    'domain': domain
                })

    uncracked_accounts = []
    with open(uncracked_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')

            # SecretsDump format: username:rid:lm_hash:ntlm_hash::::
            if len(parts) >= 7:
                username = parts[0]
                ntlm_hash = parts[3]  # NTLM hash is at index 3
                uncracked_accounts.append({
                    'username': username,
                    'hash': ntlm_hash,
                    'password': None,
                    'domain': domain
                })
            # Simple format: username:hash
            elif len(parts) == 2:
                username, hash_ = parts
                uncracked_accounts.append({
                    'username': username,
                    'hash': hash_,
                    'password': None,
                    'domain': domain
                })

    return cracked_accounts, uncracked_accounts


def map_accounts_to_models(cracked_accounts, uncracked_accounts):
    """
    Convert raw account dictionaries to Account model objects.
    
    Args:
        cracked_accounts (list): List of cracked account dictionaries
        uncracked_accounts (list): List of uncracked account dictionaries
        
    Returns:
        tuple: Lists of cracked and uncracked Account objects
    """
    cracked_models = []
    for acc in cracked_accounts:
        password = Password(acc['password'], is_cracked=True, hash_value=acc['hash'])
        account = Account(
            username=acc['username'],
            domain=acc['domain'],
            password=password
        )
        cracked_models.append(account)
    
    uncracked_models = []
    for acc in uncracked_accounts:
        password = Password(None, is_cracked=False, hash_value=acc['hash'])
        account = Account(
            username=acc['username'],
            domain=acc['domain'],
            password=password
        )
        uncracked_models.append(account)
    
    return cracked_models, uncracked_models