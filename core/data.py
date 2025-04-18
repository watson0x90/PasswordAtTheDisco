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
            if len(parts) == 3:
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
            if len(parts) == 2:
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