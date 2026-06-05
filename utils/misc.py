# utils/misc.py
"""
Miscellaneous utility functions for the password audit tool.
Enhanced with robust error handling.
"""

import os
import shutil
from contextlib import contextmanager


def count_accounts_in_domain(domain_entry):
    """
    Count the number of accounts in a domain without processing them.
    Fast preliminary count for progress tracking.
    
    Args:
        domain_entry (str): Domain entry string in format domain:cracked_file:uncracked_file
        
    Returns:
        int: Total number of accounts or default estimate if count fails
    """
    try:
        domain, cracked_file, uncracked_file = domain_entry.split(':')
        
        # Count cracked accounts
        cracked_count = 0
        if os.path.exists(cracked_file):
            with open(cracked_file, 'r', encoding='utf-8') as f:
                for _ in f:
                    cracked_count += 1
                    
        # Count uncracked accounts
        uncracked_count = 0
        if os.path.exists(uncracked_file):
            with open(uncracked_file, 'r', encoding='utf-8') as f:
                for _ in f:
                    uncracked_count += 1
                    
        return cracked_count + uncracked_count
    except Exception:
        return 100 

@contextmanager
def error_suppression(log_function=None):
    """
    Context manager to suppress terminal errors and optionally log them.
    
    Args:
        log_function (callable, optional): Function to log errors
    """
    try:
        yield
    except Exception as e:
        if log_function:
            log_function(f"Error: {str(e)}")

def format_password_mask(password: str, mask_percentage: float = 0.6) -> str:
    """
    Create a masked version of a password for display.
    
    Args:
        password (str): The password to mask
        mask_percentage (float, optional): Percentage of characters to mask
        
    Returns:
        str: The masked password
    """
    if not password:
        return ""
        
    length = len(password)
    if length <= 3:
        return password[0] + '*' * (length - 1)
    
    visible_chars = max(3, int(length * (1 - mask_percentage)))
    prefix_len = visible_chars // 2
    suffix_len = visible_chars - prefix_len
    
    prefix = password[:prefix_len]
    suffix = password[-suffix_len:] if suffix_len > 0 else ""
    mask = '*' * (length - prefix_len - suffix_len)
    
    return prefix + mask + suffix

def generate_seed() -> str:
    """
    Generate a random seed for password hashing.
    
    Returns:
        str: A random string to use as a seed
    """
    import uuid
    return str(uuid.uuid4())

def format_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes (int): Size in bytes
        
    Returns:
        str: Formatted size string (e.g., "1.23 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def pluralize(count: int, singular: str, plural: str = None) -> str:
    """
    Return singular or plural form based on count.
    
    Args:
        count (int): The count
        singular (str): Singular form
        plural (str, optional): Plural form, defaults to singular + "s"
        
    Returns:
        str: Appropriate form based on count
    """
    if plural is None:
        plural = singular + "s"
    return singular if count == 1 else plural

def print_info(message):
    """Print an info message."""
    print(f"INFO: {message}")

def print_success(message):
    """Print a success message."""
    print(f"SUCCESS: {message}")

def print_warning(message):
    """Print a warning message."""
    print(f"WARNING: {message}")

def print_error(message, file=None, log_function=None):
    """
    Print an error message and optionally log it.
    
    Args:
        message (str): Error message
        file (file, optional): File to write to
        log_function (callable, optional): Function to log message
    """
    if log_function:
        log_function(message)
    elif file:
        print(f"ERROR: {message}", file=file)
    else:
        print(f"ERROR: {message}")

def display_banner(title):
    """
    Display a banner with the given title.
    
    Args:
        title (str): Banner title
    """
    width = shutil.get_terminal_size().columns if hasattr(shutil, 'get_terminal_size') else 80
    print("=" * width)
    print(f"Password Security Audit Tool - {title}".center(width))
    print("=" * width)