# reports/markdown/utils.py
"""
Utility functions for Markdown reports.
"""

def get_risk_distribution(data):
    """Consistently extract risk distribution from data."""
    if 'domain_risk' in data and 'risk_distribution' in data['domain_risk']:
        return data['domain_risk']['risk_distribution']
    return data.get('risk_counter', {})

def get_password_length_stats(data):
    """Consistently extract password length statistics."""
    lengths = data.get('password_lengths', [])
    if not lengths:
        return {'avg': 0, 'min': 0, 'max': 0, 'count': 0}
    
    return {
        'avg': sum(lengths) / len(lengths) if lengths else 0,
        'min': min(lengths) if lengths else 0,
        'max': max(lengths) if lengths else 0,
        'count': len(lengths)
    }

def extract_basic_stats(data):
    """
    Extract basic statistics from data consistently.
    
    Args:
        data (dict): Domain data
        
    Returns:
        dict: Dict with basic statistics
    """
    try:
        total_accounts = len(data['output_rows'])
        cracked = sum(1 for row in data['output_rows'] if row['Password Length'] != 'N/A')
        uncracked = total_accounts - cracked
        out_of_compliance = sum(1 for row in data['output_rows'] 
                              if row['Days Out of Compliance'] not in ('Unknown', 'N/A') 
                              and int(row['Days Out of Compliance']) > 0)
        non_expiring = sum(1 for row in data['output_rows'] 
                          if row['Password Set to Expire'] == 'No')
    except (KeyError, TypeError):
        total_accounts = 0
        cracked = 0
        uncracked = 0
        out_of_compliance = 0
        non_expiring = 0
    
    return {
        'total_accounts': total_accounts,
        'cracked': cracked,
        'uncracked': uncracked,
        'out_of_compliance': out_of_compliance,
        'non_expiring': non_expiring
    }