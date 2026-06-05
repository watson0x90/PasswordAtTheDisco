# models/account.py
"""
Account model for representing user accounts in password security analysis.
"""

from datetime import datetime
from typing import Dict, Any

class Account:
    """
    Represents a user account with authentication credentials and properties.
    """
    
    def __init__(self, username: str, domain: str, password=None):
        """
        Initialize an Account object.
        
        Args:
            username (str): The account username
            domain (str): The account domain
            password (Password, optional): Password object associated with this account
        """
        self.username = username
        self.domain = domain
        self.password = password
        self.last_password_set = None
        self.password_set_to_expire = None
        self.enabled = None
        self.when_created = None
        self.last_logon = None
        self.last_logon_timestamp = None
        self.password_cant_change = None
        self.days_out_of_compliance = None
        self.controlled_object_count = None
        self.da_domains = None
        self.risk_level = None
        self.risk_score = None
        self.risk_vector = None
        self.score_breakdown = None
    
    def set_bloodhound_data(self, data: Dict[str, Any]) -> None:
        """
        Set account properties from BloodHound data.
        
        Args:
            data (dict): BloodHound data for the account
        """
        props = data.get('props', [{}])[0]
        self.password_set_to_expire = 'No' if props.get('pwdneverexpires', True) else 'Yes'
        self.enabled = props.get('enabled', False)
        self.password_cant_change = props.get('passwordcantchange', False)
        
        # Process timestamps
        pwd_last_set = props.get('pwdlastset')
        if pwd_last_set and isinstance(pwd_last_set, (int, float)):
            self.last_password_set = datetime.fromtimestamp(pwd_last_set)
        
        when_created = props.get('whencreated')
        if when_created and isinstance(when_created, (int, float)):
            self.when_created = datetime.fromtimestamp(when_created)
        
        last_logon = props.get('lastlogon')
        if last_logon and isinstance(last_logon, (int, float)):
            self.last_logon = datetime.fromtimestamp(last_logon)
        
        last_logon_timestamp = props.get('lastlogontimestamp')
        if last_logon_timestamp and isinstance(last_logon_timestamp, (int, float)):
            self.last_logon_timestamp = datetime.fromtimestamp(last_logon_timestamp)
        
        # Process domain admin paths and controllables
        controllables = data.get('controllables', [])
        self.da_domains = [c['domain'] for c in controllables if c['labels'].get('has_da_path', False) is True]
        
        # Sum up controlled objects
        self.controlled_object_count = sum(
            int(v) for c in controllables
            for k, v in c['labels'].items() 
            if k != 'has_da_path' and str(v).isdigit()
        ) if controllables else 0
    
    def set_risk_data(self, risk_level: str, risk_score: float, risk_vector: str, 
                     score_breakdown: Dict[str, Any]) -> None:
        """
        Set risk assessment data for the account.
        
        Args:
            risk_level (str): Risk level classification (Critical, High, Medium, Low)
            risk_score (float): Numerical risk score (0-10)
            risk_vector (str): CVSS-style risk vector string
            score_breakdown (dict): Detailed score component breakdown
        """
        self.risk_level = risk_level
        self.risk_score = risk_score
        self.risk_vector = risk_vector
        self.score_breakdown = score_breakdown
    
    def calculate_days_out_of_compliance(self, max_password_age_days: int) -> int:
        """
        Calculate days out of compliance for password age.
        
        Args:
            max_password_age_days (int): Maximum password age in days per policy
            
        Returns:
            int: Days out of compliance (0 if compliant)
        """
        if not self.last_password_set:
            return 0
            
        days_since_set = (datetime.now() - self.last_password_set).days
        days_out = max(0, days_since_set - max_password_age_days)
        self.days_out_of_compliance = days_out
        return days_out
    
    def has_da_pathway(self) -> bool:
        """
        Check if account has a Domain Admin pathway.
        
        Returns:
            bool: True if account has DA pathway, False otherwise
        """
        return bool(self.da_domains)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert account to dictionary representation.
        
        Returns:
            dict: Dictionary representation of account
        """
        return {
            'Username': self.username,
            'Domain': self.domain,
            'Password': self.password.to_string() if self.password else None,
            'Password Hash': self.password.hash_value if self.password else None,
            'Last Password Set': self.last_password_set.strftime('%Y-%m-%d') if self.last_password_set else 'Unknown',
            'Password Set to Expire': self.password_set_to_expire,
            'Enabled': self.enabled,
            'When Created': self.when_created.strftime('%Y-%m-%d') if self.when_created else 'Unknown',
            'Last Logon': self.last_logon.strftime('%Y-%m-%d') if self.last_logon else 'Unknown',
            'Last Logon Timestamp': self.last_logon_timestamp.strftime('%Y-%m-%d') if self.last_logon_timestamp else 'Unknown',
            'Password Cant Change': self.password_cant_change,
            'Days Out of Compliance': self.days_out_of_compliance,
            'DA Domains': ', '.join(self.da_domains) if self.da_domains else 'None',
            'Controlled Object Count': self.controlled_object_count,
            'Risk Level': self.risk_level,
            'Risk Score': self.risk_score,
            'Risk Vector': self.risk_vector
        }