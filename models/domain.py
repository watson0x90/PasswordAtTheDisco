# models/domain.py
"""
Domain model for representing domains in password security analysis.
"""

from typing import Dict, Any, List, Counter
from collections import defaultdict

class Domain:
    """
    Represents a domain with its accounts and security metrics.
    """
    
    def __init__(self, name: str):
        """
        Initialize a Domain object.
        
        Args:
            name (str): Domain name
        """
        self.name = name
        self.accounts = []  # List of Account objects
        self.password_to_users = defaultdict(list)  # Map passwords to usernames
        self.hash_to_users = defaultdict(list)  # Map password hashes to usernames
        
        # Risk metrics
        self.risk_score = 0.0
        self.risk_level = "Unknown"
        self.risk_distribution = {}
        self.avg_account_score = 0.0
        self.max_account_score = 0.0
        
        # Statistics
        self.total_accounts = 0
        self.cracked_accounts = 0
        self.out_of_compliance_accounts = 0
        self.non_expiring_accounts = 0
        self.da_pathway_accounts = 0
        self.avg_password_length = 0.0
        self.password_complexity_distribution = {}
        self.password_issues = {}
        self.banned_words = Counter()
    
    def add_account(self, account) -> None:
        """
        Add an account to the domain.
        
        Args:
            account: Account object to add
        """
        self.accounts.append(account)
        self.total_accounts += 1
        
        # Track password/hash mappings
        if account.password:
            if account.password.is_cracked and account.password.value:
                self.password_to_users[account.password.value].append(account.username)
                self.cracked_accounts += 1
            else:
                self.hash_to_users[account.password.hash_value].append(account.username)
        
        # Update statistics
        if account.days_out_of_compliance and account.days_out_of_compliance > 0:
            self.out_of_compliance_accounts += 1
            
        if account.password_set_to_expire == 'No':
            self.non_expiring_accounts += 1
            
        if account.has_da_pathway():
            self.da_pathway_accounts += 1
    
    def calculate_risk_metrics(self) -> None:
        """Calculate risk metrics for the domain based on accounts."""
        if not self.accounts or self.cracked_accounts == 0:
            return
            
        # Calculate risk distribution
        risk_counter = Counter()
        scores = []
        password_lengths = []
        
        for account in self.accounts:
            if account.password and account.password.is_cracked:
                risk_counter[account.risk_level] += 1
                scores.append(account.risk_score)
                password_lengths.append(account.password.length)
                
                # Update complexity distribution
                complexity = account.password.complexity_label
                self.password_complexity_distribution[complexity] = self.password_complexity_distribution.get(complexity, 0) + 1
                
                # Collect banned words
                self.banned_words.update(account.password.forbidden_words)
                
                # Track issues
                for violation in account.password.policy_violations:
                    self.password_issues[violation] = self.password_issues.get(violation, 0) + 1
        
        # Set risk distribution
        self.risk_distribution = dict(risk_counter)
        
        # Calculate average and maximum scores
        self.avg_account_score = sum(scores) / len(scores) if scores else 0
        self.max_account_score = max(scores) if scores else 0
        
        # Calculate average password length
        self.avg_password_length = sum(password_lengths) / len(password_lengths) if password_lengths else 0
        
        # Calculate domain risk score (weighted by severity)
        weights = {"Critical": 1.0, "High": 0.6, "Medium": 0.25, "Low": 0.05}
        total = sum(risk_counter.values())
        
        if total > 0:
            weighted_sum = sum(weights[level] * count for level, count in risk_counter.items())
            self.risk_score = min(10.0, (weighted_sum / total) * 10)
        
        # Determine overall risk level for domain
        if self.risk_score >= 8.0:
            self.risk_level = "Critical"
        elif self.risk_score >= 6.0:
            self.risk_level = "High"
        elif self.risk_score >= 4.0:
            self.risk_level = "Medium"
        else:
            self.risk_level = "Low"
    
    def get_passwords_by_risk(self, risk_level: str) -> List[str]:
        """
        Get passwords with a specific risk level.
        
        Args:
            risk_level (str): Risk level to filter by
            
        Returns:
            list: List of passwords with the specified risk level
        """
        passwords = []
        for account in self.accounts:
            if account.risk_level == risk_level and account.password and account.password.is_cracked:
                passwords.append(account.password.value)
        return passwords
    
    def get_accounts_with_da_pathway(self) -> List:
        """
        Get accounts with Domain Admin pathway.
        
        Returns:
            list: List of accounts with DA pathway
        """
        return [account for account in self.accounts if account.has_da_pathway()]
    
    def get_accounts_out_of_compliance(self) -> List:
        """
        Get accounts that are out of compliance.
        
        Returns:
            list: List of accounts out of compliance
        """
        return [account for account in self.accounts if account.days_out_of_compliance and account.days_out_of_compliance > 0]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert domain to dictionary representation.
        
        Returns:
            dict: Dictionary representation of domain
        """
        return {
            'name': self.name,
            'total_accounts': self.total_accounts,
            'cracked_accounts': self.cracked_accounts,
            'out_of_compliance_accounts': self.out_of_compliance_accounts,
            'non_expiring_accounts': self.non_expiring_accounts,
            'da_pathway_accounts': self.da_pathway_accounts,
            'avg_password_length': round(self.avg_password_length, 1),
            'risk_score': round(self.risk_score, 1),
            'risk_level': self.risk_level,
            'risk_distribution': self.risk_distribution,
            'avg_account_score': round(self.avg_account_score, 1),
            'max_account_score': round(self.max_account_score, 1),
            'password_complexity_distribution': self.password_complexity_distribution,
            'top_issues': dict(Counter(self.password_issues).most_common(5)),
            'top_banned_words': dict(self.banned_words.most_common(5))
        }