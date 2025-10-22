# models/risk.py
"""
Risk model for representing password security risk assessments.
"""

from typing import Dict, Any, List, Optional

class Risk:
    """
    Represents a risk assessment for a password or account.
    """
    
    def __init__(self):
        """Initialize a Risk object."""
        # Base score components
        self.base_score = 0.0
        self.complexity_factor = 0.0
        self.length_factor = 0.0
        self.dictionary_factor = 0.0
        self.similarity_factor = 0.0
        
        # Temporal score components
        self.temporal_score = 0.0
        self.compliance_factor = 0.0
        self.expiration_factor = 0.0
        
        # Environmental score components
        self.environmental_score = 0.0
        self.privilege_factor = 0.0
        self.share_factor = 0.0
        self.domain_factor = 0.0
        
        # Final risk assessment
        self.final_score = 0.0
        self.risk_level = "Unknown"
        self.risk_vector = ""
    
    def calculate_base_score(self, complexity_label: str, password_length: int, 
                           is_common: bool, is_dictionary_word: bool,
                           banned_words_count: int, keyboard_patterns_count: int, 
                           similar_passwords: List) -> float:
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
            float: Base score (0-10)
        """
        import math
        
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
        self.complexity_factor = complexity_factors.get(complexity_label, 1.0)
        
        # Length factor using sigmoid function
        self.length_factor = 1.0 / (1.0 + math.exp((password_length - 10) / 2))
        
        # Dictionary factor
        self.dictionary_factor = min(1.0, 
                                    (0.7 if is_common else 0) +
                                    (0.5 if is_dictionary_word else 0) +
                                    (min(0.8, 0.2 * banned_words_count)) +
                                    (min(0.5, 0.1 * keyboard_patterns_count)))
        
        # Similarity factor
        self.similarity_factor = 0
        if similar_passwords:
            # Take the highest similarity score, scale it (0.7-1.0 becomes 0.0-0.5)
            max_similarity = similar_passwords[0][1]
            if max_similarity >= 0.9:  # 90% or more similar
                self.similarity_factor = 0.6
            elif max_similarity >= 0.8:  # 80-89% similar
                self.similarity_factor = 0.4
            elif max_similarity >= 0.7:  # 70-79% similar
                self.similarity_factor = 0.2
        
        # Combined factor calculation
        combined_factor = ((self.complexity_factor * self.length_factor) + 
                          self.dictionary_factor + 
                          self.similarity_factor)
        
        # Scale to 0-10 range
        self.base_score = combined_factor * (10.0/4.0)  # Adjusted for new similarity factor
        
        return min(10.0, self.base_score)
    
    def calculate_temporal_score(self, base_score: float, days_out_of_compliance: Any, 
                                password_set_to_expire: str) -> float:
        """
        Calculate the temporal score component (0-10) based on time-related factors.
        
        Args:
            base_score (float): The base score (0-10)
            days_out_of_compliance (int/str): Days past compliance period
            password_set_to_expire (str): Whether password is set to expire
            
        Returns:
            float: Temporal score (0-10)
        """
        # Compliance factor (0.6-1.0)
        if days_out_of_compliance in ("Unknown", "N/A"):
            self.compliance_factor = 0.8  # Middle risk if unknown
        else:
            try:
                days = int(days_out_of_compliance) if isinstance(days_out_of_compliance, (int, str)) else 0
                self.compliance_factor = min(1.0, 0.6 + (0.4 * min(1.0, days / 180.0)))
            except (ValueError, TypeError):
                self.compliance_factor = 0.8  # Middle risk if error
        
        # Expiration factor (0.85-1.0)
        if password_set_to_expire == "Unknown":
            self.expiration_factor = 0.925  # Middle value if unknown
        else:
            self.expiration_factor = 1.0 if password_set_to_expire == 'No' else 0.85
        
        self.temporal_score = base_score * self.compliance_factor * self.expiration_factor
        return min(10.0, self.temporal_score)
    
    def calculate_environmental_score(self, temporal_score: float, has_da_path: bool, 
                                     controlled_object_count: Any, shared_with: Any, 
                                     domain_risk_level: Optional[str] = None) -> float:
        """
        Calculate the environmental score component (0-10) based on context factors.
        
        Args:
            temporal_score (float): The temporal score (0-10)
            has_da_path (bool): Whether account has domain admin pathway
            controlled_object_count (int/str): Number of objects controlled
            shared_with (int): Number of accounts sharing this password
            domain_risk_level (str, optional): Risk level of the domain
            
        Returns:
            float: Environmental score (0-10)
        """
        # Privilege factor (1.0-1.8)
        self.privilege_factor = 1.0
        if has_da_path:
            self.privilege_factor += 0.5
        
        if controlled_object_count != 'Unknown':
            try:
                obj_count = int(controlled_object_count)
                if obj_count > 1000:
                    self.privilege_factor += 0.5  # Extreme control
                elif obj_count > 500:
                    self.privilege_factor += 0.4  # Very high control
                elif obj_count > 100:
                    self.privilege_factor += 0.3  # High control
                elif obj_count > 50:
                    self.privilege_factor += 0.2  # Medium-high control
                elif obj_count > 10:
                    self.privilege_factor += 0.1  # Medium control
            except (ValueError, TypeError):
                pass
        
        # Share factor (logarithmic scale)
        share_count = int(shared_with) if isinstance(shared_with, (int, str)) and shared_with != 'Unknown' else 0
        self.share_factor = 1.0
        if share_count > 0:
            if share_count >= 1000:  # S:4 - Extreme sharing
                self.share_factor += 0.5
            elif share_count >= 100:  # S:3 - Critical sharing
                self.share_factor += 0.4
            elif share_count >= 10:   # S:2 - High sharing
                self.share_factor += 0.3
            else:                     # S:1 - Low sharing
                self.share_factor += 0.2
        
        # Domain risk factor
        self.domain_factor = 1.0
        if domain_risk_level:
            domain_risk_map = {
                "Critical": 1.3,
                "High": 1.2,
                "Medium": 1.1,
                "Low": 1.0,
                "Unknown": 1.0
            }
            self.domain_factor = domain_risk_map.get(domain_risk_level, 1.0)
        
        # Combined environmental calculation
        self.environmental_score = temporal_score * self.privilege_factor * self.share_factor * self.domain_factor
        return min(10.0, self.environmental_score)
    
    def calculate_final_score(self, password_analysis: Dict[str, Any], shared_with: Any, 
                            da_domains: Any, controlled_object_count: Any,
                            similar_passwords: Optional[List] = None, 
                            domain_risk_level: Optional[str] = None) -> float:
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
            float: Final risk score (0-10)
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
        self.calculate_base_score(
            complexity_label, password_length, is_common, is_dictionary_word,
            banned_words_count, keyboard_patterns_count, similar_passwords
        )
        
        # Calculate temporal score
        self.calculate_temporal_score(
            self.base_score, days_out_of_compliance, password_set_to_expire
        )
        
        # Calculate environmental score
        has_da_path = da_domains and da_domains not in ('None', 'Unknown', [])
        self.calculate_environmental_score(
            self.temporal_score, has_da_path, controlled_object_count, shared_with, domain_risk_level
        )
        
        # Set final score
        self.final_score = min(10.0, self.environmental_score)
        
        # Determine risk level
        self.set_risk_level(has_da_path)
        
        return self.final_score
    
    def set_risk_level(self, has_da_path: bool = False) -> str:
        """
        Set risk level based on final score.
        
        Args:
            has_da_path (bool): Whether account has domain admin pathway
            
        Returns:
            str: Risk level (Critical, High, Medium, Low)
        """
        if has_da_path:
            self.risk_level = "Critical"
        elif self.final_score >= 8.0:
            self.risk_level = "Critical"
        elif self.final_score >= 6.0:
            self.risk_level = "High"
        elif self.final_score >= 4.0:
            self.risk_level = "Medium"
        else:
            self.risk_level = "Low"
            
        return self.risk_level
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert risk assessment to dictionary representation.
        
        Returns:
            dict: Dictionary representation of risk assessment
        """
        return {
            "base_score": round(self.base_score, 1),
            "base_components": {
                "complexity_factor": round(self.complexity_factor, 2),
                "length_factor": round(self.length_factor, 2),
                "dictionary_factor": round(self.dictionary_factor, 2),
                "similarity_factor": round(self.similarity_factor, 2),
            },
            "temporal_score": round(self.temporal_score, 1),
            "temporal_components": {
                "compliance_factor": round(self.compliance_factor, 2),
                "expiration_factor": round(self.expiration_factor, 2),
            },
            "environmental_score": round(self.environmental_score, 1),
            "environmental_components": {
                "privilege_factor": round(self.privilege_factor, 2),
                "share_factor": round(self.share_factor, 2),
                "domain_factor": round(self.domain_factor, 2)
            },
            "final_score": round(self.final_score, 1),
            "risk_level": self.risk_level,
            "risk_vector": self.risk_vector
        }