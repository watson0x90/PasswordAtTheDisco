"""
Executive reporting module for Password!AtTheDisco.

This module provides business-focused, high-level security reports
designed for executive leadership and decision-makers.
"""

from .summary import generate_executive_summary, calculate_security_posture_score

__all__ = [
    'generate_executive_summary',
    'calculate_security_posture_score'
]
