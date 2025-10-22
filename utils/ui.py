# utils/ui.py
"""
UI utility functions for the password audit tool.
Provides functions for displaying information in the terminal.
"""

import os
import sys
import time
from typing import List, Dict, Any, Optional

class ProgressBar:
    """
    Simple text-based progress bar for terminal.
    """
    
    def __init__(self, total: int, prefix: str = '', suffix: str = '', 
                length: int = 50, fill: str = '█', print_end: str = '\r'):
        """
        Initialize progress bar.
        
        Args:
            total (int): Total iterations
            prefix (str, optional): Prefix string
            suffix (str, optional): Suffix string
            length (int, optional): Character length of bar
            fill (str, optional): Bar fill character
            print_end (str, optional): End character for print
        """
        self.total = max(1, total)  # Avoid division by zero
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.print_end = print_end
        self.iteration = 0
        self.start_time = time.time()
    
    def update(self, iteration: Optional[int] = None) -> None:
        """
        Update the progress bar.
        
        Args:
            iteration (int, optional): Current iteration
        """
        if iteration is not None:
            self.iteration = iteration
        else:
            self.iteration += 1
        
        self.print()
    
    def print(self) -> None:
        """Print the progress bar."""
        percent = min(100, 100 * (self.iteration / float(self.total)))
        filled_length = int(self.length * self.iteration // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        
        # Calculate elapsed time and ETA
        elapsed_time = time.time() - self.start_time
        if self.iteration > 0:
            items_per_second = self.iteration / elapsed_time
            eta = (self.total - self.iteration) / items_per_second if items_per_second > 0 else 0
            time_info = f" {format_time(elapsed_time)} elapsed | ETA: {format_time(eta)}"
        else:
            time_info = ""
        
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent:.1f}% {self.iteration}/{self.total}{time_info} {self.suffix}')
        sys.stdout.flush()
        
        # Print new line on complete
        if self.iteration >= self.total:
            sys.stdout.write('\n')
            sys.stdout.flush()
    
    def finish(self) -> None:
        """Mark the progress as finished."""
        self.iteration = self.total
        self.print()

def format_time(seconds: float) -> str:
    """
    Format time in human-readable form.
    
    Args:
        seconds (float): Time in seconds
        
    Returns:
        str: Formatted time string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        seconds %= 60
        return f"{int(minutes)}m {int(seconds)}s"
    else:
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        return f"{int(hours)}h {int(minutes)}m"

def print_header(title: str, width: int = 80) -> None:
    """
    Print a formatted header.
    
    Args:
        title (str): Header title
        width (int, optional): Width of header
    """
    print("=" * width)
    print(f"{title.center(width)}")
    print("=" * width)

def print_section(title: str, width: int = 80) -> None:
    """
    Print a formatted section header.
    
    Args:
        title (str): Section title
        width (int, optional): Width of header
    """
    print("\n" + "-" * width)
    print(f"{title}")
    print("-" * width)

def print_table(headers: List[str], rows: List[List[Any]], 
               widths: Optional[List[int]] = None) -> None:
    """
    Print a formatted table.
    
    Args:
        headers (list): List of column headers
        rows (list): List of rows (each a list of values)
        widths (list, optional): List of column widths
    """
    if not widths:
        # Calculate column widths based on content
        widths = []
        for i in range(len(headers)):
            col_values = [str(row[i]) for row in rows if i < len(row)]
            widths.append(max(len(headers[i]), max(len(val) for val in col_values) if col_values else 0))
    
    # Print header
    header_row = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_row)
    print("-" * len(header_row))
    
    # Print rows
    for row in rows:
        row_str = " | ".join(str(val).ljust(w) for val, w in zip(row, widths[:len(row)]))
        print(row_str)

def print_dict(data: Dict[str, Any], title: Optional[str] = None, 
              indent: int = 0) -> None:
    """
    Print a dictionary in a formatted way.
    
    Args:
        data (dict): Dictionary to print
        title (str, optional): Title for the dictionary
        indent (int, optional): Indentation level
    """
    indent_str = " " * indent
    
    if title:
        print(f"{indent_str}{title}:")
    
    for key, value in data.items():
        if isinstance(value, dict):
            print(f"{indent_str}{key}:")
            print_dict(value, indent=indent + 2)
        elif isinstance(value, list):
            print(f"{indent_str}{key}:")
            for item in value:
                if isinstance(item, dict):
                    print_dict(item, indent=indent + 2)
                else:
                    print(f"{indent_str}  - {item}")
        else:
            print(f"{indent_str}{key}: {value}")

def print_summary(domain: str, data: Dict[str, Any]) -> None:
    """
    Print a summary of domain analysis results.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
    """
    total_accounts = len(data['output_rows'])
    cracked = sum(1 for row in data['output_rows'] if row['Password Length'] != 'N/A')
    uncracked = total_accounts - cracked
    
    # Calculate risk statistics
    risk_counter = data.get('risk_counter', {})
    high_critical = risk_counter.get('High', 0) + risk_counter.get('Critical', 0)
    
    # Security metrics
    domain_risk = data.get('domain_risk', {})
    risk_score = domain_risk.get('risk_score', 'N/A')
    risk_level = domain_risk.get('overall_risk_level', 'Unknown')
    
    # Print summary
    print_header(f"Password Security Summary - {domain}")
    print(f"Domain: {domain}")
    print(f"Domain Risk Score: {risk_score}/10.0 ({risk_level})")
    print(f"Total Accounts: {total_accounts}")
    print(f"Cracked Passwords: {cracked} ({cracked/total_accounts:.1%})")
    print(f"Uncracked Passwords: {uncracked} ({uncracked/total_accounts:.1%})")
    print(f"High/Critical Risk Accounts: {high_critical} ({high_critical/total_accounts:.1%})")
    
    # Print risk distribution
    if risk_counter:
        print("\nRisk Distribution:")
        for level in ['Critical', 'High', 'Medium', 'Low']:
            count = risk_counter.get(level, 0)
            print(f"  {level}: {count} ({count/total_accounts:.1%})")
    
    # Print top issues
    issues_counter = data.get('issues_counter', {})
    if issues_counter:
        print("\nTop Password Issues:")
        for issue, count in sorted(issues_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {issue}: {count}")

def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def prompt_yes_no(question: str, default: str = 'y') -> bool:
    """
    Prompt user for yes/no input.
    
    Args:
        question (str): Question to ask
        default (str, optional): Default answer ('y' or 'n')
        
    Returns:
        bool: True for yes, False for no
    """
    valid = {"yes": True, "y": True, "no": False, "n": False}
    if default == 'y':
        prompt = "[Y/n]"
    elif default == 'n':
        prompt = "[y/N]"
    else:
        prompt = "[y/n]"
    
    while True:
        sys.stdout.write(f"{question} {prompt} ")
        choice = input().lower()
        if choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes'/'y' or 'no'/'n'.\n")

class ConsoleMenu:
    """
    Simple console-based menu system.
    """
    
    def __init__(self, title: str, options: List[str]):
        """
        Initialize console menu.
        
        Args:
            title (str): Menu title
            options (list): List of menu options
        """
        self.title = title
        self.options = options
    
    def display(self) -> int:
        """
        Display the menu and get user selection.
        
        Returns:
            int: Selected option index (0-based)
        """
        print("\n" + "=" * 50)
        print(f"{self.title.center(50)}")
        print("=" * 50)
        
        for i, option in enumerate(self.options, 1):
            print(f"{i}. {option}")
        
        print("0. Exit/Back")
        print("-" * 50)
        
        while True:
            try:
                choice = int(input("Enter your choice: "))
                if 0 <= choice <= len(self.options):
                    return choice - 1  # Convert to 0-based index (-1 means exit)
                else:
                    print(f"Please enter a number between 0 and {len(self.options)}")
            except ValueError:
                print("Please enter a valid number")