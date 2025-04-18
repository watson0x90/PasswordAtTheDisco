# utils/misc.py
"""
Miscellaneous utility functions for the password audit tool.
"""

import sys
import time
import threading
from core.config import ENABLE_ANIMATION
from contextlib import contextmanager

# Try to import Rich, use fallback if not available
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Create Rich console if available
if HAS_RICH:
    console = Console()
else:
    console = None

def show_processing_animation(stop_event: threading.Event) -> None:
    """
    Display a spinning animation in the terminal until stopped.
    Uses Rich library if available, otherwise falls back to simple spinner.
    
    Args:
        stop_event (threading.Event): Event to signal when to stop animation
    """
    if not ENABLE_ANIMATION:
        return
        
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Processing domains..."),
            BarColumn(bar_width=None),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("", total=None)  # Indeterminate progress
            while not stop_event.is_set():
                progress.update(task)
                time.sleep(0.1)
        console.print("[bold green]Processing domains... Done![/bold green]")
    else:
        # Fallback to simple spinner if Rich is not available
        spinner = ['|', '/', '-', '\\']
        while not stop_event.is_set():
            for char in spinner:
                sys.stdout.write(f'\rProcessing domains... {char}')
                sys.stdout.flush()
                time.sleep(0.1)
        sys.stdout.write('\rProcessing domains... Done!    \n')
        sys.stdout.flush()


def show_task_progress(task_name: str, total: int, update_callback=None):
    """
    Create and return a Rich progress context manager for task progress.
    
    Args:
        task_name (str): Name of the task
        total (int): Total number of steps
        update_callback (callable, optional): Callback for updating progress
        
    Returns:
        Progress context manager if Rich is available, else None
    """
    if not ENABLE_ANIMATION or not HAS_RICH:
        return DummyProgress()
        
    progress = Progress(
        SpinnerColumn(),
        TextColumn(f"[bold blue]{task_name}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=Console(stderr=True),  # Redirect to stderr to avoid mixing with regular output
        transient=False,
    )
    
    # Create a single task with the provided total
    task_id = progress.add_task(task_name, total=total)
    
    if update_callback:
        update_callback(progress, task_id)
        
    return progress

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

class DummyProgress:
    """Dummy progress context manager for when Rich is not available."""
    
    def __init__(self):
        self.task_id = 0
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def add_task(self, description, total=None):
        self.task_id += 1
        return self.task_id
    
    def update(self, task_id, advance=1, completed=None):
        pass

def print_info(message):
    """Print an info message with Rich formatting if available."""
    if HAS_RICH:
        console.print(f"[blue]INFO:[/blue] {message}")
    else:
        print(f"INFO: {message}")

def print_success(message):
    """Print a success message with Rich formatting if available."""
    if HAS_RICH:
        console.print(f"[green]SUCCESS:[/green] {message}")
    else:
        print(f"SUCCESS: {message}")

def print_warning(message):
    """Print a warning message with Rich formatting if available."""
    if HAS_RICH:
        console.print(f"[yellow]WARNING:[/yellow] {message}")
    else:
        print(f"WARNING: {message}")

def print_error(message, file=None, log_function=None):
    """
    Print an error message with Rich formatting if available,
    and optionally log it instead of printing.
    """
    if log_function:
        log_function(message)
    elif HAS_RICH and not file:
        console.print(f"[bold red]ERROR:[/bold red] {message}")
    else:
        if file:
            print(f"ERROR: {message}", file=file)
        else:
            print(f"ERROR: {message}")

def display_banner(title):
    """Display a fancy banner with Rich if available."""
    if HAS_RICH:
        text = Text()
        text.append("Password Security Audit Tool\n", style="bold cyan")
        text.append(title, style="bold")
        console.print(Panel(text, border_style="cyan"))
    else:
        print("=" * 60)
        print(f"Password Security Audit Tool - {title}".center(60))
        print("=" * 60)