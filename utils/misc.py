# utils/misc.py
"""
Miscellaneous utility functions for the password audit tool.
Enhanced with robust terminal animations and progress tracking.
"""

import sys
import time
import shutil
import threading
import datetime
import os
from contextlib import contextmanager
from core.config import ENABLE_ANIMATION

# Try to import Rich, use fallback if not available
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.status import Status
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Try to import psutil, use fallback if not available
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Create Rich console if available with proper feature detection
def setup_console():
    """Set up Rich console with appropriate feature detection."""
    if HAS_RICH:
        try:
            # Test if we can use all Rich features
            console = Console()
            console.size
            console.color_system
            
            # If all features work, return the console
            return console
        except Exception:
            # Fall back to a more compatible console
            return Console(color_system="standard", highlight=False, record=False)
    return None

# Initialize console
console = setup_console()

class ThrottledProgress:
    """Wrapper for Rich progress with update rate limiting."""
    
    def __init__(self, progress, task_id, min_update_interval=0.1):
        """
        Initialize rate-limited progress tracker.
        
        Args:
            progress: Rich Progress object
            task_id: Task ID to update
            min_update_interval (float): Minimum seconds between updates
        """
        self.progress = progress
        self.task_id = task_id
        self.min_update_interval = min_update_interval
        self.last_update = 0
        self.pending_advance = 0
        
    def update(self, advance=1, **kwargs):
        """
        Update progress with rate limiting.
        
        Args:
            advance (int): Progress amount to advance
            kwargs: Additional progress parameters
        """
        self.pending_advance += advance
        
        current_time = time.time()
        if current_time - self.last_update >= self.min_update_interval:
            self.progress.update(self.task_id, advance=self.pending_advance, **kwargs)
            self.pending_advance = 0
            self.last_update = current_time
            
    def force_update(self, **kwargs):
        """
        Force an immediate update regardless of timing.
        
        Args:
            kwargs: Progress parameters
        """
        if self.pending_advance > 0:
            self.progress.update(self.task_id, advance=self.pending_advance, **kwargs)
            self.pending_advance = 0
            self.last_update = time.time()

def show_processing_animation(stop_event: threading.Event) -> None:
    """
    Display a spinning animation in the terminal until stopped.
    Enhanced with better error handling and cleanup.
    
    Args:
        stop_event (threading.Event): Event to signal when to stop animation
    """
    animation_thread = None
    
    try:
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
            
            # Show completion message if not interrupted
            if not stop_event.is_set():
                console.print("[bold green]Processing domains... Done![/bold green]")
        else:
            # Create spinner in a separate thread for better cleanup
            def spinner_thread():
                spinner = ['|', '/', '-', '\\']
                i = 0
                while not stop_event.is_set():
                    char = spinner[i % len(spinner)]
                    sys.stdout.write(f'\rProcessing domains... {char}')
                    sys.stdout.flush()
                    time.sleep(0.1)
                    i += 1
            
            # Start animation thread
            animation_thread = threading.Thread(target=spinner_thread)
            animation_thread.daemon = True
            animation_thread.start()
            
            # Wait for the stop event (this is non-blocking for the main thread)
            while not stop_event.is_set():
                time.sleep(0.2)
                
            # Cleanup when done (thread should terminate due to stop_event)
            if animation_thread.is_alive():
                animation_thread.join(timeout=1.0)
                
            sys.stdout.write('\rProcessing domains... Done!    \n')
            sys.stdout.flush()
    except Exception as e:
        # Ensure we clean up even during exceptions
        stop_event.set()
        if animation_thread and animation_thread.is_alive():
            animation_thread.join(timeout=0.5)
        
        if HAS_RICH and console:
            console.print(f"[bold red]Animation error: {str(e)}[/bold red]")
        else:
            print(f"\nAnimation error: {str(e)}")

def show_task_progress(task_name: str, total: int, update_callback=None):
    """
    Create and return a Rich progress context manager for task progress.
    Enhanced with adaptive width and better metrics.
    
    Args:
        task_name (str): Name of the task
        total (int): Total number of steps
        update_callback (callable, optional): Callback for updating progress
        
    Returns:
        Progress context manager if Rich is available, else None
    """
    if not ENABLE_ANIMATION or not HAS_RICH:
        return DummyProgress()
    
    # Get terminal width
    terminal_width = shutil.get_terminal_size().columns if hasattr(shutil, 'get_terminal_size') else 80
    
    # Adjust bar width based on terminal width
    bar_width = max(10, min(40, terminal_width - 80))
        
    # Use a single console instance and set transient=True to avoid duplicated lines
    progress = Progress(
        SpinnerColumn(),
        TextColumn(f"[bold blue]{task_name}"),
        BarColumn(bar_width=bar_width),  # Adaptive width
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),  # Add remaining time estimate
        console=console,  # Use the global console to prevent duplicate outputs
        transient=True,   # This helps prevent duplicate lines by refreshing in place
        refresh_per_second=5  # Lower refresh rate to reduce flicker
    )
    
    # Create a single task with the provided total
    task_id = progress.add_task(task_name, total=total)
    
    if update_callback:
        update_callback(progress, task_id)
        
    return progress

def create_metrics_live_display():
    """
    Create a live metrics panel for domain processing.
    
    Returns:
        tuple: (Live object, metrics dict) if Rich is available, else (None, {})
    """
    if HAS_RICH and console:
        metrics = {
            "Domains Processed": 0,
            "Accounts Analyzed": 0,
            "Cracked Passwords": 0,
            "Processing Rate": "0 domains/sec",
            "Elapsed Time": "00:00:00",
            "Memory Usage": "0 MB"
        }
        
        start_time = time.time()
        
        def get_panel():
            # Update timing metrics
            elapsed = time.time() - start_time
            metrics["Elapsed Time"] = str(datetime.timedelta(seconds=int(elapsed)))
            
            # Calculate processing rate
            if metrics["Domains Processed"] > 0 and elapsed > 0:
                rate = metrics["Domains Processed"] / elapsed
                metrics["Processing Rate"] = f"{rate:.2f} domains/sec"
                
            # Get memory usage from psutil
            try:
                if HAS_PSUTIL:
                    process = psutil.Process(os.getpid())
                    memory = process.memory_info().rss / (1024 * 1024)
                    metrics["Memory Usage"] = f"{memory:.1f} MB"
            except (ImportError, AttributeError):
                metrics["Memory Usage"] = "Unknown"
            
            # Create a table for better formatting
            table = Table(show_header=False, box=None)
            table.add_column("Metric")
            table.add_column("Value")
            
            for key, value in metrics.items():
                table.add_row(key, str(value))
                
            return Panel(table, title="Processing Metrics", border_style="blue")
        
        # Create live display with 1 second refresh rate
        live = Live(get_panel(), refresh_per_second=1, console=console)
        return live, metrics
    
    return None, {}

def process_with_group(title, function, *args, **kwargs):
    """
    Run a function with a visual group in the console.
    
    Args:
        title (str): Group title
        function (callable): Function to run
        args, kwargs: Arguments to pass to function
        
    Returns:
        Any: Return value from function
    """
    if HAS_RICH and console:
        with console.group(f"[bold blue]{title}[/bold blue]"):
            result = function(*args, **kwargs)
            console.print(f"[green]✓[/green] {title} completed")
            return result
    else:
        print(f"\n--- {title} ---")
        result = function(*args, **kwargs)
        print(f"--- {title} completed ---\n")
        return result

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
        self.total = 0
        self.completed = 0
        self.start_time = time.time()
    
    def __enter__(self):
        print(f"Starting progress tracking... (animation disabled)")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start_time
        print(f"Progress complete. Processed {self.completed}/{self.total} in {elapsed:.1f}s")
        
        # Print exception if one occurred
        if exc_type:
            print(f"Error during progress: {exc_val}")
    
    def add_task(self, description, total=None):
        self.task_id += 1
        self.total = total or 0
        print(f"Task: {description}, Total: {total}")
        return self.task_id
    
    def update(self, task_id, advance=1, completed=None, description=None):
        if completed is not None:
            self.completed = completed
        else:
            self.completed += advance
        
        # Print progress update at reasonable intervals
        if self.total and self.completed % max(1, self.total // 10) == 0:
            percentage = (self.completed / self.total * 100) if self.total else 0
            print(f"Progress: {self.completed}/{self.total} ({percentage:.1f}%)" + 
                  (f" - {description}" if description else ""))

def print_info(message):
    """Print an info message with Rich formatting if available."""
    if HAS_RICH and console:
        console.print(f"[blue]INFO:[/blue] {message}")
    else:
        print(f"INFO: {message}")

def print_success(message):
    """Print a success message with Rich formatting if available."""
    if HAS_RICH and console:
        console.print(f"[green]SUCCESS:[/green] {message}")
    else:
        print(f"SUCCESS: {message}")

def print_warning(message):
    """Print a warning message with Rich formatting if available."""
    if HAS_RICH and console:
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
    elif HAS_RICH and console and not file:
        console.print(f"[bold red]ERROR:[/bold red] {message}")
    else:
        if file:
            print(f"ERROR: {message}", file=file)
        else:
            print(f"ERROR: {message}")

def display_banner(title):
    """Display a fancy banner with Rich if available."""
    if HAS_RICH and console:
        text = Text()
        text.append("Password Security Audit Tool\n", style="bold cyan")
        text.append(title, style="bold")
        console.print(Panel(text, border_style="cyan"))
    else:
        width = shutil.get_terminal_size().columns if hasattr(shutil, 'get_terminal_size') else 80
        print("=" * width)
        print(f"Password Security Audit Tool - {title}".center(width))
        print("=" * width)

# Improved Status Panel implementation that integrates with progress display
class StatusPanel:
    """Status panel for displaying operation status without disrupting progress."""
    
    def __init__(self, console_instance):
        """
        Initialize a status panel.
        
        Args:
            console_instance (Console): Rich console instance
        """
        self.console = console_instance
        self.status = None
        
        # Only create a Status object if Rich is available
        if HAS_RICH and self.console:
            self.status = Status("Ready", console=self.console)
        
    def update(self, content):
        """
        Update the status message without disrupting progress display.
        
        Args:
            content (str): New status message
        """
        if self.status:
            # Update status in-place without creating new lines
            self.status.update(status=content)
        else:
            # Fallback when Rich is not available
            print(f"[Status] {content}")

# Add the create_status_panel method to the console
if HAS_RICH and console:
    console.create_status_panel = lambda: StatusPanel(console)
else:
    # Define a dummy console if needed
    class DummyStatusPanel:
        def update(self, content):
            print(f"Status: {content}")
    
    # If console doesn't exist, create a minimal version with required methods
    if console is None:
        class MinimalConsole:
            def create_status_panel(self):
                return DummyStatusPanel()
        
        console = MinimalConsole()
    else:
        # Add method to existing console
        console.create_status_panel = lambda: DummyStatusPanel()