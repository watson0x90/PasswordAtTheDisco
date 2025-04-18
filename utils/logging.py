# utils/logging.py
"""
Logging utility functions for the password audit tool.
Provides functions for setting up and using logging.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from core.config import reports_folder
from utils.misc import error_suppression

def setup_logging(log_level=logging.INFO, console_level=logging.ERROR, 
                log_file=None, log_format=None) -> logging.Logger:
    """
    Set up logging to a timestamped file and console.
    
    Args:
        log_level (int, optional): File logging level
        console_level (int, optional): Console logging level (set to ERROR to suppress info and warning prints)
        log_file (str, optional): Path to log file, default is timestamped in reports folder
        log_format (str, optional): Log format string
        
    Returns:
        Logger: Configured logger instance
    """
    # Create default timestamped log file if not specified
    if log_file is None:
        start_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_file = reports_folder / f'audit_{start_time}.log'
    
    # Create reports folder if it doesn't exist
    os.makedirs(reports_folder, exist_ok=True)
    
    # Set default format if not specified
    if log_format is None:
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Configure logger
    logger = logging.getLogger('password_audit')
    logger.setLevel(logging.DEBUG)  # Allow all levels of messages to be logged
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Create formatter
    formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
    
    # Create file handler for all messages
    fh = logging.FileHandler(log_file)
    fh.setLevel(log_level)  # Can be DEBUG to capture everything
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    # Create console handler with higher level - set to ERROR to hide INFO, DEBUG and WARNING
    ch = logging.StreamHandler()
    ch.setLevel(console_level)  # Should be ERROR to suppress INFO, DEBUG and WARNING
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # Make sure we don't propagate messages to the root logger
    logger.propagate = False
    
    return logger

def get_logger(name=None) -> logging.Logger:
    """
    Get the password audit logger or a child logger.
    
    Args:
        name (str, optional): Logger name for child logger
        
    Returns:
        Logger: Logger instance
    """
    if name:
        return logging.getLogger(f'password_audit.{name}')
    else:
        return logging.getLogger('password_audit')

def log_exception(logger, message=None, exc_info=True, print_to_console=False) -> None:
    """
    Log an exception with optional message, suppress console output by default.
    
    Args:
        logger (Logger): Logger to use
        message (str, optional): Message to log with exception
        exc_info (bool, optional): Whether to include exception info
        print_to_console (bool, optional): Whether to print to console
    """
    with error_suppression(logger.error if not print_to_console else None):
        if message:
            logger.error(message, exc_info=exc_info)
        else:
            logger.error("An exception occurred", exc_info=exc_info)

def configure_file_logger(filename: str, level=logging.INFO) -> logging.Logger:
    """
    Configure a logger that only writes to a specific file.
    
    Args:
        filename (str): Log file name/path
        level (int, optional): Logging level
        
    Returns:
        Logger: Configured logger
    """
    # Create directory if needed
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    
    # Set up logger
    logger = logging.getLogger(f'file_logger_{os.path.basename(filename)}')
    logger.setLevel(level)
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Add file handler
    handler = logging.FileHandler(filename)
    handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Prevent propagation to prevent duplicate logging
    logger.propagate = False
    
    return logger