# utils/logging.py
import logging
from datetime import datetime
from core.config import reports_folder

def setup_logging():
    """Set up logging to a timestamped file in the reports folder."""
    start_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file = reports_folder / f'audit_{start_time}.log'
    
    logger = logging.getLogger('audit')
    logger.setLevel(logging.ERROR)
    
    # Create file handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.ERROR)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(fh)
    
    return logger