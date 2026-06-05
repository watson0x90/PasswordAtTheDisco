# utils/concurrency.py
"""
Concurrency utility functions for the password audit tool.
Provides utilities for parallel processing with proper shutdown handling.
"""

import os
import signal
import threading
import concurrent.futures
from typing import List, Callable, Any, Dict, Tuple

# Global shutdown event for graceful shutdown
shutdown_event = threading.Event()

def register_signal_handlers():
    """Register signal handlers for graceful shutdown."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def signal_handler(signum, frame):
    """
    Signal handler for graceful shutdown.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    print(f"\nReceived signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()

def parallel_process(items: List[Any], process_func: Callable, 
                    max_workers: int = None, timeout: int = None,
                    process_name: str = "items") -> List[Any]:
    """
    Process items in parallel with proper shutdown handling.
    
    Args:
        items (list): List of items to process
        process_func (callable): Function to process each item
        max_workers (int, optional): Maximum number of worker processes
        timeout (int, optional): Timeout in seconds for each task
        process_name (str, optional): Name for progress reporting
        
    Returns:
        list: List of results
    """
    if max_workers is None:
        max_workers = min(32, os.cpu_count() + 4)
    
    total_items = len(items)
    results = []
    processed_count = 0
    
    # Process items in parallel
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_item = {executor.submit(process_func, item): item for item in items}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_item):
            # Check for shutdown signal
            if shutdown_event.is_set():
                print(f"\nShutdown requested. Cancelling remaining {process_name}...")
                executor.shutdown(wait=False, cancel_futures=True)
                break
            
            try:
                # Get result with optional timeout
                if timeout:
                    result = future.result(timeout=timeout)
                else:
                    result = future.result()
                
                # Add to results
                results.append(result)
                
                # Update progress
                processed_count += 1
                print(f"\rProcessed {processed_count}/{total_items} {process_name}...", end="")
            
            except concurrent.futures.TimeoutError:
                print(f"\nTimeout processing {future_to_item[future]}")
            except Exception as e:
                print(f"\nError processing {future_to_item[future]}: {str(e)}")
    
    print(f"\rProcessed {processed_count}/{total_items} {process_name}. Done!{' ' * 10}")
    return results

def parallel_map(func: Callable, items: List[Any], 
                max_workers: int = None, chunksize: int = 1) -> List[Any]:
    """
    Parallel implementation of map with proper shutdown handling.
    
    Args:
        func (callable): Function to apply to each item
        items (list): List of items to process
        max_workers (int, optional): Maximum number of worker processes
        chunksize (int, optional): Chunk size for processing
        
    Returns:
        list: List of results
    """
    if max_workers is None:
        max_workers = min(32, os.cpu_count() + 4)
    
    results = []
    
    # Use ProcessPoolExecutor for CPU-bound tasks
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = [executor.submit(func, item) for item in items]
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(futures):
            # Check for shutdown signal
            if shutdown_event.is_set():
                print("\nShutdown requested. Cancelling remaining tasks...")
                executor.shutdown(wait=False, cancel_futures=True)
                break
            
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Error in task: {str(e)}")
    
    return results

def run_with_timeout(func: Callable, args: Tuple = None, 
                    kwargs: Dict = None, timeout: int = 30) -> Any:
    """
    Run a function with a timeout.
    
    Args:
        func (callable): Function to run
        args (tuple, optional): Positional arguments for the function
        kwargs (dict, optional): Keyword arguments for the function
        timeout (int, optional): Timeout in seconds
        
    Returns:
        Any: Function result or None if timeout
        
    Raises:
        TimeoutError: If function execution exceeds timeout
    """
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    
    # Define a wrapper function that sets the result
    result_container = [None]
    exception_container = [None]
    completed = threading.Event()
    
    def wrapper():
        try:
            result_container[0] = func(*args, **kwargs)
        except Exception as e:
            exception_container[0] = e
        finally:
            completed.set()
    
    # Start the function in a thread
    thread = threading.Thread(target=wrapper)
    thread.daemon = True
    thread.start()
    
    # Wait for completion or timeout
    completed.wait(timeout)
    
    # Check results
    if not completed.is_set():
        raise TimeoutError(f"Function execution timed out after {timeout} seconds")
    
    # Re-raise any exceptions
    if exception_container[0] is not None:
        raise exception_container[0]
    
    return result_container[0]

def create_worker_pool(worker_count: int = None) -> concurrent.futures.ThreadPoolExecutor:
    """
    Create a thread pool for worker tasks.
    
    Args:
        worker_count (int, optional): Number of worker threads
        
    Returns:
        ThreadPoolExecutor: Thread pool executor
    """
    if worker_count is None:
        worker_count = min(32, (os.cpu_count() or 1) * 5)
    
    return concurrent.futures.ThreadPoolExecutor(max_workers=worker_count)

def shutdown_worker_pool(pool: concurrent.futures.Executor, wait: bool = True):
    """
    Shutdown a worker pool.
    
    Args:
        pool (Executor): The executor pool to shutdown
        wait (bool, optional): Whether to wait for tasks to complete
    """
    if pool:
        pool.shutdown(wait=wait)