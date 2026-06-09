"""
ChainEDR Utility Functions

Shared utilities used across multiple modules.
Includes caching, retry logic, address validation, and logging helpers.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Dict
from functools import wraps
from web3 import Web3

from .config import Config, redact_sensitive


T = TypeVar('T')


def is_valid_address(address: str) -> bool:
    """
    Validate Ethereum address format.
    
    Args:
        address: Address string to validate
    
    Returns:
        True if valid Ethereum address, False otherwise
    """
    if not address:
        return False
    
    # Check if it's a valid hex string with correct length
    if not address.startswith('0x'):
        return False
    
    if len(address) != 42:  # 0x + 40 hex chars
        return False
    
    try:
        # Use Web3 to validate and checksum
        Web3.to_checksum_address(address)
        return True
    except Exception:
        return False


def to_checksum_address(address: str) -> str:
    """
    Convert address to checksummed format.
    
    Args:
        address: Ethereum address
    
    Returns:
        Checksummed address
    
    Raises:
        ValueError: If address is invalid
    """
    if not is_valid_address(address):
        raise ValueError(f"Invalid Ethereum address: {address}")
    
    return Web3.to_checksum_address(address)


def retry_on_failure(
    max_retries: int = None,
    delay: float = None,
    exceptions: tuple = (Exception,)
) -> Callable:
    """
    Decorator to retry function on failure.
    
    Args:
        max_retries: Maximum number of retry attempts (default from Config)
        delay: Delay between retries in seconds (default from Config)
        exceptions: Tuple of exceptions to catch and retry
    
    Returns:
        Decorated function
    """
    if max_retries is None:
        max_retries = Config.MAX_RETRIES
    if delay is None:
        delay = Config.RETRY_DELAY
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        print(
                            f"Attempt {attempt + 1} failed: "
                            f"{redact_sensitive(e)}. Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                    else:
                        print(f"All {max_retries + 1} attempts failed.")
            
            raise last_exception
        
        return wrapper
    return decorator


def cache_result(cache_key_func: Optional[Callable] = None) -> Callable:
    """
    Decorator to cache function results to disk.
    
    Args:
        cache_key_func: Optional function to generate cache key from args
                       If None, uses hash of all arguments
    
    Returns:
        Decorated function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not Config.ENABLE_CACHE:
                return func(*args, **kwargs)
            
            # Generate cache key
            if cache_key_func:
                cache_key = cache_key_func(*args, **kwargs)
            else:
                # Hash all arguments
                key_data = json.dumps({
                    'func': func.__name__,
                    'args': str(args),
                    'kwargs': str(kwargs)
                }, sort_keys=True)
                cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Check cache
            cache_file = Config.CACHE_DIR / f"{cache_key}.json"
            
            if cache_file.exists():
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                        print(f"Cache hit: {func.__name__}")
                        return cached_data
                except Exception as e:
                    print(f"Cache read error: {e}. Fetching fresh data.")
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            
            try:
                Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
                with open(cache_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Cached result: {func.__name__}")
            except Exception as e:
                print(f"Cache write error: {e}")
            
            return result
        
        return wrapper
    return decorator


def normalize_function_signature(signature: str) -> str:
    """
    Normalize function signature for comparison.
    Removes spaces and standardizes format.
    
    Args:
        signature: Function signature (e.g., "transfer(address, uint256)")
    
    Returns:
        Normalized signature
    """
    # Remove all spaces
    signature = signature.replace(" ", "")
    
    # Ensure it has parentheses
    if "(" not in signature:
        signature += "()"
    
    return signature


def extract_function_selector(signature: str) -> str:
    """
    Calculate function selector (first 4 bytes of keccak256 hash).
    
    Args:
        signature: Function signature (e.g., "transfer(address,uint256)")
    
    Returns:
        Function selector as hex string (e.g., "0xa9059cbb")
    """
    normalized = normalize_function_signature(signature)
    selector = Web3.keccak(text=normalized)[:4]
    return "0x" + selector.hex()


def format_gas(gas: int) -> str:
    """
    Format gas amount for human readability.
    
    Args:
        gas: Gas amount in wei
    
    Returns:
        Formatted string (e.g., "21,000" or "1.2M")
    """
    if gas < 1_000:
        return str(gas)
    elif gas < 1_000_000:
        return f"{gas:,}"
    else:
        return f"{gas / 1_000_000:.1f}M"


def format_wei(wei: int) -> str:
    """
    Format wei amount to ETH with appropriate precision.
    
    Args:
        wei: Amount in wei
    
    Returns:
        Formatted string (e.g., "1.5 ETH")
    """
    eth = wei / 1e18
    
    if eth == 0:
        return "0 ETH"
    elif eth < 0.0001:
        return f"{wei} wei"
    elif eth < 1:
        return f"{eth:.6f} ETH"
    else:
        return f"{eth:.4f} ETH"


def truncate_hex(hex_string: str, length: int = 10) -> str:
    """
    Truncate long hex strings for display.
    
    Args:
        hex_string: Hex string to truncate
        length: Number of characters to show from start and end
    
    Returns:
        Truncated string (e.g., "0x1234...5678")
    """
    if not hex_string or len(hex_string) <= length * 2:
        return hex_string
    
    return f"{hex_string[:length]}...{hex_string[-length:]}"


def safe_get(dictionary: Dict, *keys: str, default: Any = None) -> Any:
    """
    Safely get nested dictionary value.
    
    Args:
        dictionary: Dictionary to search
        *keys: Sequence of keys to traverse
        default: Default value if key not found
    
    Returns:
        Value at nested key or default
    """
    current = dictionary
    
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    
    return current


def print_section(title: str, width: int = 60) -> None:
    """
    Print a formatted section header.
    
    Args:
        title: Section title
        width: Total width of header
    """
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width)


def print_key_value(key: str, value: Any, indent: int = 2) -> None:
    """
    Print key-value pair with formatting.
    
    Args:
        key: Key name
        value: Value to print
        indent: Indentation level
    """
    indent_str = " " * indent
    print(f"{indent_str}{key}: {redact_sensitive(value, name=key)}")
