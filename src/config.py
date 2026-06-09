"""
ChainEDR Configuration Management

Loads configuration from environment variables and provides
constants used across all modules.
"""

import os
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    def _load_dotenv_fallback() -> None:
        """Load a local .env file without adding python-dotenv as a hard dependency."""
        candidates = [
            Path.cwd() / ".env",
            Path(__file__).resolve().parent.parent / ".env",
        ]
        for env_path in candidates:
            if not env_path.exists():
                continue
            for raw_line in env_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
            break

    _load_dotenv_fallback()


_SENSITIVE_ENV_PARTS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "private",
    "authorization",
)
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"\b(api[_-]?key|token|secret|password|passwd|authorization|private[_-]?key)"
    r"(\s*[:=]\s*)"
    r"([^\s,;]+)",
    re.IGNORECASE,
)


def is_sensitive_name(name: str) -> bool:
    lowered = str(name).lower()
    return any(part in lowered for part in _SENSITIVE_ENV_PARTS)


def redact_secret(value: object, *, visible: int = 4) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    if len(text) <= visible * 2:
        return "***"
    return f"{text[:visible]}...{text[-visible:]}"


def redact_url(value: object) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    try:
        split = urlsplit(text)
    except Exception:
        return redact_secret(text)

    query = urlencode(
        [
            (key, "***" if is_sensitive_name(key) else val)
            for key, val in parse_qsl(split.query, keep_blank_values=True)
        ]
    )
    path_parts = [
        "***" if re.fullmatch(r"[A-Za-z0-9_\-]{20,}", part) else part
        for part in split.path.split("/")
    ]
    return urlunsplit((split.scheme, split.netloc, "/".join(path_parts), query, split.fragment))


def redact_sensitive(value: object, *, name: str = "") -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    redacted = _URL_RE.sub(lambda match: redact_url(match.group(0)), text)
    redacted = _SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}***",
        redacted,
    )
    if name and is_sensitive_name(name) and redacted == text:
        return redact_secret(redacted)
    return redacted


class Config:
    """
    Central configuration class for ChainEDR.
    All settings are loaded from environment variables.
    """
    
    # API Keys
    ETHERSCAN_API_KEY: str = os.getenv("ETHERSCAN_API_KEY", "")
    
    # RPC Configuration
    RPC_URL: str = os.getenv("RPC_URL", "")
    RPC_URL_FALLBACK: Optional[str] = os.getenv("RPC_URL_FALLBACK")
    
    # Timeouts (seconds)
    RPC_TIMEOUT: int = int(os.getenv("RPC_TIMEOUT", "30"))
    ETHERSCAN_TIMEOUT: int = int(os.getenv("ETHERSCAN_TIMEOUT", "10"))
    
    # Rate Limiting
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
    RETRY_DELAY: float = float(os.getenv("RETRY_DELAY", "1.0"))
    
    # Cache Settings
    ENABLE_CACHE: bool = os.getenv("ENABLE_CACHE", "true").lower() == "true"
    CACHE_DIR: Path = Path(os.getenv("CACHE_DIR", "./data/cache"))
    
    # Database Configuration (PostgreSQL)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "10"))
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    
    # Etherscan API Endpoints
    ETHERSCAN_API_BASE: str = "https://api.etherscan.io/v2/api"
    
    # Supported Contract Patterns
    SUPPORTED_PATTERNS = [
        "ERC20",
        "ERC721", 
        "ERC1155",
        "LENDING",
        "DEX",
        "BRIDGE",
        "UNKNOWN"
    ]
    
    # Known Proxy Patterns
    # EIP-1967: Standard proxy storage slot
    EIP1967_IMPLEMENTATION_SLOT: str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    
    # EIP-1967: Beacon proxy slot
    EIP1967_BEACON_SLOT: str = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
    
    # OpenZeppelin proxy patterns
    OPENZEPPELIN_IMPLEMENTATION_SLOT: str = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
    
    # EIP-897: DelegateProxy
    EIP897_IMPLEMENTATION_FUNCTION: str = "implementation()"
    
    # Pattern Detection Signatures
    # ERC20 required functions
    ERC20_SIGNATURES = [
        "totalSupply()",
        "balanceOf(address)",
        "transfer(address,uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "allowance(address,address)"
    ]
    
    # ERC721 required functions
    ERC721_SIGNATURES = [
        "balanceOf(address)",
        "ownerOf(uint256)",
        "safeTransferFrom(address,address,uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "setApprovalForAll(address,bool)",
        "getApproved(uint256)",
        "isApprovedForAll(address,address)"
    ]
    
    # Lending protocol common functions
    LENDING_SIGNATURES = [
        "deposit",
        "withdraw",
        "borrow",
        "repay",
        "liquidate"
    ]
    
    # DEX common functions (UniV2 pair: swap/getReserves/token0/token1/skim/sync)
    DEX_SIGNATURES = [
        "swap",
        "addLiquidity",
        "removeLiquidity",
        "getReserves",
        "getAmountOut",
        "token0",
        "token1",
        "skim",
        "sync",
        "factory",
    ]

    # Bridge common functions
    BRIDGE_SIGNATURES = [
        "lock",
        "unlock",
        "relay",
        "sendMessage",
        "receiveMessage",
        "depositFor",
        "withdrawTo",
    ]
    
    @classmethod
    def validate(cls) -> None:
        """
        Validate that required configuration is present.
        Raises ValueError if critical config is missing.
        """
        if not cls.ETHERSCAN_API_KEY:
            raise ValueError(
                "ETHERSCAN_API_KEY not set. "
                "Please set it in .env file or environment variables."
            )
        
        if not cls.RPC_URL:
            raise ValueError(
                "RPC_URL not set. "
                "Please set it in .env file or environment variables."
            )
        
        if not cls.DATABASE_URL:
            print(
                "WARNING: DATABASE_URL not set. "
                "Database features will not work. "
                "Set DATABASE_URL in .env or start PostgreSQL with docker-compose."
            )
        
        # Create cache directory if it doesn't exist
        if cls.ENABLE_CACHE:
            cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_etherscan_url(cls, module: str, action: str, **params) -> str:
        """
        Build Etherscan API URL with parameters.
        
        Args:
            module: API module (e.g., "contract", "proxy")
            action: API action (e.g., "getabi", "eth_getCode")
            **params: Additional query parameters
        
        Returns:
            Complete API URL
        """
        query = {
            "chainid": "1",
            "module": module,
            "action": action,
            "apikey": cls.ETHERSCAN_API_KEY,
            **params,
        }
        return f"{cls.ETHERSCAN_API_BASE}?{urlencode(query)}"


# NOTE: Config.validate() is NOT called on import.
# Call it explicitly when you need to validate (e.g., before RPC calls).
# This prevents noisy warnings when importing for tests or --help.

