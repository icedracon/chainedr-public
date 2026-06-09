"""
ChainEDR Logging Module

Structured logging for all ChainEDR modules.
Replaces print() with proper log levels, structured output,
and configurable verbosity.
"""

import logging
import sys
from typing import Optional


# Module-level loggers
_loggers = {}


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """
    Get or create a named logger for a ChainEDR module.

    Args:
        name: Logger name (typically module name like 'classifier')
        level: Optional log level override

    Returns:
        Configured Logger instance
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"chainedr.{name}")

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(level or logging.WARNING)
    logger.propagate = False

    _loggers[name] = logger
    return logger


def set_global_level(level: int) -> None:
    """
    Set log level for all ChainEDR loggers.

    Args:
        level: logging.DEBUG, logging.INFO, etc.
    """
    for logger in _loggers.values():
        logger.setLevel(level)
