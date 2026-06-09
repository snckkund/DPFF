"""
DPFF Forensic Logger
Centralized structured logging for all DPFF modules.
Provides console + file logging with rotation.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime


def _get_output_dir():
    """Return the directory for writable outputs (logs, db, reports)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)  # Next to DPFF.exe
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Project root


# Ensure logs directory exists
LOG_DIR = os.path.join(_get_output_dir(), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, 'dpff.log')

# Custom formatter for console (concise, colored-friendly)
CONSOLE_FORMAT = '%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s'
CONSOLE_DATE_FORMAT = '%H:%M:%S'

# Detailed formatter for log file (full timestamps, module info)
FILE_FORMAT = '%(asctime)s | %(levelname)-7s | %(name)-25s | %(funcName)-20s | %(message)s'
FILE_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'

# Track if root logger has been configured
_configured = False


def _configure_root():
    """Configure the root DPFF logger (called once)."""
    global _configured
    if _configured:
        return
    
    root_logger = logging.getLogger('dpff')
    root_logger.setLevel(logging.DEBUG)
    
    # Console Handler — INFO and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(CONSOLE_FORMAT, datefmt=CONSOLE_DATE_FORMAT))
    root_logger.addHandler(console_handler)
    
    # File Handler — DEBUG and above with rotation (5MB max, keep 3 backups)
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(FILE_FORMAT, datefmt=FILE_DATE_FORMAT))
    root_logger.addHandler(file_handler)
    
    _configured = True
    root_logger.info("="*60)
    root_logger.info(f"DPFF Session Started at {datetime.now().isoformat()}")
    root_logger.info("="*60)


def get_logger(name: str) -> logging.Logger:
    """
    Get a named logger under the 'dpff' hierarchy.
    
    Usage:
        from src.forensic_logger import get_logger
        logger = get_logger(__name__)
        logger.info("Message here")
    """
    _configure_root()
    return logging.getLogger(f'dpff.{name}')
