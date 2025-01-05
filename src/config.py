# src/config.py

import logging
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_IN_DIR = BASE_DIR / "data_in"
DATA_OUT_DIR = BASE_DIR / "data_out"
LOG_DIR = BASE_DIR / "logs"

# File paths
NVD_JSONL_FILE = DATA_IN_DIR / "nvd.jsonl"

# Logging configuration
LOG_CONFIG = {
    "level": logging.INFO,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "dir": LOG_DIR
}

# Crawler settings
CRAWLER_SETTINGS = {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "timeout": 30,
    "retry_count": 3,
    "delay_between_requests": 1,  # seconds
}