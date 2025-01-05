# src/config.py

import logging
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_IN_DIR = BASE_DIR / "data_in"
DATA_OUT_DIR = BASE_DIR / "data_out"
LOG_DIR = BASE_DIR / "logs"

# External paths
EXTERNAL_CWE_TOP25_DIR = BASE_DIR.parent / "cwe_top25"
TARGET_CVES_CSV = EXTERNAL_CWE_TOP25_DIR / "data_in" / "top25-mitre-mapping-analysis-2023-public.csv"

# File paths
NVD_JSONL_FILE = DATA_IN_DIR / "nvd.jsonl"
#NVD_JSONL_FILE = "tmp/cve.json"

# Logging configuration
LOG_CONFIG = {
    "level": logging.INFO,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "dir": LOG_DIR
}

# Crawler settings
CRAWLER_SETTINGS = {
    "timeout": 30,
    "retry_count": 3,
    "delay_between_requests": 1,  # seconds
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
}

# URLs to ignore (will not be crawled)
IGNORED_URLS = [
    "www.cve.org",
    "cve.org",
    "www.securitytracker.com",
    "securitytracker.com",
    "exchange.xforce.ibmcloud.com"
]