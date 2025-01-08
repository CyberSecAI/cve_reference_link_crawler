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

#TARGET_CVES_CSV =  "./data_in/top25-mitre-mapping-analysis-2023-public_10.csv"
TARGET_CVES_CSV = EXTERNAL_CWE_TOP25_DIR / "data_in" / "top25-mitre-mapping-analysis-2023-public.csv"

# File paths
NVD_JSONL_FILE = DATA_IN_DIR / "nvd.jsonl"
#NVD_JSONL_FILE = "tmp/cve.json"

DEAD_DOMAINS_CSV = DATA_IN_DIR / "dead_domains.csv"  

# Logging configuration
LOG_CONFIG = {
    #"level": logging.INFO,
    "level": logging.DEBUG, 
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "dir": LOG_DIR
}

CRAWLER_SETTINGS = {
    "timeout": 30,  # General request timeout
    "retry_count": 3,
    "delay_between_requests": 1,  # seconds
    "robots_txt": {
        "fetch_timeout": 10,      # Timeout for fetching robots.txt
        "rule_check_timeout": 5,  # Timeout for checking rules in robots.txt
        "cache_duration": 3600,   # How long to cache robots.txt (seconds)
    },
    "url_process_timeout": 30,    # Overall timeout for processing a single URL
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1"
    }
}


# URLs to ignore (will not be crawled)
IGNORED_URLS = [
    "www.cve.org",
    "cve.org",
    "cve.mitre.org",
    "cwe.mitre.org",
    "first.org",
    "nist.gov",    
    "www.securitytracker.com",
    "securitytracker.com",
    "exchange.xforce.ibmcloud.com"
]