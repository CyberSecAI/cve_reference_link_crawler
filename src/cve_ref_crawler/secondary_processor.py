# src/cve_ref_crawler/secondary_processor.py

import re
from pathlib import Path
from typing import Set, Optional, List, Dict
from .get_url_content import ContentCrawler
from .utils.logging_utils import setup_logging
from config import LOG_CONFIG

class SecondaryProcessor:
    """Process text files to find and fetch CVE-specific URLs"""
    
    def __init__(self, base_dir: str):
        """
        Initialize the secondary processor
        
        Args:
            base_dir: Base directory containing CVE directories
        """
        self.base_dir = Path(base_dir)
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )
        self.crawler = ContentCrawler(base_dir)

    def is_url_already_processed(self, cve_id: str, url: str) -> bool:
        """Check if a URL has already been processed by looking for its content"""
        # Check both raw and text directories for files containing the URL's domain and hash
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        file_prefix = f"{domain}_{url_hash}"
        
        raw_dir = self.output_dir / cve_id / "raw"
        text_dir = self.output_dir / cve_id / "text"
        
        # Check if files exist with this URL's signature
        for directory in [raw_dir, text_dir]:
            if directory.exists():
                for file in directory.iterdir():
                    if file_prefix in file.name:
                        self.logger.debug(f"URL {url} already processed (found {file})")
                        return True
        return False


    def extract_cve_specific_urls(self, text_content: str, cve_id: str) -> Set[str]:
        """
        Extract URLs specifically related to the CVE
        
        Args:
            text_content: Content to search
            cve_id: CVE ID to look for
            
        Returns:
            Set of URLs
        """
        urls = set()
        
        # Look for URLs in lines containing the CVE ID
        for line in text_content.split('\n'):
            if cve_id in line:
                # Find URLs in this line
                found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', line)
                urls.update(found_urls)
        
        # Look for URLs in markdown tables containing the CVE ID
        table_lines = []
        in_table = False
        
        for line in text_content.split('\n'):
            if '|' in line:
                if not in_table:
                    table_lines = [line]
                    in_table = True
                else:
                    table_lines.append(line)
                    if cve_id in line:
                        # Found CVE in table, extract URLs from this row
                        found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', line)
                        urls.update(found_urls)
            else:
                in_table = False
        
        return urls

    def process_cve_directory(self, cve_id: str) -> None:
        """
        Process text files in a CVE directory
        
        Args:
            cve_id: CVE ID to process
        """
        cve_dir = self.base_dir / cve_id
        text_dir = cve_dir / "text"
        
        if not text_dir.exists():
            self.logger.warning(f"No text directory found for {cve_id}")
            return
            
        # Create secondary directory for additional content
        secondary_dir = cve_dir / "secondary"
        
        for text_file in text_dir.glob("*"):
            try:
                with open(text_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                urls = self.extract_cve_specific_urls(content, cve_id)
                if urls:
                    self.logger.info(f"Found {len(urls)} CVE-specific URLs in {text_file}")
                    
                    for url in urls:
                        if not self.crawler.should_ignore_url(url):
                            self.logger.info(f"Processing secondary URL: {url}")
                            self.crawler.process_url(url, cve_id)
                            
            except Exception as e:
                self.logger.error(f"Error processing {text_file}: {str(e)}")

def process_directories(base_dir: str, cve_ids: Optional[List[str]] = None) -> None:
    """
    Process all or specific CVE directories
    
    Args:
        base_dir: Base directory containing CVE directories
        cve_ids: Optional list of specific CVE IDs to process
    """
    processor = SecondaryProcessor(base_dir)
    base_path = Path(base_dir)
    
    if cve_ids:
        directories = [d for d in base_path.iterdir() if d.is_dir() and d.name in cve_ids]
    else:
        directories = [d for d in base_path.iterdir() if d.is_dir() and d.name.startswith("CVE-")]
        
    for cve_dir in directories:
        processor.process_cve_directory(cve_dir.name)