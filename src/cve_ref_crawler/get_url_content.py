# src/cve_ref_crawler/get_url_content.py

import os
from pathlib import Path
import requests
from urllib.parse import urlparse
import hashlib
from datetime import datetime
from bs4 import BeautifulSoup
import PyPDF2
import io
from typing import Optional, Dict
from markitdown import MarkItDown
from tqdm import tqdm
from .utils.file_utils import ensure_directory
from .utils.logging_utils import setup_logging
from config import LOG_CONFIG, CRAWLER_SETTINGS, IGNORED_URLS

class ContentCrawler:
    def __init__(self, output_dir: str):
        """Initialize the content crawler"""
        self.output_dir = Path(output_dir)
        self.session = requests.Session()
        self.session.headers.update(CRAWLER_SETTINGS["headers"])
        
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )
        self.md_converter = MarkItDown()

    def should_ignore_url(self, url: str) -> bool:
        """
        Check if URL should be ignored based on ignore list
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL should be ignored
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.lower()
        
        # Remove 'www.' prefix if present for comparison
        if hostname.startswith('www.'):
            hostname = hostname[4:]
            
        for ignored in IGNORED_URLS:
            ignored = ignored.lower()
            if ignored.startswith('www.'):
                ignored = ignored[4:]
            if ignored in hostname:
                self.logger.info(f"Ignoring URL {url} (matches ignore pattern: {ignored})")
                return True
        return False

    def is_cve_processed(self, cve_id: str) -> bool:
        """
        Check if CVE has already been processed
        
        Args:
            cve_id: CVE ID to check
            
        Returns:
            bool: True if CVE has already been processed
        """
        text_dir = self.output_dir / cve_id / "text"
        # Check if text directory exists and is not empty
        if text_dir.exists() and any(text_dir.iterdir()):
            return True
        return False

    def _generate_filename(self, url: str, content_type: str) -> str:
        """Generate a unique filename based on URL and timestamp"""
        parsed_url = urlparse(url)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        base = f"{parsed_url.netloc}_{url_hash}_{timestamp}"
        if content_type == "pdf":
            return f"{base}.pdf"
        return f"{base}.html"

    def _save_raw_content(self, content: str | bytes, url: str, cve_id: str, content_type: str = "html") -> Optional[Path]:
        """Save the raw content to a file"""
        raw_dir = self.output_dir / cve_id / "raw"
        ensure_directory(raw_dir)
        
        filename = self._generate_filename(url, content_type)
        filepath = raw_dir / filename
        
        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"
        
        try:
            with open(filepath, mode, encoding=encoding) as f:
                f.write(content)
            self.logger.info(f"Raw content saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error saving raw content: {str(e)}")
            return None

    def _save_converted_content(self, content: str, url: str, cve_id: str) -> Optional[Path]:
        """Save the converted text content"""
        text_dir = self.output_dir / cve_id / "text"
        ensure_directory(text_dir)
        
        filename = self._generate_filename(url, "txt")
        filepath = text_dir / filename
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            self.logger.info(f"Converted content saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error saving converted content: {str(e)}")
            return None

    def _convert_content(self, filepath: Path) -> Optional[str]:
        """Convert content using MarkItDown"""
        try:
            result = self.md_converter.convert(str(filepath))
            return result.text_content
        except Exception as e:
            self.logger.error(f"Error converting content: {str(e)}")
            return None

    def _fetch_url(self, url: str) -> Optional[Dict]:
        """Fetch content from URL"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            if 'application/pdf' in content_type:
                return {'content': response.content, 'type': 'pdf'}
            return {'content': response.text, 'type': 'html'}
                
        except requests.RequestException as e:
            self.logger.error(f"Error fetching URL {url}: {str(e)}")
            return None

    def process_url(self, url: str, cve_id: str) -> bool:
        """
        Process a single URL: fetch, save raw content, and convert
        
        Args:
            url: URL to process
            cve_id: CVE ID for organizing output
            
        Returns:
            bool: True if processing was successful
        """
        self.logger.info(f"Started processing URL: {url} for {cve_id}")
        
        # Fetch content
        result = self._fetch_url(url)
        if not result:
            self.logger.error(f"Failed to fetch content from {url}")
            return False
            
        # Save raw content
        raw_filepath = self._save_raw_content(
            content=result['content'],
            url=url,
            cve_id=cve_id,
            content_type=result['type']
        )
        if not raw_filepath:
            self.logger.error(f"Failed to save raw content from {url}")
            return False
            
        # Convert and save text content
        self.logger.info(f"Converting content from {url}")
        converted_content = self._convert_content(raw_filepath)
        if not converted_content:
            self.logger.error(f"Failed to convert content from {url}")
            return False
            
        text_filepath = self._save_converted_content(
            content=converted_content,
            url=url,
            cve_id=cve_id
        )
        
        success = text_filepath is not None
        if success:
            self.logger.info(f"Successfully processed {url}")
        else:
            self.logger.error(f"Failed to save converted content from {url}")
        return success

    def process_cve_urls(self, cve_id: str) -> None:
        """Process all URLs for a given CVE with progress bar"""
        # Check if already processed
        if self.is_cve_processed(cve_id):
            self.logger.info(f"Skipping {cve_id} - already processed")
            return
            
        self.logger.info(f"Starting to process URLs for {cve_id}")
        
        links_file = self.output_dir / cve_id / "links.txt"
        if not links_file.exists():
            self.logger.error(f"No links.txt found for {cve_id}")
            return
        
        try:
            with open(links_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"Found {len(urls)} URLs to process for {cve_id}")
            
            success_count = 0
            with tqdm(total=len(urls), desc=f"Processing {cve_id}", unit="url") as pbar:
                for url in urls:
                    if self.process_url(url, cve_id):
                        success_count += 1
                    pbar.update(1)
            
            self.logger.info(f"Completed processing {cve_id}: {success_count}/{len(urls)} URLs successful")
            
        except Exception as e:
            self.logger.error(f"Error processing URLs for {cve_id}: {str(e)}")




