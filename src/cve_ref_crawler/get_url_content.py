# src/cve_ref_crawler/get_url_content.py

import os
from pathlib import Path
import requests
from urllib.parse import urlparse
import hashlib
from datetime import datetime
import logging
from bs4 import BeautifulSoup
import PyPDF2
import io
from typing import Optional, Dict
from markitdown import MarkItDown
from .utils.file_utils import ensure_directory

class ContentCrawler:
    def __init__(self, output_dir: str):
        """
        Initialize the content crawler
        
        Args:
            output_dir: Base output directory path
        """
        self.output_dir = Path(output_dir)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('crawler.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.md_converter = MarkItDown()

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
        """
        Process all URLs for a given CVE ID
        
        Args:
            cve_id: CVE ID to process
        """
        self.logger.info(f"Starting to process URLs for {cve_id}")
        
        links_file = self.output_dir / cve_id / "links.txt"
        if not links_file.exists():
            self.logger.error(f"No links.txt found for {cve_id}")
            return
            
        try:
            with open(links_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            self.logger.info(f"Found {len(urls)} URLs to process for {cve_id}")
            
            for url in urls:
                success = self.process_url(url, cve_id)
                if not success:
                    self.logger.warning(f"Failed to process {url} for {cve_id}")
                    
            self.logger.info(f"Completed processing URLs for {cve_id}")
            
        except Exception as e:
            self.logger.error(f"Error processing URLs for {cve_id}: {str(e)}")