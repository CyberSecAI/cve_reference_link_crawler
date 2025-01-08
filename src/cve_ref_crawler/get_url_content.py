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
from typing import Optional, Dict, Tuple
from markitdown import MarkItDown
from markitdown._markitdown import FileConversionException
from tqdm import tqdm
from .utils.file_utils import ensure_directory
from .utils.logging_utils import setup_logging
from .handlers.googlesource import is_googlesource_url, handle_googlesource_url, parse_googlesource_response
from config import LOG_CONFIG, CRAWLER_SETTINGS, IGNORED_URLS

import urllib.robotparser
from urllib.parse import urlparse
from functools import lru_cache
import time

class RobotsParser:
    def __init__(self, user_agent):
        """Initialize robots parser with user agent"""
        self.user_agent = user_agent
        self.parsers = {}
        self.last_checked = {}
        self.cache_duration = 3600  # Cache robots.txt for 1 hour

    @lru_cache(maxsize=100)
    def get_base_url(self, url: str) -> str:
        """Get base URL for robots.txt"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def get_robots_parser(self, url: str) -> urllib.robotparser.RobotFileParser:
        """Get or create robots parser for a given URL"""
        base_url = self.get_base_url(url)
        
        # Check if we need to refresh the cached parser
        now = time.time()
        if base_url in self.parsers:
            if now - self.last_checked[base_url] > self.cache_duration:
                del self.parsers[base_url]
                del self.last_checked[base_url]

        # Create new parser if needed
        if base_url not in self.parsers:
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(f"{base_url}/robots.txt")
            try:
                rp.read()
                self.parsers[base_url] = rp
                self.last_checked[base_url] = now
            except Exception as e:
                # If robots.txt can't be fetched, assume everything is allowed
                return None

        return self.parsers.get(base_url)

    def can_fetch(self, url: str) -> bool:
        """Check if URL can be fetched according to robots.txt"""
        try:
            parser = self.get_robots_parser(url)
            if parser is None:  # No robots.txt available
                return True
            return parser.can_fetch(self.user_agent, url)
        except Exception as e:
            # On error, assume we can fetch
            return True
        
        
class ContentCrawler:
    def __init__(self, output_dir: str):
        """Initialize the content crawler"""
        self.output_dir = Path(output_dir)
        self.session = requests.Session()
        self.session.headers.update(CRAWLER_SETTINGS["headers"])
        
        # Initialize robots parser with our user agent
        self.robots = RobotsParser(
            CRAWLER_SETTINGS["headers"]["User-Agent"]
        )
        
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )
        self.md_converter = MarkItDown()
        
        # Load dead domains
        self.dead_domains = set()
        self._load_dead_domains()

    def find_cve_specific_urls(self, text_file: Path, target_cve: str) -> set[str]:
        """
        Extract URLs that appear on the same line as the target CVE
        
        Args:
            text_file: Path to the text file to analyze
            target_cve: The specific CVE ID we're interested in
            
        Returns:
            Set of URLs that appear on same line as the CVE
        """
        urls = set()
        
        try:
            with open(text_file, 'r', encoding='utf-8') as f:
                for line in f:
                    # Only process lines containing our target CVE
                    if target_cve in line:
                        # Look for googlesource URLs in this line
                        matches = re.finditer(r'https://[^\s\(\)\[\]<>\"\']+', line)
                        for match in matches:
                            url = match.group(0)
                            # Remove trailing punctuation that might have been caught
                            url = url.rstrip('.,;')
                            urls.add(url)
                            
            if urls:
                self.logger.info(f"Found {len(urls)} URLs for {target_cve} in {text_file}")
            else:
                self.logger.debug(f"No URLs found for {target_cve} in {text_file}")
                
            return urls
            
        except Exception as e:
            self.logger.error(f"Error extracting URLs for {target_cve} from {text_file}: {str(e)}")
            return set()

    def _convert_content(self, filepath: Path) -> Tuple[Optional[str], str]:
        """
        Convert content using MarkItDown with fallback methods
        
        Args:
            filepath: Path to file to convert
            
        Returns:
            Tuple[Optional[str], str]: (converted content, method used)
        """
        # Try MarkItDown first
        try:
            result = self.md_converter.convert(str(filepath))
            return result.text_content, "markitdown"
        except FileConversionException as e:
            self.logger.warning(f"MarkItDown conversion failed: {str(e)}")
        except Exception as e:
            self.logger.warning(f"Unexpected error in MarkItDown conversion: {str(e)}")

        # Fallback for PDFs using PyPDF2
        if str(filepath).lower().endswith('.pdf'):
            try:
                self.logger.info("Attempting PDF conversion with PyPDF2")
                with open(filepath, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    text = []
                    for page in pdf_reader.pages:
                        try:
                            text.append(page.extract_text())
                        except Exception as e:
                            self.logger.warning(f"Error extracting page text: {str(e)}")
                            continue
                    if text:
                        return "\n".join(text), "pypdf2"
            except Exception as e:
                self.logger.warning(f"PyPDF2 conversion failed: {str(e)}")

        # If all methods fail
        self.logger.error(f"All conversion methods failed for {filepath}")
        return None, "none"

    def _load_dead_domains(self):
        """Load dead domains from CSV if it exists"""
        try:
            if Path(DEAD_DOMAINS_CSV).exists():
                df = pd.read_csv(DEAD_DOMAINS_CSV)
                if 'Domain' in df.columns:
                    self.dead_domains = set(df['Domain'].str.lower())
                    self.logger.info(f"Loaded {len(self.dead_domains)} dead domains from CSV")
            else:
                self.logger.debug("Dead domains CSV file not found")
        except Exception as e:
            self.logger.error(f"Error loading dead domains CSV: {str(e)}")
            

    def should_ignore_url(self, url: str) -> bool:
        """
        Check if URL should be ignored based on rules and robots.txt
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL should be ignored
        """
        # First check existing ignore rules
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.lower()
        
        # Remove 'www.' prefix if present for comparison
        if hostname.startswith('www.'):
            hostname = hostname[4:]
            
        # Check against IGNORED_URLS
        for ignored in IGNORED_URLS:
            ignored = ignored.lower()
            if ignored.startswith('www.'):
                ignored = ignored[4:]
            if ignored in hostname:
                self.logger.info(f"Ignoring URL {url} (matches ignore pattern: {ignored})")
                return True
                
        # Check against dead domains
        if hostname in self.dead_domains or f"www.{hostname}" in self.dead_domains:
            self.logger.info(f"Ignoring URL {url} (matches dead domain)")
            return True
            
        # Check robots.txt
        if not self.robots.can_fetch(url):
            self.logger.info(f"Ignoring URL {url} (blocked by robots.txt)")
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

 

    def _fetch_url(self, url: str) -> Optional[Dict]:
        """Fetch content from URL"""
        try:
            # First check robots.txt
            if not self.robots.can_fetch(url):
                self.logger.warning(f"URL {url} blocked by robots.txt")
                return None
                
            # Handle special cases
            if is_googlesource_url(url):
                modified_url = handle_googlesource_url(url)
                if not modified_url:
                    self.logger.warning(f"Skipping unsupported googlesource URL: {url}")
                    return None
                    
                response = self.session.get(modified_url, timeout=30)
                response.raise_for_status()
                
                content = parse_googlesource_response(response.text)
                if content:
                    return {'content': content, 'type': 'text'}
                return None
            
            # Normal URL handling
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            if 'application/pdf' in content_type:
                return {'content': response.content, 'type': 'pdf'}
            return {'content': response.text, 'type': 'html'}
                
        except requests.RequestException as e:
            self.logger.error(f"Error fetching URL {url}: {str(e)}")
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

    def process_url(self, url: str, cve_id: str) -> bool:
        """Process a single URL: fetch, save raw content, and convert"""
        self.logger.info(f"Started processing URL: {url} for {cve_id}")
        
        try:
            # Skip if URL should be ignored
            if self.should_ignore_url(url):
                self.logger.info(f"Skipping ignored URL: {url}")
                return True

            # Fetch content
            result = self._fetch_url(url)
            if not result:
                return False

            # Save raw content
            raw_filepath = self._save_raw_content(
                content=result['content'],
                url=url,
                cve_id=cve_id,
                content_type=result['type']
            )
            
            if not raw_filepath:
                return False
            
            # Convert the content using MarkItDown
            converted_content, conversion_method = self._convert_content(raw_filepath)
            if not converted_content:
                self.logger.error(f"Failed to convert content from {url}")
                return False
                
            # Save converted content
            text_filepath = self._save_converted_content(converted_content, url, cve_id)
            success = text_filepath is not None
            
            if success:
                self.logger.info(f"Successfully processed {url} using {conversion_method}")
            else:
                self.logger.error(f"Failed to save converted content from {url}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error processing URL {url}: {e}")
            return False

    def process_cve_urls(self, cve_id: str) -> None:
        """Process URLs for a given CVE"""
        # Check if already processed
        if self.is_cve_processed(cve_id):
            self.logger.info(f"Skipping {cve_id} - already processed")
            return
                
        self.logger.info(f"Starting to process URLs for {cve_id}")
        
        # First pass: Process URLs from links.txt
        links_file = self.output_dir / cve_id / "links.txt"
        if not links_file.exists():
            self.logger.error(f"No links.txt found for {cve_id}")
            return
            
        try:
            with open(links_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                self.logger.info(f"No URLs found in links.txt for {cve_id}")
                return
                
            self.logger.info(f"Found {len(urls)} URLs to process for {cve_id}")
            
            # Process each URL
            success_count = 0
            with tqdm(total=len(urls), desc=f"Processing {cve_id}", unit="url") as pbar:
                for url in urls:
                    if self.process_url(url, cve_id):
                        success_count += 1
                    pbar.update(1)
            
            self.logger.info(f"Completed processing {cve_id}: {success_count}/{len(urls)} URLs successful")
                
        except Exception as e:
            self.logger.error(f"Error processing URLs for {cve_id}: {str(e)}")