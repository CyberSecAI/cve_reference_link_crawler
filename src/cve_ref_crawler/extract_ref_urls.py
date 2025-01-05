# src/cve_ref_crawler/extract_ref_urls.py

import json
from pathlib import Path
from typing import Dict, List, Set, Iterator
from .utils.file_utils import ensure_directory
from .utils.logging_utils import setup_logging
from config import LOG_CONFIG

class CVEProcessor:
    def __init__(self, input_file: str, output_dir: str):
        """
        Initialize the CVE processor
        
        Args:
            input_file: Path to input JSON file
            output_dir: Path to output directory
        """
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )
        
    def create_output_directories(self, cve_id: str) -> Path:
        """
        Create directory for CVE if it doesn't exist
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Path object for the created directory
        """
        cve_dir = self.output_dir / cve_id
        ensure_directory(cve_dir)
        self.logger.debug(f"Created directory: {cve_dir}")
        return cve_dir
        
    def extract_urls(self, references: List[Dict]) -> Set[str]:
        """
        Extract unique URLs from references
        
        Args:
            references: List of reference dictionaries
            
        Returns:
            Set of unique URLs
        """
        urls = {ref['url'] for ref in references if 'url' in ref}
        self.logger.debug(f"Extracted {len(urls)} unique URLs")
        return urls
        
    def save_urls(self, urls: Set[str], output_path: Path) -> None:
        """
        Save URLs to links.txt file
        
        Args:
            urls: Set of URLs to save
            output_path: Directory path to save links.txt
        """
        links_file = output_path / 'links.txt'
        with open(links_file, 'w') as f:
            for url in sorted(urls):
                f.write(f"{url}\n")
        self.logger.info(f"Saved {len(urls)} URLs to {links_file}")

    def read_json_content(self) -> Iterator[Dict]:
        """
        Read and parse JSON content from file
        
        Yields:
            Dict: Each CVE entry from the JSON file
        """
        try:
            self.logger.debug(f"Reading JSON file: {self.input_file}")
            with open(self.input_file, 'r') as f:
                content = f.read()
                # Handle array of JSON objects by wrapping in array if needed
                if not content.strip().startswith('['):
                    content = f"[{content}]"
                data = json.loads(content)
                
                for entry in data:
                    if 'cve' in entry:
                        yield entry
        except Exception as e:
            self.logger.error(f"Error reading JSON file: {e}")
                
    def process_file(self) -> None:
        """Process the JSON file and create output files"""
        # Create base output directory
        ensure_directory(self.output_dir)
        
        self.logger.info(f"Starting to process file: {self.input_file}")
        
        processed_count = 0
        error_count = 0
        
        # Process each CVE entry
        for entry in self.read_json_content():
            try:
                # Extract CVE data
                cve_data = entry.get('cve')
                if not cve_data:
                    self.logger.warning("No CVE data found in entry")
                    continue
                    
                # Get CVE ID
                cve_id = cve_data.get('id')
                if not cve_id:
                    self.logger.warning("No CVE ID found in entry")
                    continue
                    
                # Get references
                references = cve_data.get('references', [])
                if not references:
                    self.logger.info(f"No references found for {cve_id}")
                    continue
                
                # Create directory and save URLs
                self.logger.info(f"Processing {cve_id}")
                cve_dir = self.create_output_directories(cve_id)
                urls = self.extract_urls(references)
                self.save_urls(urls, cve_dir)
                self.logger.info(f"Successfully processed {cve_id} with {len(urls)} URLs")
                processed_count += 1
                
            except Exception as e:
                self.logger.error(f"Error processing entry: {e}")
                error_count += 1
        
        self.logger.info(f"Processing completed. Successfully processed {processed_count} entries with {error_count} errors.")