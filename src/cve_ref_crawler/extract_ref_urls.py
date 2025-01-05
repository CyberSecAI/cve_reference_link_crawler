# src/cve_ref_crawler/extract_ref_urls.py

import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Iterator
from .utils.file_utils import ensure_directory
from .utils.logging_utils import setup_logging
from .utils.cve_filter import load_target_cves
from config import LOG_CONFIG

class CVEProcessor:
    def __init__(self, input_file: str, output_dir: str, target_cves: Optional[Set[str]] = None):
        """
        Initialize the CVE processor
        
        Args:
            input_file: Path to input JSON file
            output_dir: Path to output directory
            target_cves: Optional set of CVE IDs to process
        """
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.target_cves = target_cves
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )
        
        if target_cves:
            self.logger.info(f"Initialized with {len(target_cves)} target CVEs")

    def read_json_content(self) -> Iterator[Dict]:
        """
        Read and parse JSON content from file
        
        Yields:
            Dict: Each CVE entry from the JSON file
        """
        try:
            with open(self.input_file, 'r') as f:
                content = f.read()
                # Handle array of JSON objects
                data = json.loads(f"[{content}]")
                for entry in data:
                    if 'cve' in entry:
                        yield entry
        except Exception as e:
            self.logger.error(f"Error reading JSON file: {e}")
        
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
    
    def should_process_cve(self, cve_id: str) -> bool:
        """
        Check if CVE should be processed based on target list
        
        Args:
            cve_id: CVE ID to check
            
        Returns:
            bool: True if CVE should be processed
        """
        if self.target_cves is None:
            return True
        return cve_id in self.target_cves
                
    def process_file(self) -> None:
        """Process the JSON file and create output files"""
        # Create base output directory
        ensure_directory(self.output_dir)
        
        self.logger.info(f"Starting to process file: {self.input_file}")
        
        processed_count = 0
        skipped_count = 0
        error_count = 0
        
        # Process each CVE entry
        for entry in self.read_json_content():
            try:
                # Extract CVE data
                cve_data = entry.get('cve')
                if not cve_data:
                    continue
                    
                # Get CVE ID
                cve_id = cve_data.get('id')
                if not cve_id:
                    continue
                
                # Check if we should process this CVE
                if not self.should_process_cve(cve_id):
                    skipped_count += 1
                    self.logger.debug(f"Skipping {cve_id} (not in target list)")
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
        
        self.logger.info(
            f"Processing completed. "
            f"Processed: {processed_count}, "
            f"Skipped: {skipped_count}, "
            f"Errors: {error_count}"
        )