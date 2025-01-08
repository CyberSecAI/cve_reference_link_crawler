# src/cve_ref_crawler/llm_extractor.py

from pathlib import Path
from typing import Optional
import logging
from .utils.logging_utils import setup_logging
from config import LOG_CONFIG

class VulnerabilityExtractor:
    def __init__(self, output_dir: str):
        """Initialize the vulnerability extractor"""
        self.output_dir = Path(output_dir)
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )

    def should_process_refined_content(self, cve_id: str) -> bool:
        """Check if vulnerability extraction is needed"""
        refined_dir = self.output_dir / cve_id / "refined"
        if refined_dir.exists() and any(refined_dir.iterdir()):
            self.logger.info(f"Skipping {cve_id} - refined content already exists")
            return False
        return True
    
    def process_cve(self, cve_id: str) -> bool:
        """
        Process all text files for a CVE and extract vulnerability information
        
        Args:
            cve_id: The CVE ID to process
            
        Returns:
            bool: True if successful extraction
        """
        # Setup directories
        text_dir = self.output_dir / cve_id / "text"
        refined_dir = self.output_dir / cve_id / "refined"
        
        # Consider extracted if refined directory exists and contains files 
        if refined_dir.exists():
            has_refined = any(refined_dir.iterdir())
            if has_refined:
                self.logger.debug(f"{cve_id} already has refined vulnerability content")
                return True
            
        if not text_dir.exists():
            self.logger.warning(f"No text directory found for {cve_id}")
            return False
            
        try:
            # Create refined directory
            refined_dir.mkdir(parents=True, exist_ok=True)
            
            # Combine all text content
            all_content = []
            for text_file in text_dir.glob("*.txt"):
                try:
                    with open(text_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        all_content.append(f"=== Content from {text_file.name} ===\n{content}\n")
                except Exception as e:
                    self.logger.error(f"Error reading {text_file}: {e}")
                    continue
            
            if not all_content:
                self.logger.warning(f"No content found for {cve_id}")
                return False
                
            # Save combined raw content
            with open(refined_dir / "combined.txt", 'w', encoding='utf-8') as f:
                f.write("\n".join(all_content))
                
            # Extract vulnerability information using LLM
            extracted_info = self._extract_vulnerability_info(
                cve_id=cve_id,
                content="\n".join(all_content)
            )
            
            if extracted_info == "NOINFO":
                self.logger.info(f"No vulnerability information found for {cve_id}")
                return False
                
            # Save extracted information
            with open(refined_dir / "refined.txt", 'w', encoding='utf-8') as f:
                f.write(extracted_info)
                
            self.logger.info(f"Successfully processed {cve_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing {cve_id}: {e}")
            return False

    def _extract_vulnerability_info(self, cve_id: str, content: str) -> str:
        """
        Extract vulnerability information using LLM
        
        Args:
            cve_id: The CVE ID being processed
            content: The text content to analyze
            
        Returns:
            str: Extracted vulnerability info or "NOINFO"
        """
        # This is where you'd implement the LLM call
        # For now, placeholder
        return "NOINFO"