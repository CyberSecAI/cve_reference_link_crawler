# src/main.py

from pathlib import Path
from tqdm import tqdm
from cve_ref_crawler import CVEProcessor, ContentCrawler
from cve_ref_crawler.secondary_processor import SecondaryProcessor
from cve_ref_crawler.utils.cve_filter import load_target_cves
from cve_ref_crawler.utils.logging_utils import setup_logging
from cve_ref_crawler.llm_extractor import VulnerabilityExtractor
from config import NVD_JSONL_FILE, DATA_OUT_DIR, LOG_CONFIG, TARGET_CVES_CSV, DEAD_DOMAINS_CSV

def main():
    logger = setup_logging(
        log_dir=LOG_CONFIG["dir"],
        log_level=LOG_CONFIG["level"],
        module_name="main"
    )
    logger.info("Starting CVE reference processing")
    
    # Load target CVEs from CSV
    target_cves = load_target_cves(TARGET_CVES_CSV)
    
    if not target_cves:
        logger.error("No target CVEs loaded. Exiting.")
        return
    
    # Initialize and run CVE processor
    logger.info("Initializing CVE processor")
    processor = CVEProcessor(
        input_file=NVD_JSONL_FILE,
        output_dir=DATA_OUT_DIR,
        target_cves=target_cves
    )
    processor.process_file()
    
    # Initialize content crawler
    logger.info("Initializing content crawler")
    crawler = ContentCrawler(output_dir=DATA_OUT_DIR)
    
    # Initialize vulnerability_extractor
    vulnerability_extractor = VulnerabilityExtractor(output_dir=DATA_OUT_DIR)

    # Get list of CVE directories to process
    cve_dirs = [d for d in DATA_OUT_DIR.iterdir() if d.is_dir()]
    
    # Initialize counters for primary processing
    primary_skipped_count = 0
    primary_processed_count = 0
    
    # Phase 1: Process primary URLs with progress bar
    logger.info("Phase 1: Processing primary URLs")
    with tqdm(total=len(cve_dirs), desc="Processing primary URLs", unit="cve") as pbar:
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            
            if cve_id not in target_cves:
                logger.warning(f"Found directory for non-target CVE: {cve_id}")
                pbar.update(1)
                continue
                
            if crawler.is_cve_processed(cve_id):
                primary_skipped_count += 1
                pbar.set_postfix({"skipped": primary_skipped_count, "processed": primary_processed_count})
                pbar.update(1)
                continue
                
            logger.info(f"Processing primary URLs for {cve_id}")
            crawler.process_cve_urls(cve_id)
            primary_processed_count += 1
            pbar.set_postfix({"skipped": primary_skipped_count, "processed": primary_processed_count})
            pbar.update(1)

    # Phase 2: Process secondary URLs from text content
    logger.info("Phase 2: Processing secondary URLs")
    secondary_processor = SecondaryProcessor(DATA_OUT_DIR)
    secondary_processed_count = 0
    secondary_skipped_count = 0
    
    with tqdm(total=len(cve_dirs), desc="Processing secondary URLs", unit="cve") as pbar:
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            if cve_id in target_cves:
                if secondary_processor.is_secondary_processing_completed(cve_id):
                    secondary_skipped_count += 1
                else:
                    logger.info(f"Processing secondary URLs for {cve_id}")
                    secondary_processor.process_cve_directory(cve_id)
                    secondary_processed_count += 1
            pbar.set_postfix({"processed": secondary_processed_count, "skipped": secondary_skipped_count})
            pbar.update(1)

    # Phase 3: Extract vulnerability information
    logger.info("Phase 3: Extracting vulnerability information")
    extraction_skipped_count = 0
    extraction_processed_count = 0

    with tqdm(total=len(cve_dirs), desc="Extracting vulnerability info", unit="cve") as pbar:
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            if cve_id in target_cves:
                if vulnerability_extractor.is_cve_extracted(cve_id):
                    extraction_skipped_count += 1
                else:
                    if vulnerability_extractor.process_cve(cve_id):
                        extraction_processed_count += 1
            pbar.update(1)
            
    crawler.finish_processing()
    
    logger.info(
        f"Completed CVE reference processing:\n"
        f"Phase 1 (Primary URLs):\n"
        f"  - CVEs skipped (already processed): {primary_skipped_count}\n"
        f"  - CVEs processed: {primary_processed_count}\n"
        f"  - Total CVEs handled: {primary_skipped_count + primary_processed_count}\n"
        f"Phase 2 (Secondary URLs):\n"
        f"  - CVEs skipped (already processed): {secondary_skipped_count}\n"
        f"  - CVEs processed: {secondary_processed_count}\n"
        f"  - Total CVEs handled: {secondary_skipped_count + secondary_processed_count}\n"
        f"Phase 3 (Vulnerability Extraction):\n"
        f"  - CVEs skipped: {extraction_skipped_count}\n"
        f"  - CVEs processed: {extraction_processed_count}\n"
        f"  - Total CVEs handled: {extraction_skipped_count + extraction_processed_count}"
    )

if __name__ == "__main__":
    main()