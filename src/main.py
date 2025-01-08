# src/main.py

from pathlib import Path
from tqdm import tqdm
from cve_ref_crawler import CVEProcessor, ContentCrawler
from cve_ref_crawler.secondary_processor import SecondaryProcessor
from cve_ref_crawler.utils.cve_filter import load_target_cves
from cve_ref_crawler.utils.logging_utils import setup_logging
from config import NVD_JSONL_FILE, DATA_OUT_DIR, LOG_CONFIG, TARGET_CVES_CSV

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
    
    with tqdm(total=len(cve_dirs), desc="Processing secondary URLs", unit="cve") as pbar:
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            if cve_id in target_cves:
                logger.info(f"Processing secondary URLs for {cve_id}")
                secondary_processor.process_cve_directory(cve_id)
                secondary_processed_count += 1
            pbar.update(1)
    
    # Phase 3: Extract vulnerability information
    logger.info("Phase 3: Extracting vulnerability information")
    extractor = VulnerabilityExtractor(DATA_OUT_DIR)
    
    success_count = 0
    for cve_id in tqdm(cve_ids, desc="Extracting vulnerability info"):
        if extractor.process_cve(cve_id):
            success_count += 1
            
    crawler.finish_processing()
    
    logger.info(f"Completed vulnerability extraction. Successful: {success_count}/{len(cve_ids)}")
    
    logger.info(
        f"Completed CVE reference processing:\n"
        f"Phase 1 (Primary URLs):\n"
        f"  - CVEs skipped (already processed): {primary_skipped_count}\n"
        f"  - CVEs processed: {primary_processed_count}\n"
        f"  - Total CVEs handled: {primary_skipped_count + primary_processed_count}\n"
        f"Phase 2 (Secondary URLs):\n"
        f"  - CVEs processed for secondary URLs: {secondary_processed_count}"
    )

if __name__ == "__main__":
    main()