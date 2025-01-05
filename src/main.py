# src/main.py

from pathlib import Path
from tqdm import tqdm
from cve_ref_crawler import CVEProcessor, ContentCrawler
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
    
    # Get list of CVE directories to process
    cve_dirs = [d for d in DATA_OUT_DIR.iterdir() if d.is_dir()]
    
    # Initialize counters
    skipped_count = 0
    processed_count = 0
    
    # Process CVEs with progress bar
    with tqdm(total=len(cve_dirs), desc="Processing CVEs", unit="cve") as pbar:
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            
            if cve_id not in target_cves:
                logger.warning(f"Found directory for non-target CVE: {cve_id}")
                pbar.update(1)
                continue
                
            if crawler.is_cve_processed(cve_id):
                skipped_count += 1
                pbar.set_postfix({"skipped": skipped_count, "processed": processed_count})
                pbar.update(1)
                continue
                
            logger.info(f"Processing URLs for {cve_id}")
            crawler.process_cve_urls(cve_id)
            processed_count += 1
            pbar.set_postfix({"skipped": skipped_count, "processed": processed_count})
            pbar.update(1)
    
    logger.info(
        f"Completed CVE reference processing:\n"
        f"  - CVEs skipped (already processed): {skipped_count}\n"
        f"  - CVEs processed: {processed_count}\n"
        f"  - Total CVEs handled: {skipped_count + processed_count}"
    )

if __name__ == "__main__":
    main()