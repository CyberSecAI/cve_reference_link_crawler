# src/main.py

from cve_ref_crawler import CVEProcessor, ContentCrawler
from cve_ref_crawler.utils.cve_filter import load_target_cves
from cve_ref_crawler.utils.logging_utils import setup_logging
from config import (
    NVD_JSONL_FILE,
    DATA_OUT_DIR,
    LOG_CONFIG,
    TARGET_CVES_CSV
)

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
    
    # Initialize and run CVE processor with target CVEs
    logger.info("Initializing CVE processor")
    processor = CVEProcessor(
        input_file=NVD_JSONL_FILE,
        output_dir=DATA_OUT_DIR,
        target_cves=target_cves
    )
    processor.process_file()
    
    # Initialize and run content crawler
    logger.info("Initializing content crawler")
    crawler = ContentCrawler(output_dir=DATA_OUT_DIR)
    
    # Process each CVE directory
    for cve_dir in DATA_OUT_DIR.iterdir():
        if cve_dir.is_dir():
            cve_id = cve_dir.name
            if cve_id in target_cves:
                logger.info(f"Processing URLs for {cve_id}")
                crawler.process_cve_urls(cve_id)
            else:
                logger.warning(f"Found directory for non-target CVE: {cve_id}")
    
    logger.info("Completed CVE reference processing")

if __name__ == "__main__":
    main()