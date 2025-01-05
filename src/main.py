# src/main.py
from cve_ref_crawler import CVEProcessor, ContentCrawler
from cve_ref_crawler.utils.logging_utils import setup_logging
from config import NVD_JSONL_FILE, DATA_OUT_DIR

def main():
    logger = setup_logging(module_name="main")
    logger.info("Starting CVE reference processing")
    
    # Initialize and run CVE processor
    logger.info("Initializing CVE processor")
    processor = CVEProcessor(
        input_file=NVD_JSONL_FILE,
        output_dir=DATA_OUT_DIR
    )
    processor.process_file()
    
    # Initialize and run content crawler
    logger.info("Initializing content crawler")
    crawler = ContentCrawler(output_dir=DATA_OUT_DIR)
    
    # Process each CVE directory
    for cve_dir in DATA_OUT_DIR.iterdir():
        if cve_dir.is_dir():
            cve_id = cve_dir.name
            logger.info(f"Processing URLs for {cve_id}")
            crawler.process_cve_urls(cve_id)
    
    logger.info("Completed CVE reference processing")

if __name__ == "__main__":
    main()