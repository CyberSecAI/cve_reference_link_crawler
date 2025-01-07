# CVE Reference Link Crawler

A Python-based tool to extract, download, and process CVE reference content from the National Vulnerability Database (NVD). 

This tool focuses on specific CVEs from a target list, downloads their reference content, and converts it to a standardized text format.

The links are in, e.g. for CVE-2022-31516:
- "References to Advisories, Solutions, and Tools" on https://nvd.nist.gov/vuln/detail/CVE-2022-31516
- "references" section of nvd.json for CVE-2022-31516
```json
   "cve": {
      "id": "CVE-2022-31516",
      .....
      "references": [
        {
          "url": "https://github.com/github/securitylab/issues/669#issuecomment-1117265726"
````

## Overview

This tool:
1. Loads target CVEs from a CSV file
   - TARGET_CVES_CSV in config.py is set to top25-mitre-mapping-analysis-2023-public.csv as the list of CVEs to get the references content for.
2. Processes only the specified CVEs from the NVD JSON data
3. Downloads and archives reference content for these CVEs
4. Converts various file formats to text using MarkItDown
5. Creates a structured archive of both raw and processed content

## Content Processing Workflow

### Two-Phase Processing
The tool processes content in two phases to ensure comprehensive coverage:

1. Initial Phase:
   - Processes all direct URLs from the CVE data
   - Creates CVE directories with raw and text content

2. Secondary Phase:
   - Scans generated text files for additional CVE-specific URLs
   - Downloads and processes these secondary URLs
   - Maintains the same directory structure for consistency

This two-phase approach is particularly important because relevant vulnerability information is often not in the directly linked document. For example:
- https://nvd.nist.gov/vuln/detail/CVE-2021-0955 links to
  - https://source.android.com/docs/security/bulletin/2021-12-01 (a bulletin with multiple CVEs)
    - Which contains the actual fix: https://android.googlesource.com/platform/packages/providers/MediaProvider/+/e81d03db8006fddf6e7c8a8eda1b73743314a214

### Content Conversion
The tool uses multiple methods to convert content to readable text:

1. Primary Method: MarkItDown
   - Handles multiple formats: PDF, Images (with OCR), HTML, CSV, JSON, XML
   - Provides consistent output format

2. Fallback Methods:
   - PyPDF2 for PDFs that fail with MarkItDown
   - Custom handlers for specific sources

### URL Handlers

The tool includes specialized handlers for specific sources:

1. Google Source Handler
   - Transforms URLs for raw content access
   - Decodes base64-encoded responses
   - Formats commit information:
     ```
     Original: .../MediaProvider/+/e81d03db8006fddf6e7c8a8eda1b73743314a214
     Handled: .../MediaProvider/+/e81d03db8006fddf6e7c8a8eda1b73743214?format=TEXT
     ```

2. CISA URL Handler
   - Handles post-February 2023 website reorganization
   - Automatically redirects old URLs:
     ```
     Old: www.cisa.gov/uscert/ics/advisories/icsa-22-179-02
     New: www.cisa.gov/news-events/ics-advisories/icsa-22-179-02
     ```

### URL Filtering
The tool maintains a configurable ignore list for:
1. Known dead domains:
   - www.securitytracker.com (defunct)
2. Circular references:
   - www.cve.org (links back to NVD)
3. Problematic sources:
   - Sites requiring authentication
   - Rate-limited APIs
   - JavaScript-dependent content

Configure ignored URLs in config.py:
```python
IGNORED_URLS = [
    "www.cve.org",
    "securitytracker.com",
    # Add more as needed
]
```

## Project Structure

```
project_root/
├── cve_reference_link_crawler/
│   ├── src/
│   │   ├── config.py          # Configuration settings
│   │   ├── main.py            # Main entry point
│   │   └── cve_ref_crawler/   
│   │       ├── handlers/      # URL handlers
│   │       │   ├── googlesource.py
│   │       │   └── cisa.py
│   │       └── utils/         # Utility functions
│   ├── logs/                  # Processing logs
│   ├── data_in/              
│   │   └── nvd.jsonl          # NVD JSON data
│   └── data_out/              # Output directory
│       └── CVE-YYYY-XXXXX/    # Per-CVE directories
└── cwe_top25/                 # External CVE list
    └── data_in/
        └── top25-mitre-mapping-analysis-2023-public.csv 
```

## Output Structure

For each CVE, the tool creates:
```
data_out/
└── CVE-YYYY-XXXXX/
    ├── links.txt              # URLs from CVE references
    ├── raw/                   # Original content
    │   ├── site1_hash_timestamp.html
    │   └── site2_hash_timestamp.pdf
    └── text/                  # Converted content
        ├── site1_hash_timestamp.md
        └── site2_hash_timestamp.md
```

### Example: CVE-2021-3675

This example demonstrates typical processing outcomes:

1. Initial Links (from links.txt):
   ```
   https://support.hp.com/us-en/document/ish_6411153-6411191-16/hpsbhf03797
   https://support.lenovo.com/us/en/product_security/LEN-68054
   https://synaptics.com/.../fingerprint-driver-SGX-security-brief-2022-06-14.pdf
   ```

2. Processing Results:
   - First two links failed (common for vendor-specific pages)
   - PDF successfully processed and converted to text
   - Demonstrates both successful and failed crawling scenarios

## Prerequisites

1. Python 3.8+
2. Git
3. NVD data (from http://nvd.handsonhacking.org/nvd.jsonl)
4. MarkItDown (Microsoft's document conversion utility)

## Installation

1. Setup Repository:
   ```bash
   # Clone repositories
   git clone https://github.com/CyberSecAI/cwe_top25
   git clone [this-repository-url]
   cd [this-repository-url]

   # Create required directories
   mkdir -p data_in data_out logs
   ```

2. Create Python Environment:
   ```bash
   python -m venv env
   source env/bin/activate  # Windows: env\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configure:
   - Copy NVD data to data_in/nvd.jsonl
   - Review and modify config.py settings

## Configuration

config.py settings:
```python
# Directories
DATA_IN_DIR = Path("data_in")
DATA_OUT_DIR = Path("data_out")
LOG_DIR = Path("logs")

# Crawler behavior
CRAWLER_SETTINGS = {
    "timeout": 30,
    "retry_count": 3,
    "delay": 1,  # seconds between requests
}

# Logging
LOG_CONFIG = {
    "level": logging.INFO,
    "format": "%(asctime)s - %(levelname)s - %(message)s"
}
```

## Error Handling

1. Logs Directory:
   - Located in data_out/logs/
   - Contains timestamped log files
   - Includes both success and error information

2. Common Errors:
   - Authentication Required (e.g., HackerOne)
   - JavaScript-dependent content (e.g., Dell advisories)
   - Rate limiting (e.g., Qualcomm bulletins)
   - Domain-specific issues (e.g., Secomea content)

3. Error Resolution:
   - Check logs/crawler_YYYYMMDD_HHMMSS.log
   - Consider adding problematic domains to IGNORED_URLS
   - Review timeout and retry settings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Areas for Improvement

1. Content Processing:
   - Add Markdown extension to text files
   - Extract vulnerability-specific information
   - Support for additional document formats

2. Structure:
   - Consider CVEProject/cvelistV5-style organization
   - Improve handling of large files

3. Crawler Enhancement:
   - Add GitHub pull request diff support
   - Improve vendor-specific page handling
   - Add archive.org or Google cache fallback for dead links
   - robots.txt support

## License

This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.
https://creativecommons.org/licenses/by-sa/4.0/

## Notes



### Only the Vulnerability-related info 
It is possible to extract and summarize only the Vulnerability-related info e.g. using an LLM:

**ChatGPT 4o Output**

**Extracted Vulnerability Information for CVE-2021-0955:**

- **CVE ID**: CVE-2021-0955  
- **Component Affected**: Android Framework  
- **Type of Vulnerability**: Elevation of Privilege (EoP)  
- **Severity**: High  
- **Updated AOSP Versions**: Android 11  
- **References**:  
  [AOSP Change](https://android.googlesource.com/platform/packages/providers/MediaProvider/%2B/e81d03db8006fddf6e7c8a8eda1b73743314a214)  
  Bug ID: A-192085766  

#### **Details:**
CVE-2021-0955 is an elevation of privilege vulnerability in the Android Framework. The issue allows a local attacker to potentially execute actions with elevated privileges. The attack does not require user interaction or specific privileges.

The vulnerability occurs due to a race condition in the `FuseDaemon` class. It involves the improper management of file handles during the `fuse_reply_write` process, leading to a use-after-free scenario. The issue is addressed by ensuring proper sequence ordering, specifically by recording operations before invoking `fuse_reply_write`.

The fix for this vulnerability is available in the Android Open Source Project (AOSP) and applies to devices running Android 11.





### Large Files
1. A git pre-commit hook is setup to prevent files greater than 20MB being committed: .pre-commit-config.yaml
2. A bash script can be run manually to move big files to tmp/big_files: big_files.sh

### Document to Text tools
[MarkItDown](https://github.com/microsoft/markitdown) is used here.
- [Docling](https://github.com/DS4SD/docling) is an alternative.

### Archive Sources
The following archive sources were considered but not implemented due to limited content availability:
- Google Cache (e.g., https://webcache.googleusercontent.com/search?q=cache:...)
- Wayback Machine

### Links that were not successfully crawled

The log file indicates what links failed to download.

1. GitHub pulls could add 'files' to get the file diff content e.g. https://github.com/haiwen/seafile-server/pull/520 -> https://github.com/haiwen/seafile-server/pull/520/files
2. Cisa.gov content is not retrieved e.g. https://www.cisa.gov/uscert/ics/advisories/icsa-22-181-03
3. HackerOne requires human verification, and signin e.g. https://hackerone.com/reports/1256967
4. Dell advisories content is not retrieved e.g. https://www.dell.com/support/kbdoc/en-us/000198780/dsa-2022-102
5. secomea content is not retrieved https://secomea.com/cybersecurity-advisory/
6. Qualcomm content is retrieved as blank e.g. https://www.qualcomm.com/company/product-security/bulletins/november-2022-bulletin 


### ToDos
1. Add .md to text files.
1. Extract only the vulnerability-related info from `text` dir (to markdown) e.g.
   1. data_out/CVE-2021-21773/refined/refined.txt for prompts/extract_vulnerability_info.txt (using Claude Sonnet 3.5, or ChatGPT o1. Gemini any model output was too short)
   2. data_out/CVE-2021-21773/refined/refined_long.txt for prompts/extract_vulnerability_info_long.txt
2. If this is done for all published CVEs, then a directory structure per https://github.com/CVEProject/cvelistV5/tree/main/cves would be more appropriate to avoid having all CVEs in one directory.



