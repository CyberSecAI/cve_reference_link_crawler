# CVE Reference Link Crawler

A Python-based tool to extract, download, and process CVE reference content from the National Vulnerability Database (NVD). 

This tool focuses on specific CVEs from a target list, downloads their reference content, and converts it to a standardized text format.

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034) has 11 unique links

https://access.redhat.com/security/vulnerabilities/RHSB-2022-001

The links are in, e.g. for CVE-2021-4034:
- "References to Advisories, Solutions, and Tools" on https://nvd.nist.gov/vuln/detail/CVE-2022-31516
- "references" section of nvd.json for CVE-2021-4034
```json
   "cve": {
      "id": "CVE-2021-4034",
      .....
      "references": [
        {
          "url": "..."
````

## Problem Space

A significant number of CVE Descriptions do not contain all the necessary vulnerability information and it is instead available in the reference links for that CVE.

However, this data is
- often no longer present i.e. dead links
- any format: from text, html, md, pdf, website,....
- unstructured
- multi-format i.e. can contain images, animated images, text,
- single or multi CVE i.e. the link can include details for many CVEs, not just the one of interest
- in different spoken languages

It would be good to have this reference content available:
1. persistently (to avoid link rot, or moved content)
2. in a single format i.e. as text only that can be read by people or machines
3. in a single language e.g. English.
4. per single CVE
5. with only the vulnerability information extracted (not page headers, footers, other CVE info,....)

### Link Rot

[Research by Jerry Gamblin](https://gist.github.com/jgamblin/93c10ce6ebc7a688d60eb2b21f8216b3) shows that (as at mid 2024) there are:
- 909,391 CVE reference links 
- ~~13% of all CVE reference links are dead.
   - **this is a best case %** as this just refers to the associated domain names that no longer exist. 
   - In other cases, the domain may be active, but the content no longer exists, or no longer exists in the original location or version of the site.

### Generic Links

Some CVE reference links are not specific e.g. https://www.forescout.com/blog/ per https://nvd.nist.gov/vuln/detail/cve-2022-31207 so the content is lost over time as new content is added.

### NVD CVE Enrichment
> Enrichment efforts begin with reviewing any reference material provided with the CVE record and assigns appropriate reference tags. This helps organize the various data sources to help researchers find the relevant information for their needs. Enrichment efforts also include manual searches of the internet to ensure that any other available and relevant information is used for the enrichment process. NVD enrichment efforts only use publicly available materials in the enrichment process.


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
The tool maintains multiple filtering mechanisms:

1. Dead Domains:
   - Loaded from data_in/dead_domains.csv if present
   - Format: CSV with Domain,count columns
   - Example entries:
     ```csv
     Domain,count
     www.securityfocus.com,82853
     osvdb.org,11271
     ```

2. robots.txt Compliance:
   - Respects robots.txt directives
   - Uses provided User-Agent for checking permissions
   - Caches robots.txt content for 1 hour to reduce requests
   - Falls back to allowing access if robots.txt cannot be fetched

3. Configurable Ignore List:
   - Known problematic domains
   - Circular references (e.g., www.cve.org)
   - Sources requiring authentication

Configure ignored URLs in config.py:
```python
IGNORED_URLS = [
    "www.cve.org",
    "cve.org",
    "first.org",
    "nist.gov",
    "www.securitytracker.com",
    "securitytracker.com",
    "exchange.xforce.ibmcloud.com"
]
```

The tool applies these filters in sequence:
- Checks against ignored URLs list
- Verifies domain is not in dead_domains.csv
- Checks robots.txt permissions before crawling



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


# Dead domains and robots.txt
- Place dead_domains.csv in data_in/ directory (optional)
- robots.txt caching duration can be modified in code (default 1 hour)
- User-Agent used for robots.txt checks is configured in CRAWLER_SETTINGS:
```python
CRAWLER_SETTINGS = {
    "headers": {
        "User-Agent": "Mozilla/5.0 ...",
        # other headers...
    }
}
```

## Usage

```
python src/main.py
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




## Notes

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

## License

This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.
https://creativecommons.org/licenses/by-sa/4.0/



## Ideas for Applying LLMs

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


### Translation

https://nvd.nist.gov/vuln/detail/cve-2022-30707 contains several reference links, 2 of which are in Japanese:
- https://web-material3.yokogawa.com/1/32780/files/YSAR-22-0006-E.pdf
- https://web-material3.yokogawa.com/19/32780/files/YSAR-22-0006-J.pdf

This text can be extracted as with all other reference content, **and then translated to English by an LLM**.

**Japanese**
```markdown
脆弱性詳細:
攻撃者が何らかの方法で同製品がインストールされたコンピューターに侵入できた場合、当該コンピュータ
ーに格納されているアカウント、パスワードを用いて、別の CAMS for HIS が管理するデータが漏洩／改ざ
んされる可能性があります。また、同アカウント、パスワードを用いて、別の CAMS for HIS に不要なファ
イルを作成するリソース枯渇攻撃がおこなわれ、最終的に CAMS for HIS の機能を停止させられる可能性が
あります。

•セキュリティ設計の原則に反した設計(CWE-657)
CVE: CVE-2022-30707
CVSS v3 基本値:6.4
CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H
````
**English**
````
Vulnerability Details:
If an attacker gains access to a computer with the affected product installed, they could use stored account credentials to:

Leak or manipulate data managed by another CAMS for HIS instance.
Perform resource depletion attacks by creating unnecessary files in another CAMS for HIS instance, potentially leading to a service outage.
Vulnerability Source:

Non-compliance with security design principles (CWE-657)
CVE: CVE-2022-30707
CVSS v3 Base Score: 6.4
Metrics: CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H
````



## ToDos
1. Add .md to text files.
1. Extract only the vulnerability-related info from `text` dir (to markdown) e.g.
   1. can be done with an LLM e.g. prompts/extract_vulnerability_info_gemini_2.0.md
2. If this is done for all published CVEs, then a directory structure per https://github.com/CVEProject/cvelistV5/tree/main/cves would be more appropriate to avoid having all CVEs in one directory.



