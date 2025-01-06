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
   1. TARGET_CVES_CSV in config.py is set to top25-mitre-mapping-analysis-2023-public.csv as the list of CVEs to get the references content for.
2. Processes only the specified CVEs from the NVD JSON data
3. Downloads and archives reference content for these CVEs
4. Converts various file formats to text using MarkItDown
5. Creates a structured archive of both raw and processed content


## License

> [!NOTE]  
>This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.
> - https://creativecommons.org/licenses/by-sa/4.0/


## Project Structure

```
project_root/
├── cve_reference_link_crawler/
│   ├── src/
│   │   ├── config.py          # Configuration settings
│   │   ├── main.py            # Main entry point
│   │   └── cve_ref_crawler/   # Core functionality
│   ├── data_in/               # Input data directory
│   │   └── nvd.jsonl          # NVD JSON data. 
│   └── data_out/              # Output directory
└── cwe_top25/                 # External CVE list
    └── data_in/
        └── top25-mitre-mapping-analysis-2023-public.csv 
```


## Output Structure

For each processed CVE, the tool creates the following structure:

```
data_out/
└── CVE-123-12345/
    ├── links.txt # URLs from the CVE references section
    ├── raw/                   # Original downloaded content
    │   └── downloaded_content.html
    └── text/                  # Converted text content; converted by MarkItDown
        └── converted_content.html
```

### Example

https://github.com/CyberSecAI/cve_reference_link_crawler/tree/main/data_out/CVE-2021-3675

**Links**


Per https://nvd.nist.gov/vuln/detail/cve-2021-3675, there are 3 unique reference links for CVE-2021-3675:

https://github.com/CyberSecAI/cve_reference_link_crawler/blob/main/data_out/CVE-2021-3675/links.txt
````
https://support.hp.com/us-en/document/ish_6411153-6411191-16/hpsbhf03797
https://support.lenovo.com/us/en/product_security/LEN-68054
https://synaptics.com/sites/default/files/2022-06/fingerprint-driver-SGX-security-brief-2022-06-14.pdf
````
**Raw Content**

https://github.com/CyberSecAI/cve_reference_link_crawler/tree/main/data_out/CVE-2021-3675/raw contains a pdf only indicating that the first 2 links were not crawled successfully.

**Text Content**

https://github.com/CyberSecAI/cve_reference_link_crawler/blob/main/data_out/CVE-2021-3675/text/synaptics.com_1046f482_20250105_231134.html contains the text extracted from the PDF.

## Prerequisites

1. Python 3.8+
2. Git
3. NVD data in JSON format
4. [MarkItDown](https://github.com/microsoft/markitdown) utility; a utility for converting various files to Markdown (e.g., for indexing, text analysis, etc). It supports: PDF, Images (EXIF metadata and OCR), HTML, Text-based formats (CSV, JSON, XML), ...

## Installation

1. Clone the repository:
```bash
git clone https://github.com/CyberSecAI/cwe_top25 # Using Top25 as the target list of CVEs

git clone [repository-url]
cd [repository-url]


```

2. Create and activate a virtual environment:
```bash
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Download NVD data:
- For now from http://nvd.handsonhacking.org/nvd.jsonl. 
  - Will be superseded by https://github.com/CyberSecAI/cve_source_of_truth
- Place the NVD JSON data in `data_in/nvd.jsonl`

## Configuration

Edit `src/config.py` to configure:
- Input/output directories
- URLs to ignore during crawling
- Logging settings
- Crawler behavior (timeouts, retries, etc.)

## Usage

1. Ensure your target CVE list is in the correct location (see Project Structure)
2. Run the tool:
```bash
python src/main.py
```

## Features

### Content Processing
- Downloads reference content from URLs in CVE data
- Handles both HTML and PDF content
- Converts various file formats to text using MarkItDown.
  - Some PDFs fail with MarkItDown so fall back to PyPDF2 if MarkItDown fails
- Preserves both raw and processed content

### URL Filtering
- Configurable URL ignore list
- Skips known problematic or inaccessible domains
- Currently ignored domains include:
  - www.cve.org as this is just a link back to www.cve.org from NVD.
  - www.securitytracker.com as this domain no longer exists. 
  - Lots more link rot... 

### Selective Processing
- Processes only CVEs from the target list
- Skips irrelevant CVEs from NVD data
- Creates organized directory structure for each processed CVE

### Logging
- Detailed logging of all operations
- Progress tracking and statistics
- Error handling and reporting

## Notes

### Levels of link following
The tool only reads documents linked from the CVE; it does not follow links from linked docs i.e. not recursive.
In some cases, the relevant vulnerability information is not in the linked document e.g.
- https://nvd.nist.gov/vuln/detail/CVE-2021-0955 contains 1 link (next line)
  - https://source.android.com/docs/security/bulletin/2021-12-01 (a bulletin that contains links for several CVEs)
    - https://android.googlesource.com/platform/packages/providers/MediaProvider/+/e81d03db8006fddf6e7c8a8eda1b73743314a214 is the link for CVE-2021-0955 that has the relevant info


As part of the refinement of the text to extract only the vulnerability information, an LLM could be prompted to follow the relevant link for a CVE e.g. ChatGPT 4o is provided with
1. Content of https://source.android.com/docs/security/bulletin/2021-12-01 
2. Prompt per [prompts/extract_vulnerability_info_follow_links.md](./prompts/extract_vulnerability_info_follow_links.md)

#### ChatGPT 4o Output

**Extracted Vulnerability Information for CVE-2021-0955:**

- **CVE ID**: CVE-2021-0955  
- **Component Affected**: Android Framework  
- **Type of Vulnerability**: Elevation of Privilege (EoP)  
- **Severity**: High  
- **Updated AOSP Versions**: Android 11  
- **References**:  
  [AOSP Change](https://android.googlesource.com/platform/packages/providers/MediaProvider/%2B/e81d03db8006fddf6e7c8a8eda1b73743314a214)  
  Bug ID: A-192085766  

### **Details:**
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



