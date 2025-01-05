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
├── cve_single_source_of_truth/
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
- Converts various file formats to text using MarkItDown
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




