# CVE Single Source of Truth

A Python-based tool to extract, download, and process CVE reference content from the National Vulnerability Database (NVD). This tool focuses on specific CVEs from a target list, downloads their reference content, and converts it to a standardized text format.

## Overview

This tool:
1. Loads target CVEs from a CSV file
2. Processes only the specified CVEs from the NVD JSON data
3. Downloads and archives reference content for these CVEs
4. Converts various file formats to text using MarkItDown
5. Creates a structured archive of both raw and processed content

## Project Structure

```
project_root/
├── cve_single_source_of_truth/
│   ├── src/
│   │   ├── config.py           # Configuration settings
│   │   ├── main.py            # Main entry point
│   │   └── cve_ref_crawler/   # Core functionality
│   ├── data_in/               # Input data directory
│   │   └── nvd.jsonl          # NVD JSON data
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
    ├── raw/                   # Original downloaded content
    │   └── downloaded_content.html
    └── text/                  # Converted text content
        └── converted_content.txt
```

## Prerequisites

1. Python 3.8+
2. Git
3. NVD data in JSON format
4. [MarkItDown](https://github.com/microsoft/markitdown) utility

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd cve_single_source_of_truth
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
- Clone the CVE v5 repository or download NVD JSON data
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
  - www.cve.org
  - www.securitytracker.com

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

## Contributing

[Add contribution guidelines if applicable]

## License

[Add license information]

## Contact

[Add contact information]