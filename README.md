# Huntr Vulnerability Report Scraper

Scrape **valid** Huntr bounty reports (severity: `critical|high|medium|low`) from one or many repository pages, filter out noise (informative/duplicate/spam/etc.), and write **one JSON file per repo** to a dedicated `reports/` folder:

```
reports/
triton-server.json
llama_index.json
another-repo.json
```


---

## Features

- **Multi-URL intake**
  - Positional repo URLs
  - `--urls-file` for bulk lists (supports `-` to read from **stdin**)
- **Noise filtering**
  - Excludes: informative, duplicate, spam, not applicable, false positive, etc.
  - Includes: only `critical|high|medium|low`
- **Selenium or requests**
  - Defaults to Selenium for JS-heavy pages; can run requests-only (`--no-selenium`)
- **Randomized delays**
  - Avoids hammering the site (configurable with `--delay MIN MAX`)
- **Per-repo JSON output**
  - One file per repo in `reports/`, filename based on repo name (e.g., `triton-server.json`)

---

## Installation

Requirements
  - Python 3.9+
  - pip install -r requirements.txt
    - requests, beautifulsoup4, selenium

  - Selenium mode:
    - Chrome (or Chromium) installed
    - Selenium Manager (bundled with Selenium 4.6+) will auto-manage the driver in most cases.
    - Use --no-selenium to avoid browser automation.

## Quick Start

```bash
# 1) Create and activate a venv (recommended)
python3 -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run against a repo
python scraper.py https://huntr.com/repos/nvidia/triton-server
# -> writes reports/triton-server.json
```

To disable Selenium (requests only):
```bash
python scraper.py https://huntr.com/repos/orgs/repo --no-selenium
```

## CLI

```bash
usage: scraper.py [-h] [--urls-file URLS_FILE] [--output OUTPUT]
                  [--max-reports MAX_REPORTS] [--no-selenium] [--no-headless]
                  [--delay MIN MAX] [--no-verify] [--verbose]
                  [repo_urls ...]

Huntr Scraper (multi-URL) → writes one JSON per repo into 'reports/' named by repo (e.g., triton-server.json)

positional arguments:
  repo_urls             One or more Huntr repository URLs to scrape

options:
  -h, --help            Show this help message and exit
  --urls-file URLS_FILE Text file of repo URLs (one per line). Use '-' to read from stdin.
  --output OUTPUT, -o OUTPUT
                        Output directory (default: ./reports)
  --max-reports MAX_REPORTS
                        Maximum number of reports to scrape per repo
  --no-selenium         Disable Selenium (requests only)
  --no-headless         Run browser in visible mode
  --delay MIN MAX       Delay range between requests in seconds (default: 1.0 3.0)
  --no-verify           Skip quick status verification (faster)
  --verbose, -v         Verbose logging
```

### Single repo
```bash
python scraper.py https://huntr.com/repos/orgs/repo
```

### Multiple repos (positional)
```bash
python scraper.py \
  https://huntr.com/repos/orgs/repo1 \
  https://huntr.com/repos/orgs/repo2
```

### From a file
```bash
# urls.txt
https://huntr.com/repos/orgs/repo1
https://huntr.com/repos/orgs/repo2

python scraper.py --urls-file urls.txt
```

### Faster requests-only + smaller delays
```bash
python scraper.py https://huntr.com/repos/orgs/repo \
  --no-selenium --delay 0.5 1.0 --no-verify
```

# Output Format
Each repo produces a single JSON:
```json
{
  "metadata": {
    "total_reports": 3,
    "scraping_timestamp": "2025-08-21 16:12:34",
    "filtering_criteria": {
      "included_severities": ["critical", "high", "medium", "low"],
      "excluded_statuses": ["not applicable", "spam", "duplicate", "..."]
    },
    "severity_breakdown": {
      "High": 2,
      "Medium": 1
    },
    "vulnerability_types": {
      "SQL Injection": 1,
      "Cross-Site Scripting": 1,
      "Unknown": 1
    }
  },
  "reports": [
    {
      "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "title": "SQL Injection in ...",
      "severity": "High",
      "status": "triaged",
      "description": "…",
      "proof_of_concept": "…",
      "impact": "…",
      "affected_files": ["src/db/query.py", "…"],
      "vulnerability_type": "SQL Injection",
      "cve_id": null,
      "bounty_amount": "$500",
      "researcher": "alice",
      "url": "https://huntr.com/bounties/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "scraped_at": "2025-08-21 16:12:34"
    }
  ]
}
```  
