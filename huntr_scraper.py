#!/usr/bin/env python3
"""
Huntr Vulnerability Report Scraper - Multi-URL w/ flat JSON outputs
- Writes ONE JSON file per repo into a dedicated 'reports/' folder
- File name is the repo name, e.g. triton-server.json
"""

import os
import re
import sys
import json
import time
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, asdict
import hashlib
import random

# Web scraping dependencies
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityReport:
    id: str
    title: str
    severity: str
    status: str
    description: str
    proof_of_concept: str
    impact: str
    affected_files: List[str]
    vulnerability_type: str
    cve_id: Optional[str]
    bounty_amount: Optional[str]
    researcher: Optional[str]
    url: str
    scraped_at: str

class HuntrScraper:
    def __init__(self, use_selenium=True, headless=True, delay_range=(1, 3)):
        self.use_selenium = use_selenium
        self.headless = headless
        self.delay_range = delay_range
        self.session = requests.Session()

        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        self.driver = None
        if self.use_selenium:
            self._setup_selenium()

        self.processed_urls: Set[str] = set()

        self.excluded_statuses = {
            'not applicable', 'spam', 'duplicate', 'informative',
            'self closed', 'invalid', 'won\'t fix', 'false positive',
            'wontfix', 'notapplicable', 'selfclosed', 'falsepositive',
            'not-applicable', 'self-closed', 'won-t-fix', 'false-positive',
            'rejected', 'closed', 'dismissed'
        }
        self.valid_severities = {'critical', 'high', 'medium', 'low'}

        self.excluded_status_pattern = re.compile('|'.join(re.escape(s) for s in self.excluded_statuses), re.IGNORECASE)
        self.severity_pattern = re.compile(r'\b(' + '|'.join(self.valid_severities) + r')\b', re.IGNORECASE)

    def _setup_selenium(self):
        try:
            chrome_options = Options()
            if self.headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument(f'--user-agent={random.choice(self.user_agents)}')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)

            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            logger.info("Selenium WebDriver initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize Selenium: {e}")
            logger.info("Falling back to requests-only mode")
            self.use_selenium = False

    def _random_delay(self):
        time.sleep(random.uniform(*self.delay_range))

    def _get_page_content(self, url: str, use_selenium: bool = None) -> Optional[BeautifulSoup]:
        use_selenium = use_selenium if use_selenium is not None else self.use_selenium
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if use_selenium and self.driver:
                    self.driver.get(url)
                    WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                    time.sleep(2)
                    html = self.driver.page_source
                else:
                    self.session.headers['User-Agent'] = random.choice(self.user_agents)
                    self._random_delay()
                    resp = self.session.get(url, timeout=30)
                    resp.raise_for_status()
                    html = resp.text
                return BeautifulSoup(html, 'html.parser')
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt == max_retries - 1:
                    logger.error(f"Failed to fetch {url} after {max_retries} attempts")
                    return None
                time.sleep(2 ** attempt)
        return None

    def _extract_huntr_report_data(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        reports = []
        report_containers = soup.find_all(['div', 'article', 'section'], class_=re.compile(r'(report|bounty|vulnerability|card)', re.I))
        for c in report_containers:
            parsed = self._parse_report_container(c)
            if parsed:
                reports.append(parsed)

        bounty_links = soup.find_all('a', href=re.compile(r'/bounties/[a-f0-9-]{36}'))
        for link in bounty_links:
            href = link.get('href')
            if not href:
                continue
            full = urljoin('https://huntr.com', href)
            ctx = ""
            for parent in [link.parent, link.parent.parent if link.parent else None]:
                if parent:
                    ctx += " " + parent.get_text()
            if link.parent:
                for sib in link.parent.find_all(['span', 'div', 'p']):
                    ctx += " " + sib.get_text()
            ctx = ctx.lower()
            bad = bool(self.excluded_status_pattern.search(ctx))
            sev_match = self.severity_pattern.search(ctx)
            title = link.get_text(strip=True) or (link.parent.get_text(strip=True)[:100] if link.parent else "")
            reports.append({
                'url': full,
                'title': title,
                'severity': sev_match.group(1).lower() if sev_match else 'unknown',
                'status': 'excluded' if bad else 'unknown',
                'should_scrape': bool(sev_match) and not bad,
                'context': ctx[:200]
            })
        return reports

    def _parse_report_container(self, container) -> Optional[Dict[str, str]]:
        try:
            a = container.find('a', href=re.compile(r'/bounties/[a-f0-9-]{36}'))
            if not a:
                return None
            url = urljoin('https://huntr.com', a.get('href'))
            txt = container.get_text().lower()
            bad = bool(self.excluded_status_pattern.search(txt))
            sev = self.severity_pattern.search(txt)
            title_elem = container.find(['h1','h2','h3','h4','h5','h6']) or a
            title = title_elem.get_text(strip=True) if title_elem else "Unknown"
            return {
                'url': url,
                'title': title,
                'severity': sev.group(1).lower() if sev else 'unknown',
                'status': 'excluded' if bad else 'unknown',
                'should_scrape': bool(sev) and not bad,
                'context': txt[:200],
            }
        except Exception as e:
            logger.debug(f"Error parsing container: {e}")
            return None

    def extract_valid_bounty_links(self, repo_url: str, verify_status: bool = True) -> List[str]:
        logger.info(f"Extracting valid bounty links from {repo_url}")
        soup = self._get_page_content(repo_url)
        if not soup:
            return []
        all_reports = self._extract_huntr_report_data(soup)
        valid = [r['url'] for r in all_reports if r.get('should_scrape')]
        valid = list(dict.fromkeys(valid))
        if verify_status and valid and len(valid) <= 20:
            checked = []
            for url in valid[:10]:
                if self._quick_verify_report(url):
                    checked.append(url)
                time.sleep(1)
            return checked
        return valid

    def _quick_verify_report(self, bounty_url: str) -> bool:
        try:
            resp = self.session.get(bounty_url, timeout=10)
            if resp.status_code != 200:
                return False
            soup = BeautifulSoup(resp.text, 'html.parser')
            txt = soup.get_text().lower()
            if self.excluded_status_pattern.search(txt):
                return False
            if self.severity_pattern.search(txt):
                return True
            return True
        except Exception:
            return True

    def extract_report_details(self, bounty_url: str) -> Optional[VulnerabilityReport]:
        if bounty_url in self.processed_urls:
            return None
        self.processed_urls.add(bounty_url)
        soup = self._get_page_content(bounty_url)
        if not soup:
            return None
        try:
            rid = bounty_url.split('/')[-1]
            title = self._extract_title(soup)
            severity = self._extract_severity(soup)
            status = self._extract_status(soup)
            if any(ex in status.lower().replace(' ', '').replace('-', '') for ex in [s.replace(' ', '').replace('-', '') for s in self.excluded_statuses]):
                return None
            description = self._extract_description(soup)
            poc = self._extract_proof_of_concept(soup)
            impact = self._extract_impact(soup)
            files = self._extract_affected_files(soup)
            vtype = self._extract_vulnerability_type(soup, title, description, poc)
            cve_id = self._extract_cve_id(soup)
            bounty = self._extract_bounty_amount(soup)
            researcher = self._extract_researcher(soup)
            return VulnerabilityReport(
                id=rid, title=title, severity=severity, status=status,
                description=description[:1500], proof_of_concept=poc[:1000],
                impact=impact[:500], affected_files=list(set(files))[:10],
                vulnerability_type=vtype, cve_id=cve_id, bounty_amount=bounty,
                researcher=researcher, url=bounty_url, scraped_at=time.strftime('%Y-%m-%d %H:%M:%S')
            )
        except Exception as e:
            logger.error(f"Failed to extract report details from {bounty_url}: {e}")
            return None

    def _extract_title(self, soup: BeautifulSoup) -> str:
        for sel in ['h1','h2.title','.title','[class*="title"]','title']:
            el = soup.select_one(sel)
            if el:
                t = el.get_text(strip=True)
                if t and len(t) > 10:
                    return t
        return "Unknown Vulnerability"

    def _extract_severity(self, soup: BeautifulSoup) -> str:
        for sel in ['[class*="severity"]','[class*="badge"]','[class*="label"]','.tag','[data-severity]']:
            for el in soup.select(sel):
                text = el.get_text(strip=True).lower()
                if any(s in text for s in self.valid_severities):
                    for s in self.valid_severities:
                        if s in text:
                            return s.capitalize()
        m = self.severity_pattern.search(soup.get_text().lower())
        return m.group(1).capitalize() if m else "Unknown"

    def _extract_status(self, soup: BeautifulSoup) -> str:
        for sel in ['[class*="status"]','[class*="state"]','[data-status]']:
            el = soup.select_one(sel)
            if el:
                return el.get_text(strip=True)
        txt = soup.get_text()
        for pat in [r'status:\s*([^\n\r]+)', r'state:\s*([^\n\r]+)']:
            m = re.search(pat, txt, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return "unknown"

    def _extract_description(self, soup: BeautifulSoup) -> str:
        for sel in ['[class*="description"]','[class*="summary"]','[class*="details"]','.content','article','main']:
            el = soup.select_one(sel)
            if el:
                for bad in el.find_all(['nav','header','footer','aside','script','style']):
                    bad.decompose()
                desc = el.get_text(separator='\n', strip=True)
                if len(desc) > 50:
                    return desc[:1500]
        return ""

    def _extract_proof_of_concept(self, soup: BeautifulSoup) -> str:
        for kw in ['proof of concept','poc','exploit','reproduction','steps to reproduce','reproduce']:
            t = soup.find(text=re.compile(kw, re.IGNORECASE))
            if t:
                parent = t.find_parent(['div','section','article','p','pre','code'])
                if parent:
                    s = parent.get_text(separator='\n', strip=True)
                    if len(s) > 20:
                        return s[:1000]
        for block in soup.find_all(['pre','code']):
            s = block.get_text(strip=True)
            if len(s) > 50:
                return s[:1000]
        return ""

    def _extract_impact(self, soup: BeautifulSoup) -> str:
        for kw in ['impact','risk','consequence','damage','effect']:
            t = soup.find(text=re.compile(kw, re.IGNORECASE))
            if t:
                p = t.find_parent(['div','section','article','p'])
                if p:
                    s = p.get_text(separator='\n', strip=True)
                    if len(s) > 10:
                        return s[:500]
        return ""

    def _extract_affected_files(self, soup: BeautifulSoup) -> List[str]:
        files = []
        for block in soup.find_all(['code','pre']):
            text = block.get_text(strip=True)
            files.extend(re.findall(r'[\w/\\.-]+\.(py|java|php|js|jsx|ts|tsx|rb|go|c|cpp|cs|jsp|asp|aspx|html|css|json|xml|yml|yaml)', text))
        page = soup.get_text()
        files.extend(re.findall(r'(?:file|path):\s*([\w/\\.-]+\.\w+)', page, re.IGNORECASE))
        return list(set(files))[:10]

    def _extract_vulnerability_type(self, soup: BeautifulSoup, title: str, description: str, poc: str) -> str:
        mapping = {
            'sql injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'cross-site scripting': 'Cross-Site Scripting',
            'csrf': 'Cross-Site Request Forgery',
            'cross-site request forgery': 'Cross-Site Request Forgery',
            'rce': 'Remote Code Execution',
            'remote code execution': 'Remote Code Execution',
            'lfi': 'Local File Inclusion',
            'local file inclusion': 'Local File Inclusion',
            'rfi': 'Remote File Inclusion',
            'remote file inclusion': 'Remote File Inclusion',
            'path traversal': 'Path Traversal',
            'directory traversal': 'Path Traversal',
            'ssrf': 'Server-Side Request Forgery',
            'server-side request forgery': 'Server-Side Request Forgery',
            'xxe': 'XML External Entity',
            'xml external entity': 'XML External Entity',
            'deserialization': 'Insecure Deserialization',
            'authentication bypass': 'Authentication Bypass',
            'authorization': 'Authorization Flaw',
            'privilege escalation': 'Privilege Escalation',
            'buffer overflow': 'Buffer Overflow',
            'injection': 'Injection',
            'open redirect': 'Open Redirect',
            'information disclosure': 'Information Disclosure',
            'denial of service': 'Denial of Service',
            'dos': 'Denial of Service'
        }
        text = (title + " " + description + " " + poc).lower()
        for k, v in mapping.items():
            if k in text:
                return v
        return "Unknown"

    def _extract_cve_id(self, soup: BeautifulSoup) -> Optional[str]:
        m = re.search(r'CVE-\d{4}-\d{4,}', soup.get_text())
        return m.group() if m else None

    def _extract_bounty_amount(self, soup: BeautifulSoup) -> Optional[str]:
        for pat in [r'\$\d+(?:,\d{3})*(?:\.\d{2})?', r'\d+(?:,\d{3})*\s*USD', r'bounty.*?\$\d+', r'reward.*?\$\d+']:
            m = re.search(pat, soup.get_text(), re.IGNORECASE)
            if m:
                return m.group()
        return None

    def _extract_researcher(self, soup: BeautifulSoup) -> Optional[str]:
        pats = [
            r'(?:reported by|researcher|found by|discovered by|submitted by):\s*([^\n\r,]+)',
            r'(?:by|@)\s*([a-zA-Z0-9_.-]+)',
            r'researcher:\s*([^\n\r,]+)'
        ]
        txt = soup.get_text()
        for pat in pats:
            m = re.search(pat, txt, re.IGNORECASE)
            if m:
                name = m.group(1).strip()
                if 2 < len(name) < 50:
                    return name
        return None

    def scrape_repository(self, repo_url: str, max_reports: int = None, verify_status: bool = True) -> List[VulnerabilityReport]:
        logger.info(f"Scraping repository: {repo_url}")
        links = self.extract_valid_bounty_links(repo_url, verify_status=verify_status)
        if not links:
            logger.warning("No valid bounty links found")
            return []
        if max_reports:
            links = links[:max_reports]
        out: List[VulnerabilityReport] = []
        for i, url in enumerate(links, 1):
            logger.info(f"[{i}/{len(links)}] {url}")
            try:
                rep = self.extract_report_details(url)
                if rep:
                    out.append(rep)
                self._random_delay()
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error processing {url}: {e}")
        return out

    # NEW: save one JSON file named after the repo into a flat 'reports' folder
    def save_reports_as_single_json(self, reports: List[VulnerabilityReport], output_dir: str, file_stem: str):
        """
        Writes a single JSON file at {output_dir}/{file_stem}.json
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        json_path = Path(output_dir) / f"{file_stem}.json"
        payload = {
            "metadata": {
                "total_reports": len(reports),
                "scraping_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "filtering_criteria": {
                    "included_severities": list(self.valid_severities),
                    "excluded_statuses": list(self.excluded_statuses)
                },
                "severity_breakdown": self._get_severity_breakdown(reports),
                "vulnerability_types": self._get_vuln_type_breakdown(reports)
            },
            "reports": [asdict(r) for r in reports]
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(reports)} reports -> {json_path}")
        return str(json_path)

    def _get_severity_breakdown(self, reports: List[VulnerabilityReport]) -> Dict[str, int]:
        d: Dict[str,int] = {}
        for r in reports:
            d[r.severity] = d.get(r.severity, 0) + 1
        return dict(sorted(d.items()))

    def _get_vuln_type_breakdown(self, reports: List[VulnerabilityReport]) -> Dict[str, int]:
        d: Dict[str,int] = {}
        for r in reports:
            d[r.vulnerability_type] = d.get(r.vulnerability_type, 0) + 1
        return dict(sorted(d.items()))

    def close(self):
        if self.driver:
            self.driver.quit()
        self.session.close()

# ---------- helpers for URL intake & naming ----------

def is_valid_repo_url(url: str) -> bool:
    return 'huntr.com/repos/' in url

def repo_name_from_url(url: str) -> str:
    """
    Extract the FINAL segment after /repos/, used as the filename (e.g., triton-server)
    https://huntr.com/repos/nvidia/triton-server -> triton-server
    """
    try:
        path = urlparse(url).path
        if '/repos/' in path:
            tail = path.split('/repos/')[1].strip('/')
            parts = [p for p in tail.split('/') if p]
            name = parts[-1] if parts else 'repo'
        else:
            name = re.sub(r'\W+', '-', url)
        name = name.strip('-_') or 'repo'
        return name[:120]
    except Exception:
        return 'repo'

def read_urls_from_file(path: str) -> List[str]:
    if path == '-':
        src = sys.stdin.read().splitlines()
    else:
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read().splitlines()
    out: List[str] = []
    for line in src:
        s = line.strip()
        if s and not s.startswith('#'):
            out.append(s)
    return out

def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            out.append(x); seen.add(x)
    return out

# ----------------------- CLI ------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Huntr Scraper (multi-URL) → writes one JSON per repo into 'reports/' named by repo (e.g., triton-server.json)"
    )
    # CHANGED: default to 'reports' and JSON
    parser.add_argument("repo_urls", nargs="*", help="One or more Huntr repository URLs to scrape")
    parser.add_argument("--urls-file", help="Text file of repo URLs (one per line). Use '-' to read from stdin.")
    parser.add_argument("--output", "-o", default="./reports", help="Output directory (default: ./reports)")
    parser.add_argument("--max-reports", type=int, help="Maximum number of reports to scrape per repo")
    parser.add_argument("--no-selenium", action="store_true", help="Disable Selenium (requests only)")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in visible mode")
    parser.add_argument("--delay", type=float, nargs=2, default=[1.0, 3.0], help="Delay range between requests (min max)")
    parser.add_argument("--no-verify", action="store_true", help="Skip quick status verification (faster)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    urls: List[str] = []
    urls.extend(args.repo_urls or [])
    if args.urls_file:
        try:
            urls.extend(read_urls_from_file(args.urls_file))
        except Exception as e:
            logger.error(f"Failed to read --urls-file: {e}")
            return 1

    if not urls:
        logger.error("No repository URLs provided. Add positional URLs or --urls-file.")
        return 1

    urls = dedupe_preserve_order([u.strip() for u in urls if u.strip()])
    bad = [u for u in urls if not is_valid_repo_url(u)]
    for u in bad:
        logger.error(f"Invalid Huntr repo URL (skipping): {u}")
    urls = [u for u in urls if is_valid_repo_url(u)]
    if not urls:
        logger.error("No valid Huntr repository URLs to process.")
        return 1

    logger.info(f"Total repos: {len(urls)}")
    scraper = HuntrScraper(
        use_selenium=not args.no_selenium,
        headless=not args.no_headless,
        delay_range=tuple(args.delay)
    )

    total = 0
    try:
        for repo_url in urls:
            repo_name = repo_name_from_url(repo_url)  # NEW
            logger.info("#" * 60)
            logger.info(f"Repo: {repo_url}  ->  file: {repo_name}.json in {args.output}")
            logger.info("#" * 60)

            reports = scraper.scrape_repository(
                repo_url,
                max_reports=args.max_reports,
                verify_status=not args.no_verify
            )

            # Always write one JSON file per repo in the flat 'reports' dir
            out_file = scraper.save_reports_as_single_json(reports, args.output, repo_name)  # NEW

            print("\n" + "=" * 60)
            print("✓ REPO COMPLETE")
            print("=" * 60)
            print(f"Repo: {repo_url}")
            print(f"Valid vulnerability reports scraped: {len(reports)}")
            print(f"Saved: {out_file}")
            total += len(reports)

        print("\n" + "=" * 60)
        print("🏁 ALL REPOS COMPLETE")
        print("=" * 60)
        print(f"Total repos processed : {len(urls)}")
        print(f"Total reports scraped : {total}")

    except KeyboardInterrupt:
        print("\n⚠️  Interrupted")
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"\n❌ ERROR: {e}")
        return 1
    finally:
        scraper.close()

    return 0

if __name__ == "__main__":
    exit(main())
