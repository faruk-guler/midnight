import requests
import json
import os
import csv
import re
import xml.etree.ElementTree as ET
import concurrent.futures
import time
from datetime import datetime, timedelta, timezone
from io import StringIO

# --- Threat Intelligence Data Fetcher ---
# Global data window: all time-bounded sources use this value
DATA_WINDOW_DAYS = 15

def fetch_rss_feed(url, source_name):
    print(f"Fetching {source_name} feed...")
    threats = []
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            root = ET.fromstring(response.text)
            for item in root.findall('.//item'):
                # Safe None-check for all fields
                title_el = item.find('title')
                link_el = item.find('link')
                desc_el = item.find('description')
                pub_el = item.find('pubDate')
                title = (title_el.text or 'No Title') if title_el is not None else 'No Title'
                link = (link_el.text or '') if link_el is not None else ''
                desc = (desc_el.text or '') if desc_el is not None else ''
                pub_date = (pub_el.text or '') if pub_el is not None else ''
                
                combined = title + ' ' + desc
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', combined)
                cve_id = cve_match.group(0) if cve_match else f"{source_name}-{hash(title) % 100000}"
                
                iso_date = ""
                try:
                    parts = pub_date.split(' ')
                    if len(parts) >= 4:
                        day, month_str, year = parts[1], parts[2], parts[3]
                        months = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06","Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
                        iso_date = f"{year}-{months.get(month_str, '01')}-{day.zfill(2)}T12:00:00.000Z"
                except Exception as e:
                    print(f"  [{source_name}] Date parse error: {e}")

                # Post-filter: skip items older than DATA_WINDOW_DAYS
                if iso_date:
                    try:
                        item_date = datetime.fromisoformat(iso_date.replace('Z', '+00:00'))
                        cutoff = datetime.now(timezone.utc) - timedelta(days=DATA_WINDOW_DAYS)
                        if item_date < cutoff:
                            continue
                    except Exception as e:
                        print(f"  [{source_name}] Date filter error: {e}")

                safe_desc = desc[:200] if desc else ''
                threats.append({
                    'id': cve_id,
                    'description': f"[{source_name}] {title} | {safe_desc}...",
                    'score': 8.5,
                    'severity': "HIGH",
                    'published': iso_date or datetime.now(timezone.utc).isoformat(),
                    'lastModified': iso_date or datetime.now(timezone.utc).isoformat(),
                    'source': source_name,
                    'source_url': link,
                    'is_exploited': "exploit" in combined.lower()
                })
    except Exception as e:
        print(f"Error fetching {source_name}: {e}")
    return threats

def fetch_zdi():
    return fetch_rss_feed("https://www.zerodayinitiative.com/rss/published/", "ZDI")

def fetch_google_p0():
    return fetch_rss_feed("https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss", "GoogleP0")

def fetch_cert_cc():
    return fetch_rss_feed("https://kb.cert.org/vuls/rss", "CERT-CC")

def fetch_usom():
    """Fetch security advisories from TR-CERT via the official REST API.

    API: https://siberguvenlik.gov.tr/api/  (OpenAPI v1.1, no auth required)
    Relevant endpoints used:
      - GET /api/announcement/index  → security announcements / advisories
      - GET /api/incident/index      → cyber incident notifications

    Both endpoints support:
      - language   : 'tr' | 'en'
      - date_gte   : ISO date lower bound  (e.g. "2026-06-17")
      - date_lte   : ISO date upper bound
      - q          : free-text search
      - page       : page number (0-indexed)
    """
    print("Fetching TR-CERT advisories via official siberguvenlik.gov.tr API...")
    threats = []
    base_url = "https://siberguvenlik.gov.tr"
    headers  = {"User-Agent": "Midnight-Intelligence-Tracker/2.2", "Accept": "application/json"}
    cutoff   = datetime.now(timezone.utc) - timedelta(days=DATA_WINDOW_DAYS)
    date_gte = cutoff.strftime("%Y-%m-%d")

    # Fetch both announcement and incident feeds (no date_gte — API ignores it;
    # filter client-side instead)
    def fetch_endpoint_all(path, label):
        """Fetch pages from a TR-CERT API endpoint, filter by date client-side."""
        results = []
        page = 0
        while True:
            try:
                params = {"language": "en", "page": page}
                resp = requests.get(f"{base_url}{path}", params=params,
                                    headers=headers, timeout=15)
                if resp.status_code != 200:
                    print(f"  TR-CERT {label} API returned HTTP {resp.status_code}")
                    break
                data = resp.json()
                models = data.get("models", [])
                if not models:
                    break
                # Client-side date filter
                for m in models:
                    raw_date = m.get("date", "")[:10]  # "YYYY-MM-DD"
                    if raw_date >= date_gte:
                        results.append(m)
                # Stop paginating if oldest item on this page is before cutoff
                if models and models[-1].get("date", "")[:10] < date_gte:
                    break
                if page >= data.get("pageCount", 1) - 1:
                    break
                page += 1
            except Exception as e:
                print(f"  TR-CERT {label} page {page} error: {e}")
                break
        print(f"  TR-CERT {label}: fetched {len(results)} items")
        return results

    # Fetch both announcement and incident feeds
    announcements = fetch_endpoint_all("/api/announcement/index", "announcements")
    incidents     = fetch_endpoint_all("/api/incident/index",     "incidents")

    for item in announcements + incidents:
        raw_url  = item.get("url", "")
        title    = item.get("title") or item.get("q") or "TR-CERT Advisory"
        desc     = item.get("desc") or ""
        pub_date = item.get("date", "")

        # Strip HTML tags from desc if any
        clean_desc = re.sub(r"<[^>]+>", "", desc).strip()[:300]

        # Normalise date to ISO-8601
        iso_date = ""
        try:
            # API returns "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD"
            iso_date = datetime.strptime(pub_date[:10], "%Y-%m-%d").replace(
                tzinfo=timezone.utc).isoformat()
        except Exception:
            iso_date = datetime.now(timezone.utc).isoformat()

        # Try to extract a CVE ID from the combined text
        combined  = title + " " + clean_desc + " " + raw_url
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", combined)
        cve_id    = cve_match.group(0) if cve_match else f"TR-CERT-{abs(hash(title + iso_date)) % 100000}"

        # Build the source URL — prefer a direct detail link if the API provides one
        source_url = raw_url if raw_url.startswith("http") else \
                     f"https://siberguvenlik.gov.tr/guvenlik-bildirimleri/"

        threats.append({
            "id":           cve_id,
            "description":  f"[TR-CERT] {title}" + (f" | {clean_desc}..." if clean_desc else ""),
            "score":        7.0,
            "severity":     "HIGH",
            "published":    iso_date,
            "lastModified": iso_date,
            "source":       "TR-CERT",
            "source_url":   source_url,
            "is_exploited": False,
        })

    print(f"  TR-CERT total: {len(threats)} advisories within last {DATA_WINDOW_DAYS} days")
    return threats


def fetch_github_advisories():
    """Fetch recent GitHub Security Advisories (GHSA) via the public JSON feed.

    GitHub publishes a machine-readable advisory database at:
      https://github.com/nicowillis/github-advisory-database  (mirror)
    We use the official GHSA REST v3 endpoint which requires no auth for
    public advisories, filtering by published_since.
    """
    print("Fetching GitHub Security Advisories (GHSA REST API)...")
    advisories = []
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=DATA_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # GitHub REST API: list public advisories, sorted newest first
        url = "https://api.github.com/advisories"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Midnight-Intelligence-Tracker/2.2",
        }
        page = 1
        while page <= 5:  # Max 5 pages of 100 = 500 advisories
            params = {
                "published": f">{since}",
                "per_page": 100,
                "page": page,
                "sort": "published",
                "direction": "desc",
            }
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            if resp.status_code == 403:
                print("  GHSA: rate limited — stopping early")
                break
            if resp.status_code != 200:
                print(f"  GHSA API returned HTTP {resp.status_code}")
                break
            items = resp.json()
            if not items:
                break
            for adv in items:
                pub = adv.get("published_at", "")
                # Pick the first CVE alias if available
                cve_id = adv.get("cve_id") or adv.get("ghsa_id", "Unknown")
                summary = adv.get("summary", "No summary.")[:200]
                cvss = adv.get("cvss", {}) or {}
                score = float(cvss.get("score") or 0)
                severity = (adv.get("severity") or "UNKNOWN").upper()
                advisories.append({
                    "id":           cve_id,
                    "description":  f"[GHSA] {summary}",
                    "score":        score,
                    "severity":     severity,
                    "published":    pub,
                    "lastModified": adv.get("updated_at", pub),
                    "source":       "GitHub",
                    "source_url":   adv.get("html_url") or f"https://github.com/advisories/{adv.get('ghsa_id','')}",
                    "is_exploited": False,
                })
            # Stop if this page returned fewer items than requested (last page)
            if len(items) < 100:
                break
            page += 1
    except Exception as e:
        print(f"Error fetching GHSA: {e}")
    print(f"  GHSA: fetched {len(advisories)} advisories")
    return advisories

def fetch_cisa_kev():
    print("Fetching CISA Known Exploited Vulnerabilities (KEV)...")
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        data = response.json()
        return {item['cveID']: item['shortDescription'] for item in data.get('vulnerabilities', [])}
    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")
        return {}

def fetch_exploit_db():
    print("Fetching latest Exploit-DB entries...")
    exploits = []
    try:
        url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        response = requests.get(url, timeout=20)
        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)
        recent_date = (datetime.now(timezone.utc) - timedelta(days=DATA_WINDOW_DAYS)).strftime('%Y-%m-%d')
        for row in reader:
            # Fix #8: Skip rows with empty date_published
            date_pub = row.get('date_published', '').strip()
            if not date_pub:
                continue
            if date_pub >= recent_date:
                edb_id = row.get('id', '').strip()
                if not edb_id:
                    continue
                exploits.append({
                    'id': f"EDB-{edb_id}",
                    'description': f"[EXPLOIT-DB: {row.get('type', 'Unknown')}] {row.get('description', 'Exploit')} - Author: {row.get('author', 'Unknown')}",
                    # Score is intentionally 0.0 — Exploit-DB entries don't carry CVSS data;
                    # MTS will be driven by EPSS + is_exploited bonus instead.
                    'score': 0.0,
                    'severity': "UNKNOWN",
                    'published': date_pub + "T00:00:00.000Z",
                    'lastModified': date_pub + "T00:00:00.000Z",
                    'source': 'Exploit-DB',
                    'source_url': f"https://www.exploit-db.com/exploits/{edb_id}",
                    'is_exploited': True
                })
    except Exception as e:
        print(f"Error fetching Exploit-DB: {e}")
    return exploits

def fetch_nvd():
    print(f"Fetching newly published CVEs from NVD API (Last {DATA_WINDOW_DAYS} Days)...")
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=DATA_WINDOW_DAYS)
    
    # NVD API 2.0 requires dates with Z suffix (UTC)
    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000') + 'Z'
    end_date_str = now.strftime('%Y-%m-%dT%H:%M:%S.000') + 'Z'
    
    base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date_str}&pubEndDate={end_date_str}"
    headers = {'User-Agent': 'Antigravity-Intelligence-Tracker'}
    api_key = os.environ.get('NVD_API_KEY')
    if api_key: headers['apiKey'] = api_key
    
    session = requests.Session()
    session.headers.update(headers)
    
    cves = []
    
    def process_page_data(data):
        page_cves = []
        items = data.get('vulnerabilities', [])
        for item in items:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            desc = "No description available."
            for d in cve_data.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc = d.get('value')[:300] + ('...' if len(d.get('value')) > 300 else '')
                    break
            metrics = cve_data.get('metrics', {})
            base_score, severity = 0.0, "UNKNOWN"
            # CVSS scoring: prefer v3.1 → v3.0 → v2 fallback
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score, severity = cvss_data.get('baseScore', 0.0), cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                base_score, severity = cvss_data.get('baseScore', 0.0), cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
            # CVSSv2 baseSeverity is in a separate field
                severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
            
            if base_score == 0: severity = "PENDING"
            
            published_date = cve_data.get('published', '')
            if published_date and not published_date.endswith('Z') and '+' not in published_date:
                published_date += 'Z'

            page_cves.append({'id': cve_id, 'description': desc, 'score': base_score, 'severity': severity, 
                              'published': published_date, 'lastModified': cve_data.get('lastModified', ''), 
                              'source': 'NVD', 'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}", 'is_exploited': False})
        return page_cves

    try:
        # Fetch first page to get totalResults
        resp = session.get(f"{base_url}&startIndex=0", timeout=30)
        if resp.status_code != 200:
            print(f"NVD API Error on first page: {resp.status_code}")
            return []
            
        first_page_data = resp.json()
        cves.extend(process_page_data(first_page_data))
        
        total_results = first_page_data.get('totalResults', 0)
        results_per_page = first_page_data.get('resultsPerPage', 2000)
        
        if total_results > results_per_page:
            start_indices = range(results_per_page, total_results, results_per_page)
            print(f"NVD found {total_results} results. Fetching remaining {len(start_indices)} pages in parallel...")
            
            # Thread-safe: each thread creates its own session
            def fetch_page(idx):
                thread_session = requests.Session()
                thread_session.headers.update(headers)
                for _ in range(3): # Retry logic
                    try:
                        r = thread_session.get(f"{base_url}&startIndex={idx}", timeout=30)
                        if r.status_code == 200: return process_page_data(r.json())
                        if r.status_code in [403, 429]: time.sleep(10)
                    except: time.sleep(2)
                return []

            max_nvd_workers = 5 if api_key else 2 # Respect rate limits
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_nvd_workers) as executor:
                for page_results in executor.map(fetch_page, start_indices):
                    cves.extend(page_results)
                    
    except Exception as e:
        print(f"Error fetching NVD: {e}")
    return cves

def extract_vendor(desc):
    vendors = ["microsoft", "google", "apple", "adobe", "cisco", "oracle", "linux", "android", "windows", "fortinet", "vmware", "atlassian", "ivanti"]
    desc_lower = desc.lower()
    for v in vendors:
        if v in desc_lower: return v.upper()
    return "Other"

def fetch_epss(cve_ids):
    epss_dict = {}
    if not cve_ids: return epss_dict
    try:
        chunk_size = 500
        chunks = [cve_ids[i:i + chunk_size] for i in range(0, len(cve_ids), chunk_size)]
        def fetch_chunk(chunk):
            try:
                url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
                res = requests.get(url, timeout=15)
                return {item['cve']: float(item['epss']) for item in res.json().get('data', [])}
            except: return {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for res_dict in executor.map(fetch_chunk, chunks): epss_dict.update(res_dict)
    except Exception as e: print(f"EPSS Error: {e}")
    return epss_dict

def main():
    print("--- Starting Threat Intelligence Aggregation ---")
    now = datetime.now(timezone.utc)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            'KEV':  fetch_cisa_kev,
            'EDB':  fetch_exploit_db,
            'NVD':  fetch_nvd,
            'GH':   fetch_github_advisories,
            'ZDI':  fetch_zdi,
            'P0':   fetch_google_p0,
            'CERT': fetch_cert_cc,
            'USOM': fetch_usom
        }
        futures = {executor.submit(f): name for name, f in tasks.items()}
        results = {futures[f]: f.result() for f in concurrent.futures.as_completed(futures)}

    cisa_kev_dict = results.get('KEV', {})
    # Remove KEV from results so it's not processed as a threat list in the loop below
    if 'KEV' in results: del results['KEV']

    unique_threats = {}
    for source_name, data in results.items():
        for t in data:
            tid = t['id']
            # Deduplication: NVD is the most authoritative source
            # If NVD data exists, it takes priority over all other sources
            if tid not in unique_threats:
                unique_threats[tid] = t
            elif t['source'] == 'NVD':
                # Always prioritize NVD data when available
                unique_threats[tid] = t

    all_threats = list(unique_threats.values())
    epss_scores = fetch_epss([t['id'] for t in all_threats if t['id'].startswith('CVE-')])

    def enrich_threat(t):
        cve_id = t['id']
        epss = epss_scores.get(cve_id, 0)
        t['epss'] = epss
        if cve_id in cisa_kev_dict:
            t['is_exploited'], t['severity'], t['score'] = True, "CRITICAL", max(t.get('score', 0), 9.8)
        t['vendor'] = extract_vendor(t.get('description', ''))
        
        cvss = float(t.get('score', 0))
        try:
            # Handle dates robustly
            pub_str = t['published']
            if not pub_str.endswith('Z') and '+' not in pub_str:
                pub_str += 'Z'
            pub_date = datetime.fromisoformat(pub_str.replace('Z', '+00:00'))
            days_old = (now - pub_date).days
        except Exception as e:
            days_old = 999
        
        s1, s2, s3 = (cvss / 10.0) * 40, epss * 30, (15 if t.get('is_exploited') else 0)
        s5 = 15 if days_old <= 1 else 10 if days_old <= 3 else 7 if days_old <= 7 else 1
        t['mts_score'] = min(round(s1 + s2 + s3 + s5, 1), 100.0)
        return t

    # Parallel enrichment for top speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        all_threats = list(executor.map(enrich_threat, all_threats))

    all_threats.sort(key=lambda x: x.get('mts_score', 0), reverse=True)

    # Build stats block for frontend consumption
    stats = {
        'total': len(all_threats),
        'critical_mts80': sum(1 for t in all_threats if (t.get('mts_score') or 0) >= 80),
        'high_mts60':     sum(1 for t in all_threats if 60 <= (t.get('mts_score') or 0) < 80),
        'cisa_kev':       sum(1 for t in all_threats if t.get('is_exploited') and t.get('source') != 'Exploit-DB'),
        'active_exploits': sum(1 for t in all_threats if t.get('source') == 'Exploit-DB'),
    }

    with open('cves.json', 'w', encoding='utf-8') as f:
        json.dump({
            'last_updated': now.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'total_found': len(all_threats),
            'stats': stats,
            'cves': all_threats
        }, f)
    print(f"--- Saved {len(all_threats)} threats (Critical MTS80+: {stats['critical_mts80']}, CISA KEV: {stats['cisa_kev']}) ---")

if __name__ == "__main__":
    main()
