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

# --- Threat Intelligence Data Fetcher (Antigravity v2.3) ---

def fetch_rss_feed(url, source_name):
    print(f"Fetching {source_name} feed...")
    threats = []
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            root = ET.fromstring(response.text)
            for item in root.findall('.//item'):
                title = item.find('title').text if item.find('title') is not None else "No Title"
                link = item.find('link').text if item.find('link') is not None else ""
                desc = item.find('description').text if item.find('description') is not None else ""
                pub_date = item.find('pubDate').text if item.find('pubDate') is not None else ""
                
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', title + desc)
                cve_id = cve_match.group(0) if cve_match else f"{source_name}-{hash(title) % 100000}"
                
                iso_date = ""
                try:
                    parts = pub_date.split(' ')
                    if len(parts) >= 4:
                        day, month_str, year = parts[1], parts[2], parts[3]
                        months = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06","Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
                        iso_date = f"{year}-{months.get(month_str, '01')}-{day.zfill(2)}T12:00:00.000Z"
                except: pass

                threats.append({
                    'id': cve_id,
                    'description': f"[{source_name}] {title} | {desc[:200]}...",
                    'score': 8.5,
                    'severity': "HIGH",
                    'published': iso_date or datetime.now(timezone.utc).isoformat(),
                    'lastModified': iso_date or datetime.now(timezone.utc).isoformat(),
                    'source': source_name,
                    'source_url': link,
                    'is_exploited': "exploit" in (title + desc).lower()
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

def fetch_github_advisories():
    print("Fetching GitHub Security Advisories via OSV.dev...")
    advisories = []
    try:
        url = "https://api.osv.dev/v1/queryvulnerabilities"
        since = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat().replace('+00:00', 'Z')
        payload = {"last_modified": since}
        response = requests.post(url, json=payload, timeout=20)
        if response.status_code == 200:
            vulns = response.json().get('vulnerabilities', [])
            for v in vulns:
                cve_id = v.get('id', 'Unknown')
                for alias in v.get('aliases', []):
                    if alias.startswith('CVE-'):
                        cve_id = alias
                        break
                advisories.append({
                    'id': cve_id,
                    'description': f"[GHSA] {v.get('summary', 'No summary available.')} | {v.get('details', '')[:200]}...",
                    'score': 7.5,
                    'severity': "HIGH",
                    'published': v.get('published', ''),
                    'lastModified': v.get('modified', ''),
                    'source': 'GitHub',
                    'source_url': f"https://github.com/advisories/{v.get('id')}",
                    'is_exploited': False
                })
    except Exception as e:
        print(f"Error fetching GitHub: {e}")
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
        recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')
        for row in reader:
            if row.get('date_published', '') >= recent_date:
                exploits.append({
                    'id': f"EDB-{row['id']}",
                    'description': f"[EXPLOIT-DB: {row.get('type', 'Unknown')}] {row.get('description', 'Exploit')} - Author: {row.get('author', 'Unknown')}",
                    'score': 10.0,
                    'severity': "CRITICAL",
                    'published': row.get('date_published', '') + "T00:00:00.000Z",
                    'lastModified': row.get('date_published', '') + "T00:00:00.000Z",
                    'source': 'Exploit-DB',
                    'source_url': f"https://www.exploit-db.com/exploits/{row['id']}",
                    'is_exploited': True
                })
    except Exception as e:
        print(f"Error fetching Exploit-DB: {e}")
    return exploits

def fetch_nvd():
    print("Fetching newly published CVEs from NVD API (Last 30 Days)...")
    now = datetime.now(timezone.utc)
    # Use 30 days to be safe and catch anything that might have been delayed in analysis
    start_date = now - timedelta(days=30)
    
    # NVD API 2.0 expects dates in YYYY-MM-DDTHH:mm:ss.SSS format
    # The API is sensitive to the exact format. We'll use UTC (Z).
    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date_str = now.strftime('%Y-%m-%dT%H:%M:%S.000')
    
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
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score, severity = cvss_data.get('baseScore', 0.0), cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                base_score, severity = cvss_data.get('baseScore', 0.0), cvss_data.get('baseSeverity', 'UNKNOWN')
            
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
            
            def fetch_page(idx):
                for _ in range(3): # Retry logic
                    try:
                        r = session.get(f"{base_url}&startIndex={idx}", timeout=30)
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
            'KEV': fetch_cisa_kev,
            'EDB': fetch_exploit_db,
            'NVD': fetch_nvd,
            'GH': fetch_github_advisories,
            'ZDI': fetch_zdi,
            'P0': fetch_google_p0,
            'CERT': fetch_cert_cc
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
            if tid not in unique_threats or t['source'] != 'NVD':
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
    with open('cves.json', 'w', encoding='utf-8') as f:
        json.dump({'last_updated': now.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'total_found': len(all_threats), 'cves': all_threats}, f)
    print(f"--- Saved {len(all_threats)} threats ---")

if __name__ == "__main__":
    main()
