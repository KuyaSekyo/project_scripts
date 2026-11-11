import os
import sys
import time
import argparse
import csv
import re
from datetime import datetime
import requests

# Default API configuration
VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
HA_API_KEY = os.getenv("HA_API_KEY", "YOUR_HYBRID_ANALYSIS_API_KEY")

class SmartThrottler:
    """Tracks API requests to stay within Free Tier limits dynamically."""
    def __init__(self):
        self.vt_request_timestamps = []

    def pace_virustotal(self):
        """Ensures no more than 4 requests are sent within any rolling 60-second window."""
        now = time.time()
        self.vt_request_timestamps = [t for t in self.vt_request_timestamps if now - t < 60]
        
        if len(self.vt_request_timestamps) >= 4:
            oldest_request = self.vt_request_timestamps[0]
            sleep_needed = 61 - (now - oldest_request)
            if sleep_needed > 0:
                print(f"[!] Smart Throttler: Approaching Free API limit (4 req/min). Pausing for {int(sleep_needed)}s...")
                time.sleep(sleep_needed)
        
        self.vt_request_timestamps.append(time.time())

def detect_ioc_type(ioc):
    """Detects if an indicator is a hash, a domain, or an IPv4 address."""
    # Strict regex pattern matching for MD5, SHA1, or SHA256 hashes
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
        return "hash"
    
    # Validates Standard IPv4 structure (0.0.0.0 to 255.255.255.255)
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ip_pattern, ioc):
        return "ip"
        
    # Validates Domain/FQDN structures
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
        
    return "unknown"

def check_virustotal(ioc, ioc_type, api_key, throttler):
    if not api_key or api_key.startswith("YOUR_"):
        return {"status": "Missing Key", "malicious": "N/A", "total": "N/A", "label": "N/A"}
    
    throttler.pace_virustotal()
    
    # Route to the appropriate endpoint based on the dynamic indicator type
    if ioc_type == "hash":
        url = f"https://virustotal.com{ioc}"
    elif ioc_type == "ip":
        url = f"https://virustotal.com{ioc}"
    else:
        url = f"https://virustotal.com{ioc}"
        
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            
            # Smart context-aware label parsing
            label = "N/A"
            if ioc_type == "hash":
                label = data.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
            elif ioc_type == "ip":
                label = data.get('as_owner', 'Unknown ASN Owner')
            else:
                categories = data.get('categories', {})
                if categories:
                    label = ", ".join(list(categories.values())[:2])

            return {
                "status": "Found",
                "malicious": stats.get('malicious', 0),
                "total": sum(stats.values()),
                "label": label if label else "N/A"
            }
        elif response.status_code == 404: 
            return {"status": "Not Found", "malicious": "N/A", "total": "N/A", "label": "N/A"}
        elif response.status_code == 429: 
            print("[!] Hard Rate Limit (429) hit from VT. Backing off for 60 seconds...")
            time.sleep(60)
            return {"status": "Rate Limited (Skipped)", "malicious": "N/A", "total": "N/A", "label": "N/A"}
        return {"status": f"HTTP {response.status_code}", "malicious": "N/A", "total": "N/A", "label": "N/A"}
    except Exception as e: 
        return {"status": "Error", "malicious": "N/A", "total": "N/A", "label": "N/A"}

def check_hybrid_analysis(ioc, ioc_type, api_key):
    if not api_key or api_key.startswith("YOUR_"):
        return {"status": "Missing Key", "verdict": "N/A", "score": "N/A", "family": "N/A"}
        
    # Format request body data payload depending on indicator expectations
    if ioc_type == "hash":
        url = "https://hybrid-analysis.com"
        data = {"hash": ioc}
    elif ioc_type == "ip":
        url = "https://hybrid-analysis.com"
        data = {"host": ioc}
    else:
        url = "https://hybrid-analysis.com"
        data = {"domain": ioc}
        
    headers = {
        "accept": "application/json", 
        "user-agent": "Falcon Sandbox", 
        "api-key": api_key, 
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            res_json = response.json()
            if not res_json: 
                return {"status": "Not Found", "verdict": "N/A", "score": "N/A", "family": "N/A"}
            
            if isinstance(res_json, list):
                if len(res_json) == 0:
                    return {"status": "Not Found", "verdict": "N/A", "score": "N/A", "family": "N/A"}
                # Use the primary response block found
                report = res_json[0]
            else:
                report = res_json

            return {
                "status": "Found",
                "verdict": report.get("verdict", "unknown"),
                "score": report.get("threat_score", "N/A"),
                "family": report.get("vx_family", "N/A") or report.get("classification", "N/A") or "N/A"
            }
        elif response.status_code == 404: 
            return {"status": "Not Found", "verdict": "N/A", "score": "N/A", "family": "N/A"}
        return {"status": f"HTTP {response.status_code}", "verdict": "N/A", "score": "N/A", "family": "N/A"}
    except Exception as e: 
        return {"status": "Error", "verdict": "N/A", "score": "N/A", "family": "N/A"}

def main():
    parser = argparse.ArgumentParser(description="Lite Munin: Unified Hash, Domain, & IP Reputation Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to text file containing indicators (one per line)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Error: File '{args.file}' not found.")
        sys.exit(1)

    with open(args.file, "r") as f:
        raw_iocs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    csv_filename = f"ioc_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    throttler = SmartThrottler()
    
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "Indicator", "Type", "VT Status", "VT Malicious Engines", "VT Total Engines", 
            "VT Context (Family/ASN/Category)", "HA Status", "HA Verdict", "HA Threat Score", "HA Classification"
        ])

        print(f"[*] Processing {len(raw_iocs)} mixed infrastructure indicators into {csv_filename}...\n")
        
        for index, ioc in enumerate(raw_iocs, start=1):
            ioc_type = detect_ioc_type(ioc)
            
            if ioc_type == "unknown":
                print(f"[{index}/{len(raw_iocs)}] Skipped (Unsupported Format): {ioc}")
                writer.writerow([ioc, "Unsupported", "Skipped", "N/A", "N/A", "N/A", "Skipped", "N/A", "N/A", "N/A"])
                continue
                
            print(f"[{index}/{len(raw_iocs)}] Checking ({ioc_type.upper()}): {ioc}")
            
            vt = check_virustotal(ioc, ioc_type, VT_API_KEY, throttler)
            ha = check_hybrid_analysis(ioc, ioc_type, HA_API_KEY)
            
            writer.writerow([
                ioc, ioc_type.upper(), vt["status"], vt["malicious"], vt["total"], 
                vt["label"], ha["status"], ha["verdict"], ha["score"], ha["family"]
            ])
            
            # Base cooling gap to stay friendly to server gateways
            time.sleep(1.5)

    print(f"\n[+] Task Completed. Results generated: {csv_filename}")

if __name__ == "__main__":
    main()
