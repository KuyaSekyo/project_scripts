import os
import sys
import time
import argparse
import csv
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
        # Keep only requests from the last 60 seconds
        self.vt_request_timestamps = [t for t in self.vt_request_timestamps if now - t < 60]
        
        # If we hit the 4-request cap, calculate how long we must sleep
        if len(self.vt_request_timestamps) >= 4:
            oldest_request = self.vt_request_timestamps[0]
            sleep_needed = 61 - (now - oldest_request)
            if sleep_needed > 0:
                print(f"[!] Smart Throttler: Approaching Free API limit (4 req/min). Pausing for {int(sleep_needed)}s...")
                time.sleep(sleep_needed)
        
        # Track this request
        self.vt_request_timestamps.append(time.time())

def check_virustotal(ioc, api_key, throttler):
    if not api_key or api_key.startswith("YOUR_"):
        return {"status": "Missing Key", "malicious": "N/A", "total": "N/A", "label": "N/A"}
    
    # Enforce free tier pacing rule dynamically before making the call
    throttler.pace_virustotal()
    
    url = f"https://virustotal.com{ioc}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {
                "status": "Found",
                "malicious": stats.get('malicious', 0),
                "total": sum(stats.values()),
                "label": data.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
            }
        elif response.status_code == 404: 
            return {"status": "Not Found", "malicious": "N/A", "total": "N/A", "label": "N/A"}
        elif response.status_code == 429: 
            # Fallback block if external factors skewed time windows
            print("[!] Hard Rate Limit (429) hit from VT. Backing off for 60 seconds...")
            time.sleep(60)
            return {"status": "Rate Limited (Skipped)", "malicious": "N/A", "total": "N/A", "label": "N/A"}
        return {"status": f"HTTP {response.status_code}", "malicious": "N/A", "total": "N/A", "label": "N/A"}
    except Exception as e: 
        return {"status": "Error", "malicious": "N/A", "total": "N/A", "label": "N/A"}

def check_hybrid_analysis(ioc, api_key):
    if not api_key or api_key.startswith("YOUR_"):
        return {"status": "Missing Key", "verdict": "N/A", "score": "N/A", "family": "N/A"}
        
    url = "https://hybrid-analysis.com"
    headers = {
        "accept": "application/json", 
        "user-agent": "Falcon Sandbox", 
        "api-key": api_key, 
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(url, headers=headers, data={"hash": ioc})
        if response.status_code == 200:
            res_json = response.json()
            if not res_json: 
                return {"status": "Not Found", "verdict": "N/A", "score": "N/A", "family": "N/A"}
            return {
                "status": "Found",
                "verdict": res_json.get("verdict", "unknown"),
                "score": res_json.get("threat_score", "N/A"),
                "family": res_json.get("vx_family", "N/A")
            }
        elif response.status_code == 404: 
            return {"status": "Not Found", "verdict": "N/A", "score": "N/A", "family": "N/A"}
        return {"status": f"HTTP {response.status_code}", "verdict": "N/A", "score": "N/A", "family": "N/A"}
    except Exception as e: 
        return {"status": "Error", "verdict": "N/A", "score": "N/A", "family": "N/A"}

def main():
    parser = argparse.ArgumentParser(description="Lite Munin with Smart Throttling and CSV Export")
    parser.add_argument("-f", "--file", required=True, help="Path to hash list text file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Error: File '{args.file}' not found.")
        sys.exit(1)

    with open(args.file, "r") as f:
        iocs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    csv_filename = f"ioc_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    throttler = SmartThrottler()
    
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "IOC Hash", "VT Status", "VT Malicious Matches", "VT Total Engines", 
            "VT Threat Label", "HA Status", "HA Verdict", "HA Threat Score", "HA Malware Family"
        ])

        print(f"[*] Processing {len(iocs)} hashes into {csv_filename}...\n")
        
        for index, ioc in enumerate(iocs, start=1):
            print(f"[{index}/{len(iocs)}] Checking: {ioc}")
            
            # VirusTotal check with intelligent scheduling built-in
            vt = check_virustotal(ioc, VT_API_KEY, throttler)
            
            # Hybrid Analysis check
            ha = check_hybrid_analysis(ioc, HA_API_KEY)
            
            writer.writerow([
                ioc, vt["status"], vt["malicious"], vt["total"], 
                vt["label"], ha["status"], ha["verdict"], ha["score"], ha["family"]
            ])
            
            # Base buffer to ensure Hybrid Analysis server web gates aren't hit concurrently
            time.sleep(1.5)

    print(f"\n[+] Task Completed. File generated: {csv_filename}")

if __name__ == "__main__":
    main()
