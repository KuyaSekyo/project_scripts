import os
import sys
import time
import argparse
import csv
import re
import socket
from datetime import datetime
import requests

def detect_ioc_type(ioc):
    """Detects if an indicator is a hash, an IPv4 address, or a domain/FQDN."""
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
        return "hash"
    
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ip_pattern, ioc):
        return "ip"
        
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
        
    return "unknown"

def get_hash_algo(ioc):
    """Identifies hash length for CIRCL endpoint routing."""
    length = len(ioc)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    return "sha256"

def check_circl_hash(ioc):
    """Queries CIRCL Hashlookup (No API Key) to verify known benign/system files."""
    algo = get_hash_algo(ioc)
    url = f"https://hashlookup.circl.lu/lookup/{algo}/{ioc}"
    headers = {"accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            file_name = data.get("FileName", "Known File")
            source = data.get("source", "NSRL/CIRCL")
            return {
                "source": "CIRCL Hashlookup",
                "verdict": "Known Benign / NSRL Match",
                "details": f"File: {file_name} (Source: {source})"
            }
        elif response.status_code == 404:
            return {
                "source": "CIRCL Hashlookup",
                "verdict": "Unknown / Unverified",
                "details": "Not found in known-good software databases"
            }
        return {"source": "CIRCL Hashlookup", "verdict": f"HTTP {response.status_code}", "details": "N/A"}
    except Exception as e:
        return {"source": "CIRCL Hashlookup", "verdict": "Error", "details": str(e)}

def check_shodan_internetdb(ip):
    """Queries Shodan InternetDB (No API Key) for open ports, CVEs, and tags."""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            tags = data.get("tags", [])
            
            verdict = "Suspicious / Tagged" if (tags or vulns) else "Active Host"
            details = f"Ports: {ports} | Vulns: {len(vulns)} | Tags: {tags}"
            return {"source": "Shodan InternetDB", "verdict": verdict, "details": details}
        elif response.status_code == 404:
            return {"source": "Shodan InternetDB", "verdict": "No Data", "details": "No open ports/history indexed"}
        return {"source": "Shodan InternetDB", "verdict": f"HTTP {response.status_code}", "details": "N/A"}
    except Exception as e:
        return {"source": "Shodan InternetDB", "verdict": "Error", "details": str(e)}

def check_urlscan_public(query_term):
    """Queries urlscan.io public search index (No API Key) for past malicious verdicts."""
    url = f"https://urlscan.io{query_term}&size=5"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            results = response.json().get("results", [])
            if not results:
                return {"verdict": "No Public Scans", "scans": 0}
            
            malicious_hits = 0
            for res in results:
                verdicts = res.get("verdicts", {}).get("overall", {})
                if verdicts.get("malicious") or verdicts.get("score", 0) > 0:
                    malicious_hits += 1
            
            verdict = f"Malicious ({malicious_hits}/{len(results)} scans)" if malicious_hits > 0 else f"Clean ({len(results)} recent scans)"
            return {"verdict": verdict, "scans": len(results)}
        elif response.status_code == 429:
            return {"verdict": "Rate Limited", "scans": 0}
        return {"verdict": f"HTTP {response.status_code}", "scans": 0}
    except Exception:
        return {"verdict": "Lookup Error", "scans": 0}

def main():
    parser = argparse.ArgumentParser(description="Lite Munin Keyless: Zero-Auth IOC Validator")
    parser.add_argument("-f", "--file", required=True, help="Path to text file containing IOCs (one per line)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Error: File '{args.file}' not found.")
        sys.exit(1)

    with open(args.file, "r") as f:
        raw_iocs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    csv_filename = f"keyless_ioc_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "Indicator", "Type", "Resolved IP", "Primary Source", 
            "Primary Verdict", "Technical Details", "urlscan.io Public Verdict"
        ])

        print(f"[*] Processing {len(raw_iocs)} IOCs without API keys into {csv_filename}...\n")
        
        for index, ioc in enumerate(raw_iocs, start=1):
            ioc_type = detect_ioc_type(ioc)
            
            if ioc_type == "unknown":
                print(f"[{index}/{len(raw_iocs)}] Skipped (Invalid Format): {ioc}")
                writer.writerow([ioc, "Unknown", "N/A", "N/A", "Skipped", "Invalid format", "N/A"])
                continue

            print(f"[{index}/{len(raw_iocs)}] Checking ({ioc_type.upper()}): {ioc}")

            if ioc_type == "hash":
                res = check_circl_hash(ioc)
                writer.writerow([ioc, "HASH", "N/A", res["source"], res["verdict"], res["details"], "N/A"])

            elif ioc_type == "ip":
                shodan_res = check_shodan_internetdb(ioc)
                urlscan_res = check_urlscan_public(f"ip:{ioc}")
                writer.writerow([ioc, "IP", ioc, shodan_res["source"], shodan_res["verdict"], shodan_res["details"], urlscan_res["verdict"]])

            elif ioc_type == "domain":
                # Resolve domain to IP to enrich with Shodan InternetDB
                try:
                    resolved_ip = socket.gethostbyname(ioc)
                    shodan_res = check_shodan_internetdb(resolved_ip)
                except socket.gaierror:
                    resolved_ip = "Unresolved / NXDOMAIN"
                    shodan_res = {"source": "DNS / Shodan", "verdict": "Dead / Sinkholed Domain", "details": "Domain does not resolve"}

                urlscan_res = check_urlscan_public(f"domain:{ioc}")
                writer.writerow([ioc, "DOMAIN", resolved_ip, shodan_res["source"], shodan_res["verdict"], shodan_res["details"], urlscan_res["verdict"]])

            # Polite 2-second pause to respect unauthenticated urlscan.io search quotas
            time.sleep(2)

    print(f"\n[+] Task Completed. Results saved to: {csv_filename}")

if __name__ == "__main__":
    main()
