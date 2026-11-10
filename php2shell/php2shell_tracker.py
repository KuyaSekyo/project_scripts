#!/usr/bin/env python3
"""
PHP2Shell Asset & Vulnerability Tracker Generator
Scans endpoints, fingerprints PHP runtime versions, and exports results to CSV and Excel.
"""

import sys
import os
import argparse
import requests
import urllib3
import pandas as pd

# Suppress SSL warnings for lab/self-signed assets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Minimum fixed versions released by the PHP team for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
PATCHED_VERSIONS = {
    8.5: (8, 5, 12),
    8.4: (8, 4, 27),
    8.3: (8, 3, 36),
    8.2: (8, 2, 35)
}

def parse_version(v_str):
    parts = []
    for p in v_str.split('.'):
        digits = "".join([c for c in p if c.isdigit()])
        if digits:
            parts.append(int(digits))
    return tuple(parts) if parts else (0,)

def evaluate_vulnerability(version_str):
    """Returns 'Potentially Vulnerable' or 'Not Vulnerable' based on patched baselines."""
    if not version_str or version_str == "Unknown":
        return "Unknown / Manual Check"
    
    v_tuple = parse_version(version_str)
    if not v_tuple or v_tuple[0] < 8:
        return "Potentially Vulnerable"  # EOL / older unpatched branches
    
    major_minor = (v_tuple[0], v_tuple[1] if len(v_tuple) > 1 else 0)
    
    for base, safe_tuple in PATCHED_VERSIONS.items():
        if major_minor == base:
            if v_tuple < safe_tuple:
                return "Potentially Vulnerable"
            else:
                return "Not Vulnerable"
                
    if v_tuple[0] > 8 or (v_tuple[0] == 8 and v_tuple[1] > 5):
        return "Not Vulnerable"
        
    return "Potentially Vulnerable"

import socket
from urllib.parse import urlparse

def scan_target(target):
    """Probes target and returns collected asset details safely."""
    if not target.startswith("http://") and not target.startswith("https://"):
        urls = [f"https://{target}", f"http://{target}"]
    else:
        urls = [target]

    for url in urls:
        try:
            response = requests.get(url, timeout=6, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Safe IP resolution fallback
            resolved_ip = "Unknown"
            try:
                parsed_url = urlparse(response.url)
                hostname = parsed_url.hostname
                if hostname:
                    resolved_ip = socket.gethostbyname(hostname)
            except Exception:
                pass
            
            powered_by = headers.get("X-Powered-By", "")
            server = headers.get("Server", "")
            set_cookie = headers.get("Set-Cookie", "")
            
            php_version = "Unknown"
            is_php = False
            
            if "php" in powered_by.lower() or "php" in server.lower() or "phpsessid" in set_cookie.lower():
                is_php = True
                combined = f"{powered_by} {server}"
                for token in combined.split():
                    if "/" in token and "php" in token.lower():
                        php_version = token.split("/")[1]
            
            if is_php:
                status = evaluate_vulnerability(php_version)
                return {
                    "Target URL": response.url,
                    "Public IP Address": resolved_ip,
                    "PHP Version": php_version,
                    "php2shell Status": status
                }
            else:
                return {
                    "Target URL": response.url,
                    "Public IP Address": resolved_ip,
                    "PHP Version": "No PHP Detected",
                    "php2shell Status": "Not Applicable"
                }
        except requests.exceptions.RequestException:
            continue
            
    return {
        "Target URL": target,
        "Public IP Address": "Unreachable",
        "PHP Version": "N/A",
        "php2shell Status": "Unreachable"
    }

def main():
    parser = argparse.ArgumentParser(description="PHP2Shell Tracker Generator")
    parser.add_argument("-f", "--file", required=True, help="Path to text file containing target IPs or domains")
    parser.add_argument("-o", "--output", default="php2shell_report", help="Output base filename (without extension)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Error: Target file '{args.file}' not found.")
        sys.exit(1)

    with open(args.file, "r") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[*] Starting scan across {len(targets)} targets...")
    results = []
    for t in targets:
        print(f"    -> Probing: {t}")
        res = scan_target(t)
        results.append(res)

    df = pd.DataFrame(results)

    # Export to CSV
    csv_filename = f"{args.output}.csv"
    df.to_csv(csv_filename, index=False)
    print(f"[+] CSV report saved successfully: {csv_filename}")

    # Export to formatted Excel spreadsheet
    excel_filename = f"{args.output}.xlsx"
    try:
        import openpyxl
        with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='PHP Audit Summary', index=False)
        print(f"[+] Spreadsheet report saved successfully: {excel_filename}")
    except ImportError:
        print("[!] openpyxl not found. Skipping .xlsx generation (CSV generated successfully).")

if __name__ == "__main__":
    main()
