# Lite Munin (Keyless Edition): Zero-Auth IOC Validator

A 100% API-key-free Python utility to validate **File Hashes (MD5, SHA1, SHA256)**, **IPv4 Addresses**, and **Domains/FQDNs** without creating accounts or managing API tokens. It queries open threat intelligence feeds and exports the findings directly into an Excel-friendly CSV file.

#### Special thanks to Florian Roth for his original Munin project (https://github.com), which inspired this lightweight workflow.

## Data Sources (No API Keys Required)
* **CIRCL Hashlookup:** Verifies file hashes against known legitimate software and NSRL databases to filter out benign system files.
* **Shodan InternetDB:** Checks IPv4 addresses (and resolved domain IPs) for exposed ports, known vulnerabilities (CVEs), and threat tags.
* **urlscan.io Public Search:** Queries historical public website scans for phishing or malware verdicts on domains and IPs.

## Features
* **Zero Configuration:** No environment variables, `.ini` files, or API keys needed—run it immediately out of the box.
* **No `venv` Required:** Uses Python's standard library alongside a single global dependency (`requests`).
* **Automatic DNS Enrichment:** Resolves domain names to their active IPv4 addresses to check underlying server exposure via Shodan.
* **Auto-Type Detection:** Mix hashes, domains, and IPs in a single text file; the script automatically detects and routes each indicator.
* **CSV Export:** Saves structured results to a timestamped `.csv` spreadsheet.

## Requirements & Installation
* Python 3.7+
* Internet access to `hashlookup.circl.lu`, `internetdb.shodan.io`, and `urlscan.io`.

Install the only required third-party library globally:
```bash
pip install requests
```

## Usage

### 1. Prepare Your Input File (`mixed_iocs.txt`)
Create a plain text file with one indicator per line. Blank lines and lines starting with `#` are ignored:
```text
# Known Windows system file hash
44d88612fea8a8f36de82e1278abb02f

# Suspicious domain
example-phishing-login.com

# Target IPv4 address
185.220.101.5
```

### 2. Run the Script
```bash
python lite_munin_keyless.py -f mixed_iocs.txt
```

## Sample Output

### Console Feedback
```text
[*] Processing 3 IOCs without API keys into keyless_ioc_results_20261123_123000.csv...

[1/3] Checking (HASH): 44d88612fea8a8f36de82e1278abb02f
[2/3] Checking (DOMAIN): example-phishing-login.com
[3/3] Checking (IP): 185.220.101.5

[+] Task Completed. Results saved to: keyless_ioc_results_20261123_123000.csv
```

### Generated CSV Layout

| Indicator | Type | Resolved IP | Primary Source | Primary Verdict | Technical Details | urlscan.io Public Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 44d88612fe... | HASH | N/A | CIRCL Hashlookup | Known Benign / NSRL Match | File: eicar.com (Source: NSRL) | N/A |
| example-phishing... | DOMAIN | 93.184.216.34 | Shodan InternetDB | Active Host | Ports: [80, 443] \| Vulns: 0 \| Tags: [] | Malicious (3/5 scans) |
| 185.220.101.5 | IP | 185.220.101.5 | Shodan InternetDB | Suspicious / Tagged | Ports: [22, 443] \| Vulns: 2 \| Tags: ['tor'] | Clean (2 recent scans) |

## Caveats
* **Hash Verdicts:** Because this version does not use VirusTotal, an `"Unknown / Unverified"` hash result simply means the file is not in known-good software databases—it should still be analyzed in a sandbox if suspicious.
* **DNS Resolution:** Domain lookups perform a live DNS query from your machine to resolve the IP address. Run the script on an isolated analysis machine or VPN if monitoring sensitive indicators.
