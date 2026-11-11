# Lite Munin: IOC Hash Validator

A lightweight, non-destructive Python tool inspired by Munin to validate IOCs - Domains, IP addresses, and File hashes against **VirusTotal (v3 API)** and **Hybrid Analysis (v2 API)**. It outputs directly to an Excel-friendly CSV file and features an intelligent throttling engine to automatically handle free/public API tier rate limits without crashing.

#### Special thanks to Florian Roth for his Munin Project: https://github.com/neo23x0/munin, took it as an inspiration for coming up with this project

## Features
* **No `venv` Required**: Designed to run natively using standard libraries and a single global dependency.
* **Smart Throttling**: Monitors API pacing in real time; dynamically pauses only when approaching the 4 requests/minute limit for free keys.
* **IPv4 Address Resolution**: Now checks public IP threat reputations and extracts ASN ownership metadata from VirusTotal.
* **Domain / FQDN Validation**: Routes structural network hostnames to the dedicated domain categories and URL sandbox endpoints.
* **Dynamic Content Extraction**: The output spreadsheet adapts automatically—showing malware families for files, ISP networks for IPs, and category details for domains.
* **Auto-Type Detection**: No configuration flags are needed; simply paste your mixed targets into a text file, and the script handles the sorting natively.
* **CSV Export**: Automatically records structured data to a time-stamped spreadsheet for easy post-processing.

## Requirements & Dependencies
* Python 3.7+
* Network access to VirusTotal and Hybrid Analysis endpoints.

### Installation
Install the only required third-party library globally:
```bash
pip install requests
```

## Usage Samples

### 1. Set API Keys via Environment Variables (Recommended)
```bash
export VT_API_KEY="your_virustotal_api_key"
export HA_API_KEY="your_hybrid_analysis_api_key"

Or hardcode into the script.
# Change this:
VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
HA_API_KEY = os.getenv("HA_API_KEY", "YOUR_HYBRID_ANALYSIS_API_KEY")

# To this:
VT_API_KEY = os.getenv("VT_API_KEY", "x1y2z3...your_real_vt_key...")
HA_API_KEY = os.getenv("HA_API_KEY", "a1b2c3...your_real_ha_key...")

python lite_munin_throttled.py -f <iocs filename>.txt
```

### 2. File Format (`iocs.txt`)
Create a plain text file containing one hash per line. Lines starting with `#` are ignored:
```text
# Known bad Emotet sample
1585ad28f7d1e0ca696e6c6c2f1d008a
35e304d10d53834e3e41035d12122773c9a4d183a24e03f980ad3e6b2ecde7fa
```

## Sample Output

### Console Feedback
```text
[*] Processing 5 hashes into ioc_results_20261111_083000.csv...

[1/5] Checking: 1585ad28f7d1e0ca696e6c6c2f1d008a
[2/5] Checking: 35e304d10d53834e3e41035d12122773c9a4d183a24e03f980ad3e6b2ecde7fa
[3/5] Checking: 44d88612fea8a8f36de82e1278abb02f
[4/5] Checking: d2ce6f113a01ec1a9db12f689f626123
[!] Smart Throttler: Approaching Free API limit (4 req/min). Pausing for 52s...
[5/5] Checking: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

[+] Task Completed. File generated: ioc_results_20261111_083000.csv
```

### Generated CSV File Layout

| IOC Hash | VT Status | VT Malicious Matches | VT Total Engines | VT Threat Label | HA Status | HA Verdict | HA Threat Score | HA Malware Family |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1585ad28f7... | Found | 48 | 64 | trojan.emotet | Found | malicious | 100 | emotet |
| 35e304d10d... | Not Found | N/A | N/A | N/A | Not Found | N/A | N/A | N/A |
