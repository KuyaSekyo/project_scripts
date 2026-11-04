#!/usr/bin/env bash

# Verify system binaries are available
for cmd in nmap whatweb nikto nuclei python3; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[!] Missing required component framework pipeline dependency: $cmd" >&2
        exit 1
    fi
done

if [ -z "$1" ]; then
    echo "Usage: $0 <target_domain_or_ip>"
    exit 1
fi

TARGET="$1"
CLEAN_NAME=${TARGET//\//_}
OUTPUT_DIR="scan_${CLEAN_NAME}"
mkdir -p "$OUTPUT_DIR"

# 1. Network Mapping via Nmap
echo "[+] Starting footprint intelligence mapping via Nmap..."
nmap -p- -sV -T4 --open "$TARGET" -oN "$OUTPUT_DIR/nmap_summary.txt" -oG "$OUTPUT_DIR/nmap_grepable.txt"

# Establish target paths
TARGETS_FILE="$OUTPUT_DIR/endpoints_discovered.txt"
WEB_TARGETS_FILE="$OUTPUT_DIR/web_endpoints.txt"
> "$TARGETS_FILE"
> "$WEB_TARGETS_FILE"

# Extract open endpoints
awk '/Ports:/{split($0,a,"Ports: "); split(a[2],b,","); for(i in b){if(b[i] ~ /open/){split(b[i],c,"/"); print $2 ":" c[1]}}}' "$OUTPUT_DIR/nmap_grepable.txt" >> "$TARGETS_FILE"


if [ ! -s "$TARGETS_FILE" ]; then
    echo "[-] No open network pathways detected. Exiting pipeline sequence."
    exit 0
fi

# Categorize HTTP vs generic services
while read -r line; do
    if [[ "$line" =~ :80$ ]] || [[ "$line" =~ :443$ ]] || [[ "$line" =~ :8080$ ]] || [[ "$line" =~ :8443$ ]]; then
        if [[ "$line" =~ :443$ ]] || [[ "$line" =~ :8443$ ]]; then
            echo "https://$line" >> "$WEB_TARGETS_FILE"
        else
            echo "http://$line" >> "$WEB_TARGETS_FILE"
        fi
    fi
done < "$TARGETS_FILE"

# 2. Web Directory & Structure Inspection
if [ -s "$WEB_TARGETS_FILE" ]; then
    echo "[+] Web service detected. Profiling tech stack via WhatWeb..."
    whatweb --log-json="$OUTPUT_DIR/whatweb_findings.json" --input-file="$WEB_TARGETS_FILE" -q

    echo "[+] Running subdirectory scanning and configuration audit via Nikto..."
    > "$OUTPUT_DIR/nikto_findings.json"
    while read -r web_target; do
        echo "    [*] Probing directories on: $web_target"
        # -C all forces checks across all known web subdirectories
        nikto -h "$web_target" -C all -Format json -o "$OUTPUT_DIR/tmp_nikto.json" -maxtime 10m &>/dev/null
        
        if [ -s "$OUTPUT_DIR/tmp_nikto.json" ]; then
            cat "$OUTPUT_DIR/tmp_nikto.json" > "$OUTPUT_DIR/nikto_findings.json"
            rm "$OUTPUT_DIR/tmp_nikto.json"
        fi
    done < "$WEB_TARGETS_FILE"
else
    echo "[-] No active HTTP layers detected. Skipping WhatWeb and Nikto directory probing."
fi

# 3. Targeted OWASP Top 10 + CVE Exploitation via Nuclei
echo "[+] Launching targeted OWASP Top 10 & CVE checks via Nuclei..."
# We pass both the -tags flag for owasp and default severity filters to guarantee total coverage
nuclei -list "$TARGETS_FILE" \
       -as \
       -tags owasp,cve,misconfig \
       -severity info,low,medium,high,critical \
       -jsonl \
       -o "$OUTPUT_DIR/nuclei_findings.json" \
       -silent

# 4. Generate Final Document
echo "[+] Structuring findings into Consolidated_Security_Report.pdf..."
python3 report_gen.py "$TARGET" \
                      "$OUTPUT_DIR/nmap_summary.txt" \
                      "$OUTPUT_DIR/whatweb_findings.json" \
                      "$OUTPUT_DIR/nikto_findings.json" \
                      "$OUTPUT_DIR/nuclei_findings.json" \
                      "$OUTPUT_DIR/Consolidated_Security_Report.pdf"
