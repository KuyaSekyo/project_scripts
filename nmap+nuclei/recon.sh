#!/usr/bin/env bash

if ! command -v nmap &>/dev/null || ! command -v nuclei &>/dev/null; then
    echo "[!] Missing operational binaries (nmap or nuclei). Install them to proceed." >&2
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <target_domain_or_ip>"
    exit 1
fi

TARGET="$1"
CLEAN_NAME=${TARGET//\//_}
OUTPUT_DIR="scan_${CLEAN_NAME}"
mkdir -p "$OUTPUT_DIR"

# Step 1: Run complete network service identification
echo "[+] Profiling ports and operational footprints..."
nmap -p- -sV -T4 --open "$TARGET" -oN "$OUTPUT_DIR/nmap_summary.txt" -oG "$OUTPUT_DIR/nmap_grepable.txt"

# Step 2: Build target file from discovery data
TARGETS_FILE="$OUTPUT_DIR/live_endpoints.txt"
> "$TARGETS_FILE"

awk '/Ports:/{split($0,a,"Ports: "); split(a[2],b,","); for(i in b){if(b[i] ~ /open/){split(b[i],c,"/"); print $2 ":" c[1]}}}' "$OUTPUT_DIR/nmap_grepable.txt" >> "$TARGETS_FILE"

if [ ! -s "$TARGETS_FILE" ]; then
    echo "[-] No visible connection gateways exposed. Ending automated framework pipeline."
    exit 0
fi

# Step 3: Run target software checks spitting out machine-readable JSON line logs
echo "[+] Launching full depth CVE vulnerability audit..."
nuclei -list "$TARGETS_FILE" \
       -as \
       -severity info,low,medium,high,critical \
       -jsonl \
       -o "$OUTPUT_DIR/nuclei_findings.json"

# Step 4: Fire Python report stitching architecture
echo "[+] Consolidating outputs into visual PDF layout..."
python3 report_gen.py "$TARGET" \
                      "$OUTPUT_DIR/nmap_summary.txt" \
                      "$OUTPUT_DIR/nuclei_findings.json" \
                      "$OUTPUT_DIR/Consolidated_Security_Report.pdf"
