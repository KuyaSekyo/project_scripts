#!/usr/bin/env bash

# 1. Dependency Validation Layer
for cmd in subfinder nmap whatweb sslscan gobuster nikto nuclei python3; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[!] Missing required Kali Linux framework tool: $cmd" >&2
        echo "[*] Install via: sudo apt install -y subfinder sslscan gobuster nikto nuclei"
        exit 1
    fi
done

if [ -z "$1" ]; then
    echo "Usage: $0 <target_domain_or_ip>"
    echo "Example: $0 example.com"
    exit 1
fi

TARGET="$1"
CLEAN_NAME=${TARGET//\//_}
OUTPUT_DIR="scan_${CLEAN_NAME}"
mkdir -p "$OUTPUT_DIR"

echo "[+] Starting Enterprise-Grade Security Assessment Framework against: $TARGET"
echo "[+] Outputs are aggregating in directory folder: $OUTPUT_DIR/"

# --- PHASE 1: PRE-NMAP OSINT SUBDOMAIN DISCOVERY ---
AMASS_TARGETS="$OUTPUT_DIR/discovered_hosts.txt"
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[*] Target is an IP address. Skipping passive Subdomain Discovery Phase."
    echo "$TARGET" > "$AMASS_TARGETS"
else
    echo "[+] Phase 1: Launching Passive Subdomain Enumeration via subfinder..."
    subfinder -d "$TARGET" -o "$AMASS_TARGETS" -silent
    # Ensure the root apex domain itself is included in the asset list array
    echo "$TARGET" >> "$AMASS_TARGETS"
    sort -u "$AMASS_TARGETS" -o "$AMASS_TARGETS"
    echo "[*] Discovered $(wc -l < "$AMASS_TARGETS") unique host architectures to audit."
fi

# --- PHASE 2: INFRASTRUCTURE & PORT PROFILING ---
echo "[+] Phase 2: Running network port mapping loops via Nmap..."
nmap -iL "$AMASS_TARGETS" -p- -sV -T4 --open -oN "$OUTPUT_DIR/nmap_summary.txt" -oG "$OUTPUT_DIR/nmap_grepable.txt"

# Isolate open endpoints
TARGETS_FILE="$OUTPUT_DIR/endpoints_discovered.txt"
WEB_TARGETS_FILE="$OUTPUT_DIR/web_endpoints.txt"
> "$TARGETS_FILE"
> "$WEB_TARGETS_FILE"

awk '/Ports:/{split($0,a,"Ports: "); split(a[2],b,","); for(i in b){if(b[i] ~ /open/){split(b[i],c,"/"); print $2 ":" c[1]}}}' "$OUTPUT_DIR/nmap_grepable.txt" >> "$TARGETS_FILE"

if [ ! -s "$TARGETS_FILE" ]; then
    echo "[-] No open network interface pathways detected across assets. Exiting loop sequence."
    exit 0
fi

# Parse HTTP endpoints from open network port matrices
while read -r line; do
    if [[ "$line" =~ :80$ ]] || [[ "$line" =~ :8080$ ]]; then
        echo "http://$line" >> "$WEB_TARGETS_FILE"
    elif [[ "$line" =~ :443$ ]] || [[ "$line" =~ :8443$ ]]; then
        echo "https://$line" >> "$WEB_TARGETS_FILE"
    fi
done < "$TARGETS_FILE"

# --- PHASE 3: DEEP TLS AUDITING & WEB FUZZING ---
# 3a. Cryptographic Compliance Probes via SSLScan
> "$OUTPUT_DIR/sslscan_findings.xml"
while read -r line; do
    if [[ "$line" =~ :443$ ]] || [[ "$line" =~ :8443$ ]]; then
        echo "[+] Phase 3a: Auditing TLS configuration & cipher suite compliance on $line..."
        sslscan --xml="$OUTPUT_DIR/tmp_ssl.xml" "$line" &>/dev/null
        if [ -s "$OUTPUT_DIR/tmp_ssl.xml" ]; then
            cat "$OUTPUT_DIR/tmp_ssl.xml" >> "$OUTPUT_DIR/sslscan_findings.xml"
            rm "$OUTPUT_DIR/tmp_ssl.xml"
        fi
    fi
done < "$TARGETS_FILE"

# 3b. Web Application Technology & Directory Fuzzing
if [ -s "$WEB_TARGETS_FILE" ]; then
    echo "[+] Profiling core web component architecture via WhatWeb..."
    whatweb --log-json="$OUTPUT_DIR/whatweb_findings.json" --input-file="$WEB_TARGETS_FILE" -q

    echo "[+] Phase 3b: Launching web directory wordlist fuzzing via Gobuster..."
    # Using Kali's standard medium directory wordlist
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
    if [ ! -f "$WORDLIST" ]; then
        WORDLIST="/usr/share/dirb/wordlists/common.txt" # Fallback path check
    fi

    > "$OUTPUT_DIR/gobuster_findings.json"
    while read -r web_target; do
        echo "    [*] Directory forcing: $web_target"
        # -k skips TLS validation to prevent crashes on self-signed targets
        gobuster dir -u "$web_target" -w "$WORDLIST" -k -q --no-progress -o "$OUTPUT_DIR/tmp_gobuster.txt"
        if [ -s "$OUTPUT_DIR/tmp_gobuster.txt" ]; then
            while read -r gob_line; do
                # Convert Gobuster flat output into a structured raw tracking entry
                echo "$web_target $gob_line" >> "$OUTPUT_DIR/gobuster_findings.json"
            done < "$OUTPUT_DIR/tmp_gobuster.txt"
            rm "$OUTPUT_DIR/tmp_gobuster.txt"
        fi
    done < "$WEB_TARGETS_FILE"

    echo "[+] Running web directory vulnerability checks via Nikto..."
    # -C all forces check sweeps across web subdirectories
    > "$OUTPUT_DIR/nikto_findings.json"
    while read -r web_target; do
        nikto -h "$web_target" -C all -Format json -o "$OUTPUT_DIR/tmp_nikto.json" -maxtime 5m &>/dev/null
        if [ -s "$OUTPUT_DIR/tmp_nikto.json" ]; then
            cat "$OUTPUT_DIR/tmp_nikto.json" >> "$OUTPUT_DIR/nikto_findings.json"
            rm "$OUTPUT_DIR/tmp_nikto.json"
        fi
    done < "$WEB_TARGETS_FILE"
fi

# --- PHASE 4: ACTIVE CVE & OWASP EXPLOIT SCANNING ---
echo "[+] Phase 4: Triggering vulnerability exploit signature database via Nuclei..."
nuclei -list "$TARGETS_FILE" \
       -as \
       -tags owasp,cve,misconfig \
       -severity info,low,medium,high,critical \
       -jsonl \
       -o "$OUTPUT_DIR/nuclei_findings.json" \
       -silent

# --- PHASE 5: CONSOLIDATED PDF REPORT GENERATION ---
echo "[+] Phase 5: Compiling all tool outputs into Consolidated_Security_Report.pdf..."
python3 report_gen.py "$TARGET" \
                      "$OUTPUT_DIR/nmap_summary.txt" \
                      "$OUTPUT_DIR/whatweb_findings.json" \
                      "$OUTPUT_DIR/sslscan_findings.xml" \
                      "$OUTPUT_DIR/gobuster_findings.json" \
                      "$OUTPUT_DIR/nikto_findings.json" \
                      "$OUTPUT_DIR/nuclei_findings.json" \
                      "$OUTPUT_DIR/Consolidated_Security_Report.pdf"
