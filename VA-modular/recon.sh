#!/usr/bin/env bash

# --- SIGNATURE VARIABLE MANAGEMENT ---
UA_STRING="ZP-VA"

# --- DEPENDENCY AND INTERFACE VALIDATION ---
verify_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "[!] Critical Error: '$1' framework missing from system path." >&2
        echo "[*] Run: sudo apt install -y subfinder sslscan gobuster nikto nuclei"
        exit 1
    fi
}

if [ -z "$1" ]; then
    echo "=========================================================="
    echo "       ZP-VA MODULAR ATTACK SURFACE RECON MATRIX           "
    echo "=========================================================="
    echo "Usage:   $0 <target_domain_or_ip>"
    echo "Example: $0 example.com"
    exit 1
fi

TARGET="$1"
CLEAN_NAME=${TARGET//\//_}
OUTPUT_DIR="scan_${CLEAN_NAME}"

# Pre-flight binary check for standard engines
for tool in nmap nuclei python3; do verify_tool "$tool"; done

# --- RE-SCAN COMPLIANCE ENGINE WITH HISTORICAL ARCHIVING ---
SKIP_SCANS=false

if [ -d "$OUTPUT_DIR" ]; then
    echo "=========================================================="
    echo "    ⚠️ PRIOR SCAN REPOSITORY DETECTED FOR THIS ASSET      "
    echo "=========================================================="
    echo "Target directory '$OUTPUT_DIR' already contains historical log assets."
    echo ""
    echo "1) Fast Compile: Skip scanning. Instantly recompile PDF from existing files."
    echo "2) Archive & Re-scan: Archive old files via timestamp and trigger fresh delta scan."
    echo "3) Abort: Cancel execution loop and do nothing."
    read -rp "Select update compliance strategy [1-3]: " HISTORY_CHOICE
    
    case "$HISTORY_CHOICE" in
        1)
            echo "[+] Skipping tool execution loops. Proceeding directly to report compilation..."
            SKIP_SCANS=true
            ;;
        2)
            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            ARCHIVE_DIR="$OUTPUT_DIR/archive_$TIMESTAMP"
            echo "[*] Potential re-scanning detected. Creating historical rollback partition..."
            mkdir -p "$ARCHIVE_DIR"
            
            # Move old tracking outputs safely into the archive partition space
            find "$OUTPUT_DIR" -maxdepth 1 -type f -exec mv {} "$ARCHIVE_DIR/" \;
            echo "[+] Old logs moved cleanly into: $ARCHIVE_DIR/"
            ;;
        3)
            echo "[*] Session aborted by operator. Exiting framework pipeline."
            exit 0
            ;;
        *)
            echo "[!] Invalid parsing choice. Aborting execution loop to safeguard data."
            exit 1
            ;;
    esac
fi

# Create base workspace directory if missing
mkdir -p "$OUTPUT_DIR"

# --- ONLY RUN SCAN SELECTION IF OPERATOR PREFERS AN APPLICATION REFRESH ---
if [ "$SKIP_SCANS" = false ]; then

    # --- DYNAMIC INTERACTIVE MENU LAYER ---
    echo "=========================================================="
    echo "          TARGET SCANNING PROFILE SELECTOR                "
    echo "=========================================================="
    echo "1) Web Application Target (Deep Web, Fuzzing, & CMS Analysis)"
    echo "2) Non-Web Infrastructure Host (Network Ports, OS, & Core Infrastructure)"
    echo "3) Full Stack / Dual-Target Scopes (All Available Modules Running)"
    echo "4) Light Scan Quick-Check (Nmap + Nuclei Basics Only)"
    read -rp "Select target deployment scope architecture [1-4]: " PROFILE_CHOICE

    # Set orchestration flags based on selection profile
    RUN_SUBFINDER=false; RUN_HTTPX=false; RUN_WHATWEB=false; 
    RUN_SSLSCAN=false; RUN_GOBUSTER=false; RUN_NIKTO=false;

    case "$PROFILE_CHOICE" in
        1)
            RUN_HTTPX=true; RUN_WHATWEB=true; RUN_SSLSCAN=true; RUN_GOBUSTER=true; RUN_NIKTO=true;
            if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then RUN_SUBFINDER=true; fi
            ;;
        2)
            # Infrastructure Profile
            ;;
        3)
            RUN_WHATWEB=true; RUN_SSLSCAN=true; RUN_GOBUSTER=true; RUN_NIKTO=true; RUN_HTTPX=true;
            if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then RUN_SUBFINDER=true; fi
            ;;
        4)
            # Light Quick-Check
            ;;
        *)
            echo "[!] Invalid selector. Defaulting to full stack orchestration execution."
            RUN_WHATWEB=true; RUN_SSLSCAN=true; RUN_GOBUSTER=true; RUN_NIKTO=true; RUN_HTTPX=true;
            if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then RUN_SUBFINDER=true; fi
            ;;
    esac

    # --- CONFIGURING CORE WORKSPACE TARGET FILES ---
    AMASS_TARGETS="$OUTPUT_DIR/discovered_hosts.txt"
    TARGETS_FILE="$OUTPUT_DIR/endpoints_discovered.txt"
    WEB_TARGETS_FILE="$OUTPUT_DIR/web_endpoints.txt"
    echo "$TARGET" > "$AMASS_TARGETS"

    # --- PHASE 1: PASSIVE OSINT RECON (SUBFINDER) ---
    if [ "$RUN_SUBFINDER" = true ]; then
        verify_tool "subfinder"
        echo "[+] Phase 1: Gathering asset infrastructure footprint via subfinder..."
        subfinder -d "$TARGET" -o "$OUTPUT_DIR/tmp_sub.txt" -silent
        if [ -s "$OUTPUT_DIR/tmp_sub.txt" ]; then
            cat "$OUTPUT_DIR/tmp_sub.txt" >> "$AMASS_TARGETS"
            rm "$OUTPUT_DIR/tmp_sub.txt"
        fi
        sort -u "$AMASS_TARGETS" -o "$AMASS_TARGETS"
        echo "[*] Enumerated $(wc -l < "$AMASS_TARGETS") hosts to audit."
    fi

    # --- PHASE 2: CORE PORT PROFILING AND DISCOVERY (NMAP) ---
    echo "[+] Phase 2: Running network port mapping loops via Nmap (Signed as ZP-VA)..."
    nmap -iL "$AMASS_TARGETS" -p- -sS -Pn -sV -T4 --open \
         --data-string "ZP-VA" \
         --script-args http.useragent="$UA_STRING" \
         -oN "$OUTPUT_DIR/nmap_summary.txt" \
         -oG "$OUTPUT_DIR/nmap_grepable.txt"

    # Extract open endpoints using the fixed awk script
    > "$TARGETS_FILE"
    awk '/Ports:/{split($0,a,"Ports: "); split(a,b,","); for(i in b){if(b[i] ~ /open/){split(b[i],c,"/"); print $2 ":" c}}}' "$OUTPUT_DIR/nmap_grepable.txt" >> "$TARGETS_FILE"

    if [ ! -s "$TARGETS_FILE" ]; then
        echo "[-] No open network interface pathways detected. Shutting down execution tree."
        exit 0
    fi

    # --- PHASE 3: SERVICE AND METADATA EXTRACTION (HTTPX) ---
    > "$WEB_TARGETS_FILE"
    if [ "$RUN_HTTPX" = true ]; then
        verify_tool "httpx"
        echo "[+] Phase 3: Validating web service liveness and schema mappings via HTTPx..."
        #httpx -l "$TARGETS_FILE" -scheme -silent -H "User-Agent: $UA_STRING" -o "$WEB_TARGETS_FILE"
        httpx -l "$TARGETS_FILE" -scheme -silent -t 20 -H "User-Agent: $UA_STRING" -o "$WEB_TARGETS_FILE"
    else
        while read -r line; do
            if [[ "$line" =~ :80$ ]] || [[ "$line" =~ :8080$ ]]; then echo "http://$line" >> "$WEB_TARGETS_FILE";
            elif [[ "$line" =~ :443$ ]] || [[ "$line" =~ :8443$ ]]; then echo "https://$line" >> "$WEB_TARGETS_FILE"; fi
        done < "$TARGETS_FILE"
    fi

    # --- PHASE 4: APPLICATION CONFIGURATION FUZZING ---
    if [ -s "$WEB_TARGETS_FILE" ]; then
        if [ "$RUN_WHATWEB" = true ]; then
            verify_tool "whatweb"
            echo "[+] Profiling core web component architecture via WhatWeb..."
            whatweb --user-agent="$UA_STRING" -a 1 --log-json="$OUTPUT_DIR/whatweb_findings.json" --input-file="$WEB_TARGETS_FILE" -q
        fi

        if [ "$RUN_SSLSCAN" = true ]; then
            verify_tool "sslscan"
            > "$OUTPUT_DIR/sslscan_findings.xml"
            while read -r line; do
                if [[ "$line" =~ https:// ]] || [[ "$line" =~ :443$ ]]; then
                    clean_host=$(echo "$line" | sed -e 's|https://||' -e 's|http://||')
                    echo "[+] Auditing TLS configuration suite compliance on $clean_host..."
                    sslscan --xml="$OUTPUT_DIR/tmp_ssl.xml" "$clean_host" &>/dev/null
                    if [ -s "$OUTPUT_DIR/tmp_ssl.xml" ]; then
                        cat "$OUTPUT_DIR/tmp_ssl.xml" >> "$OUTPUT_DIR/sslscan_findings.xml"
                        rm "$OUTPUT_DIR/tmp_ssl.xml"
                    fi
                fi
            done < "$WEB_TARGETS_FILE"
        fi

        if [ "$RUN_GOBUSTER" = true ]; then
            verify_tool "gobuster"
            WORDLIST="/usr/share/wordlists/dirb/common.txt"
            if [ ! -f "$WORDLIST" ]; then WORDLIST="/usr/share/dirb/wordlists/common.txt"; fi
            
            echo "[+] Launching web directory wordlist fuzzing via Gobuster..."
            > "$OUTPUT_DIR/gobuster_findings.json"
            while read -r web_target; do
                echo "    [*] Directory forcing: $web_target"
                #gobuster dir -u "$web_target" -w "$WORDLIST" -k -q --no-progress -a "$UA_STRING" -o "$OUTPUT_DIR/tmp_gobuster.txt"
                gobuster dir -u "$web_target" -w "$WORDLIST" -t 15 -b 301,302,403 -k -q --no-progress -a "$UA_STRING" -o "$OUTPUT_DIR/tmp_gobuster.txt"
                if [ -s "$OUTPUT_DIR/tmp_gobuster.txt" ]; then
                    while read -r gob_line; do echo "$web_target $gob_line" >> "$OUTPUT_DIR/gobuster_findings.json"; done < "$OUTPUT_DIR/tmp_gobuster.txt"
                    rm "$OUTPUT_DIR/tmp_gobuster.txt"
                fi
            done < "$WEB_TARGETS_FILE"
        fi

        if [ "$RUN_NIKTO" = true ]; then
            verify_tool "nikto"
            echo "[+] Running web subdirectory structural analysis via Nikto..."
            > "$OUTPUT_DIR/nikto_findings.json"
            while read -r web_target; do
                nikto -h "$web_target" -C all -Format json -useragent "$UA_STRING" -o "$OUTPUT_DIR/tmp_nikto.json" -maxtime 5m &>/dev/null
                if [ -s "$OUTPUT_DIR/tmp_nikto.json" ]; then
                    cat "$OUTPUT_DIR/tmp_nikto.json" >> "$OUTPUT_DIR/nikto_findings.json"
                    rm "$OUTPUT_DIR/tmp_nikto.json"
                fi
            done < "$WEB_TARGETS_FILE"
        fi
    fi

    # --- PHASE 5: ACTIVE EXPLOIT SIGNATURE VALIDATION (NUCLEI) ---
    echo "[+] Phase 5: Triggering vulnerability exploit signature engine via Nuclei..."
    #nuclei -list "$TARGETS_FILE" -as -tags owasp,cve,misconfig -severity info,low,medium,high,critical -H "User-Agent: $UA_STRING" -jsonl -o "$OUTPUT_DIR/nuclei_findings.json" -silent
    nuclei -list "$TARGETS_FILE" -as -tags owasp,cve,misconfig -severity info,low,medium,high,critical -concurrency 10 -mrat 200 -H "User-Agent: $UA_STRING" -jsonl -o "$OUTPUT_DIR/nuclei_findings.json" -silent

    fi # --- END OF SKIP_SCANS RECON BLOCK ---

    #--- PHASE 6: REPORT COMPILATION PIPELINE ---
    
    echo "[+] Phase 6: Compiling all modular outputs into Consolidated_Security_Report.pdf..."
    python3 report_gen.py "$TARGET" 
    "$OUTPUT_DIR/nmap_summary.txt" 
    "$OUTPUT_DIR/whatweb_findings.json" 
    "$OUTPUT_DIR/sslscan_findings.xml" 
    "$OUTPUT_DIR/gobuster_findings.json" 
    "$OUTPUT_DIR/nikto_findings.json" 
    "$OUTPUT_DIR/nuclei_findings.json" 
    "$OUTPUT_DIR/Consolidated_Security_Report.pdf"
