#!/usr/bin/env python3
import sys
import json
import os
from datetime import datetime

# Fallback remediation lookup library for findings lacking native remediation text
FALLBACK_REMEDIATIONS = {
    "a01": "Enforce strict server-side access control mechanisms. Implement the principle of least privilege, disable directory listing, and ensure stateful token verification handles resource claims.",
    "a02": "Utilize robust cryptographic algorithms (AES-256, RSA-4096) and secure key management protocols. Disable legacy protocols like TLS 1.0/1.1 and enforce HSTS across all subdomains.",
    "a03": "Validate and sanitize all incoming parameters using allow-lists. Implement parameterized queries or prepared statements for database interactions to decouple user input from execution context.",
    "a04": "Adopt a secure software development lifecycle (SSDLC). Enforce static and dynamic code review gates, utilize secure code templates, and validate architectural dependencies.",
    "a05": "Audit server and application configurations regularly. Disable default administrative portals, remove debug endpoints, drop verbose error messages, and alter all default credentials.",
    "a06": "Establish a secure patch management program. Update underlying content management systems (CMS), third-party plugins, library binaries, and operational framework dependencies continuously.",
    "a07": "Implement cryptographic nonces, strong session timeouts, and context-aware password strength guidelines. Use multi-factor authentication (MFA) to minimize credential stuffing risks.",
    "a08": "Ensure software updates, build workflows, and continuous integration engines utilize signed updates and verified hash integrity checksums. Sanitize data formats before processing deserialization.",
    "a09": "Implement comprehensive centralized logging ecosystems (SIEM). Log execution anomalies, privilege changes, and authentication updates with enough contextual data to aid forensic response teams.",
    "a10": "Incorporate automated server-side URL validation rules using a strict allow-list. Restrict network egress interfaces from the web application infrastructure toward private loopbacks or internal middleware.",
    "generic": "Review the specific software component documentation, apply the latest stable security patch, and minimize exposed surface areas by closing non-essential ports or application routes."
}

def map_to_owasp(tags, vuln_name, description):
    """Identifies the correct OWASP category based on tags or string mapping."""
    full_text = f"{' '.join(tags)} {vuln_name} {description}".lower()
    
    mapping_rules = {
        "a01:2021-broken access control": (["owasp-a01", "idor", "authz", "directory-listing", "lfi", "traversal"], "a01"),
        "a02:2021-cryptographic failures": (["owasp-a02", "ssl", "tls", "cipher", "crypto", "expired-certificate"], "a02"),
        "a03:2021-injection": (["owasp-a03", "sqli", "xss", "rce", "cmd-injection", "injection"], "a03"),
        "a04:2021-insecure design": (["owasp-a04", "design", "architecture", "business-logic"], "a04"),
        "a05:2021-security misconfiguration": (["owasp-a05", "misconfig", "default-login", "cors", "header"], "a05"),
        "a06:2021-vulnerable and outdated components": (["owasp-a06", "cve", "outdated", "wordpress-plugin", "old-version"], "a06"),
        "a07:2021-identification and authentication failures": (["owasp-a07", "brute-force", "session", "auth-bypass", "weak-password"], "a07"),
        "a08:2021-software and data integrity failures": (["owasp-a08", "deserialization", "jwt", "integrity"], "a08"),
        "a09:2021-security logging and monitoring failures": (["owasp-a09", "log", "monitoring", "audit"], "a09"),
        "a10:2021-server side request forgery (ssrf)": (["owasp-a10", "ssrf", "forgery"], "a10")
    }
    
    for label, (keywords, key) in mapping_rules.items():
        if any(kw in full_text for kw in keywords):
            return label, key
            
    return "infrastructure / unclassified network finding", "generic"

def generate_report(target, nmap_file, whatweb_file, nikto_file, nuclei_file, output_pdf):
    # 1. Parse Nmap Results
    nmap_summary = "No open port data available."
    if os.path.exists(nmap_file):
        with open(nmap_file, 'r') as f:
            nmap_summary = f.read()

    # Initialize OWASP Tracking Counters
    owasp_counts = {f"a{i:02d}": 0 for i in range(1, 11)}
    owasp_counts["generic"] = 0

    # 2. Parse WhatWeb Results
    whatweb_html = ""
    if os.path.exists(whatweb_file) and os.path.getsize(whatweb_file) > 0:
        try:
            with open(whatweb_file, 'r') as f:
                ww_data = json.load(f)
            for target_res in ww_data:
                plugins = target_res.get('plugins', {})
                plugin_items = [f"<li><strong>{k}</strong>: {v.get('version', ['N/A']) if isinstance(v.get('version'), list) else v.get('string', '')}</li>" for k, v in plugins.items()]
                whatweb_html += f"""
                <div class="tech-card">
                    <strong>Target URI:</strong> {target_res.get('target')}<br/>
                    <strong>HTTP Status:</strong> {target_res.get('http_status')}<br/>
                    <ul>{"".join(plugin_items)}</ul>
                </div>
                """
        except Exception as e:
            whatweb_html = f"<p style='color: red;'>Error parsing WhatWeb JSON: {str(e)}</p>"
    else:
        whatweb_html = "<p>No active web technologies fingerprinted.</p>"

    # 3. Parse Nikto Results
    nikto_html = ""
    nikto_count = 0
    if os.path.exists(nikto_file) and os.path.getsize(nikto_file) > 0:
        try:
            with open(nikto_file, 'r') as f:
                nk_data = json.load(f)
            items = nk_data.get('vulnerabilities', [])
            for item in items:
                nikto_count += 1
                msg = item.get('msg', '')
                url_path = item.get('url', 'N/A')
                # Nikto is primarily directory traversal (A01) or misconfiguration (A05)
                owasp_lbl, cat_key = map_to_owasp(["misconfig"], f"Nikto Finding {item.get('id')}", msg)
                owasp_counts[cat_key] += 1
                
                remediation = FALLBACK_REMEDIATIONS.get(cat_key, FALLBACK_REMEDIATIONS["generic"])

                nikto_html += f"""
                <div class="vuln-card severity-medium">
                    <div style="display:flex; justify-content:space-between;">
                        <strong>Nikto Infrastructure Finding: {item.get('id', 'N/A')}</strong>
                        <span class="badge badge-medium">MEDIUM</span>
                    </div>
                    <p><strong>Path/URI Checked:</strong> {url_path}</p>
                    <p><strong>Finding Details:</strong> {msg}</p>
                    <p class="owasp-tag">Mapped Framework: {owasp_lbl.upper()}</p>
                    <div class="remediation-block">
                        <strong>Remediation Strategy:</strong> {remediation}
                    </div>
                </div>
                """
        except Exception as e:
            nikto_html = f"<p style='color: red;'>Error parsing Nikto data stream: {str(e)}</p>"
    
    if nikto_count == 0 and not nikto_html:
        nikto_html = "<p style='color: green;'>✔ No directory leaks or legacy web configuration flaws found by Nikto.</p>"

    # 4. Parse Nuclei Results
    nuclei_html = ""
    nuclei_count = 0
    if os.path.exists(nuclei_file):
        with open(nuclei_file, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    nuclei_count += 1
                    info = data.get('info', {})
                    severity = info.get('severity', 'info').lower()
                    tags = info.get('tags', [])
                    desc = info.get('description', 'No description provided.')
                    name = info.get('name', 'Unknown Vulnerability')
                    
                    owasp_lbl, cat_key = map_to_owasp(tags, name, desc)
                    owasp_counts[cat_key] += 1

                    # Establish resolution workflow string
                    remediation = info.get('remediation')
                    if not remediation:
                        remediation = FALLBACK_REMEDIATIONS.get(cat_key, FALLBACK_REMEDIATIONS["generic"])

                    owasp_badge = f'<span class="badge badge-owasp">{owasp_lbl.split("-")[0].upper()}</span>' if cat_key != "generic" else ""
                    
                    nuclei_html += f"""
                    <div class="vuln-card severity-{severity}">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>{name}</strong>
                            <div>
                                {owasp_badge}
                                <span class="badge badge-{severity}">{severity.upper()}</span>
                            </div>
                        </div>
                        <p><strong>Matched Endpoint:</strong> {data.get('matched-at', data.get('host', 'N/A'))}</p>
                        <p><strong>Vulnerability Summary:</strong> {desc}</p>
                        <div class="remediation-block">
                            <strong>Remediation Strategy:</strong> {remediation}
                        </div>
                    </div>
                    """
                except Exception:
                    continue

    if nuclei_count == 0:
        nuclei_html = "<p style='color: green;'>✔ No exploit signatures or active OWASP Top 10 vulnerabilities flagged.</p>"

    # 5. Build the Dynamic Matrix Table View
    matrix_rows = ""
    owasp_labels_map = {
        "a01": "A01:2021 - Broken Access Control",
        "a02": "A02:2021 - Cryptographic Failures",
