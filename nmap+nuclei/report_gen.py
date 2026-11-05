#!/usr/bin/env python3
import sys
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

FALLBACK_REMEDIATIONS = {
    "a01": "Enforce strict server-side access control. Disable directory browsing, remove exposed development backup directories, and restrict path navigation requests via strong authorization configurations.",
    "a02": "Upgrade TLS endpoint parameter suites. Disable insecure cryptographic algorithms (SSLv2/v3, TLS 1.0/1.1), deploy robust cipher configurations (AES-GCM/CHACHA20), and renew expired certificates.",
    "a03": "Validate and filter all operational string input vectors against strict allow-lists. Implement parameterized query layers to fully block SQL, command, and cross-site scripting (XSS) input vectors.",
    "a04": "Adopt security-by-design architectures. Routinely audit application business workflows, establish limit validation parameters, and run static source composition testing tools.",
    "a05": "Harden running environment layers. Strip descriptive default HTTP banner strings, remove template debugging paths, alter default login configurations, and enforce security headers (HSTS, CSP).",
    "a06": "Establish strict library asset management rules. Update outdated server components, apply continuous firmware patches, and remove legacy unmaintained applications.",
    "a07": "Enforce context-aware access validation frameworks. Deploy multi-factor authentication (MFA), block automated brute-forcing with progressive rate limiting, and securely roll session identifiers.",
    "a08": "Verify object composition layers before run-time compilation. Implement cryptographic checksum validations over continuous update blocks and safely isolate deserialization actions.",
    "a09": "Consolidate host execution metrics into a centralized SIEM hub. Ensure privilege shifts, authentication responses, and system input errors are retained with detailed forensic timestamps.",
    "a10": "Incorporate rigid server-side destination validation schemas. Maintain loopback network address drops, prevent metadata environment network routing, and filter outgoing connection requests.",
    "generic": "Review the specific software component version documentation, apply the latest patch updates, and isolate exposed interfaces using local firewall blocks."
}

def map_to_owasp(tags, vuln_name, description):
    full_text = f"{' '.join(tags)} {vuln_name} {description}".lower()
    mapping_rules = {
        "a01:2021-broken access control": (["owasp-a01", "idor", "authz", "directory", "traversal", "gobuster", "status:200"], "a01"),
        "a02:2021-cryptographic failures": (["owasp-a02", "ssl", "tls", "cipher", "crypto", "sslscan", "weak-tls"], "a02"),
        "a03:2021-injection": (["owasp-a03", "sqli", "xss", "rce", "cmd-injection", "injection"], "a03"),
        "a04:2021-insecure design": (["owasp-a04", "design", "architecture", "business-logic"], "a04"),
        "a05:2021-security misconfiguration": (["owasp-a05", "misconfig", "default-login", "cors", "header", "nikto"], "a05"),
        "a06:2021-vulnerable and outdated components": (["owasp-a06", "cve", "outdated", "old-version"], "a06"),
        "a07:2021-identification and authentication failures": (["owasp-a07", "brute-force", "session", "auth-bypass", "weak-password"], "a07"),
        "a08:2021-software and data integrity failures": (["owasp-a08", "deserialization", "jwt", "integrity"], "a08"),
        "a09:2021-security logging and monitoring failures": (["owasp-a09", "log", "monitoring", "audit"], "a09"),
        "a10:2021-server side request forgery (ssrf)": (["owasp-a10", "ssrf", "forgery"], "a10")
    }
    for label, (keywords, key) in mapping_rules.items():
        if any(kw in full_text for kw in keywords):
            return label, key
    return "infrastructure / unclassified network finding", "generic"

def generate_report(target, nmap, whatweb, sslscan, gobuster, nikto, nuclei, out_pdf):
    owasp_counts = {f"a{i:02d}": 0 for i in range(1, 11)}
    owasp_counts["generic"] = 0

    # 1. Parse Nmap
    nmap_summary = "No open port data available."
    if os.path.exists(nmap):
        with open(nmap, 'r') as f: nmap_summary = f.read()

    # 2. Parse WhatWeb
    whatweb_html = ""
    if os.path.exists(whatweb) and os.path.getsize(whatweb) > 0:
        try:
            with open(whatweb, 'r') as f: ww_data = json.load(f)
            for res in ww_data:
                plugin_items = [f"<li><strong>{k}</strong>: {v.get('string', '')}</li>" for k, v in res.get('plugins', {}).items() if v]
                whatweb_html += f"<div class='tech-card'><strong>{res.get('target')}</strong> (HTTP {res.get('http_status')})<ul>{''.join(plugin_items[:8])}</ul></div>"
        except: whatweb_html = "<p>Error parsing WhatWeb JSON.</p>"
    else: whatweb_html = "<p>No web applications fingerprinted.</p>"

    # 3. Parse SSLScan (XML Integration)
    ssl_html = ""
    ssl_count = 0
    if os.path.exists(sslscan) and os.path.getsize(sslscan) > 0:
        try:
            # Wrap files in a mock root node to maintain compatibility across loops
            with open(sslscan, 'r') as f: raw_xml = f.read()
            root = ET.fromstring(f"<root>{raw_xml}</root>")
            for cipher in root.findall('.//cipher'):
                if cipher.get('status') == 'accepted' and ('DES' in cipher.get('cipher') || 'RC4' in cipher.get('cipher') || 'TLSv1.0' in cipher.get('sslversion')):
                    ssl_count += 1
                    owasp_counts["a02"] += 1
                    ssl_html += f"""
                    <div class="vuln-card severity-low">
                        <strong>Weak Cipher Accepted: {cipher.get('cipher')}</strong> <span class="badge badge-low">LOW</span>
                        <p><strong>Protocol Version:</strong> {cipher.get('sslversion')} | <strong>Bits:</strong> {cipher.get('bits')}</p>
                        <div class="remediation-block"><strong>Remediation:</strong> {FALLBACK_REMEDIATIONS['a02']}</div>
                    </div>"""
        except Exception as e: ssl_html = f"<p>SSLScan Parsing skipped or empty results: {str(e)}</p>"
    if not ssl_html: ssl_html = "<p style='color:green;'>✔ No insecure ciphers or old protocols accepted.</p>"

    # 4. Parse Gobuster (Directory Fuzzing Integration)
    gobuster_html = ""
    gob_count = 0
    if os.path.exists(gobuster) and os.path.getsize(gobuster) > 0:
        with open(gobuster, 'r') as f:
            for line in f:
                if not line.strip(): continue
                parts = line.strip().split("Status: ")
                if len(parts) >= 2 and "404" not in parts[1]:
                    gob_count += 1
                    owasp_counts["a01"] += 1
                    path_found = parts[0].strip()
                    gobuster_html += f"""
                    <div class="vuln-card severity-info">
                        <strong>Fuzzed Path Discovered: {path_found}</strong> <span class="badge badge-info">DISCOVERED</span>
                        <p><strong>Server Mapping Context response status:</strong> {parts[1]}</p>
                        <div class="remediation-block"><strong>Remediation:</strong> {FALLBACK_REMEDIATIONS['a01']}</div>
                    </div>"""
    if not gobuster_html: gobuster_html = "<p style='color:green;'>✔ No unusual directories leaked through common dictionary scanning.</p>"

    # 5. Parse Nikto
    nikto_html = ""
    nk_count = 0
    if os.path.exists(nikto) and os.path.getsize(nikto) > 0:
        try:
            with open(nikto, 'r') as f: nk_data = json.load(f)
            for item in nk_data.get('vulnerabilities', []):
                nk_count += 1
                ow_lbl, cat_key = map_to_owasp(["misconfig"], "Nikto", item.get('msg', ''))
                owasp_counts[cat_key] += 1
                nikto_html += f"""
                <div class="vuln-card severity-medium">
                    <strong>Nikto Finding: {item.get('id')}</strong> <span class="badge badge-medium">MEDIUM</span>
                    <p><strong>Path:</strong> {item.get('url')} | {item.get('msg')}</p>
                    <div class="remediation-block"><strong>Remediation:</strong> {FALLBACK_REMEDIATIONS[cat_key]}</div>
                </div>"""
        except: pass
    if not nikto_html: nikto_html = "<p style='color:green;'>✔ No web framework errors mapped by Nikto.</p>"

    # 6. Parse Nuclei
    nuclei_html = ""
    nu_count = 0
    if os.path.exists(nuclei):
        with open(nuclei, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    nu_count += 1
                    info = data.get('info', {})
                    sev = info.get('severity', 'info').lower()
                    ow_lbl, cat_key = map_to_owasp(info.get('tags', []), info.get('name', ''), info.get('description', ''))
                    owasp_counts[cat_key] += 1
                    rem = info.get('remediation') or FALLBACK_REMEDIATIONS[cat_key]
                    
                    nuclei_html += f"""
                    <div class="vuln-card severity-{sev}">
                        <strong>{info.get('name')}</strong> <span class="badge badge-{sev}">{sev.upper()}</span>
                        <p><strong>Endpoint:</strong> {data.get('matched-at')}</p>
                        <p><strong>Description:</strong> {info.get('description', 'N/A')}</p>
                        <div class="remediation-block"><strong>Remediation:</strong> {rem}</div>
                    </div>"""
                except: continue
    if not nuclei_html: nuclei_html = "<p style='color:green;'>✔ No high severity signatures flagged by Nuclei.</p>"

    # 7. Generate Matrix Table Layout
    matrix_rows = ""
    labels = {
        "a01": "A01:2021 - Broken Access Control (Gobuster / Nikto Paths)",
        "a02": "A02:2021 - Cryptographic Failures (SSLScan Auditing)",
        "a03": "A03:2021 - Injection (SQLi / XSS / RCE Exploits)",
        "a04": "A04:2021 - Insecure Design",
        "a05": "A05:2021 - Security Misconfiguration",
        "a06": "A06:2021 - Vulnerable and Outdated Components",
        "a07": "A07:2021 - Identification and Authentication Failures",
        "a08": "A08:2021 - Software and Data Integrity Failures",
        "a09": "A09:2021 - Security Logging and Monitoring Failures",
        "a10": "A10:2021 - Server-Side Request Forgery (SSRF)"
}
for k, v in labels.items():
c = owasp_counts[k]
matrix_rows += f"<tr class='{'matrix-clean' if c==0 else 'matrix-alert'}'>{v}{'CLEAN' if c==0 else f'{c} ALERTS'}"
html_content = f"""

@page {{ size: letter; margin: 20mm; @bottom-right {{ content: counter(page); font-size: 10px; color: #777; }} }}
body {{ font-family: Arial, sans-serif; color: #2b2d42; line-height: 1.4; font-size: 13px; }}
h1 {{ color: #1d3557; font-size: 24px; border-bottom: 3px solid #1d3557; padding-bottom: 5px; }}
h2 {{ color: #457b9d; font-size: 16px; margin-top: 25px; border-bottom: 1px solid #ddd; padding-bottom: 3px; break-after: avoid; }}
.meta-table, .matrix-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
.meta-table th, .meta-table td, .matrix-table th, .matrix-table td {{ border: 1px solid #e5e5e5; padding: 8px; text-align: left; }}
.meta-table th, .matrix-table th {{ background-color: #f8f9fa; color: #1d3557; }}
.matrix-clean {{ background-color: #f4fbfb; color: #2a6f97; }}
.matrix-alert {{ background-color: #fff5f5; color: #e63946; }}
.tech-card {{ background-color: #f8f9fa; border: 1px solid #e0e0e0; padding: 10px; margin-bottom: 5px; break-inside: avoid; }}
.vuln-card {{ border: 1px solid #e0e0e0; border-left: 5px solid #ccc; padding: 12px; margin-bottom: 12px; break-inside: avoid; background-color: #fafafa; }}
.severity-critical {{ border-left-color: #e63946; background-color: #fff5f5; }}
.severity-high {{ border-left-color: #f4a261; background-color: #fff9f5; }}
.severity-medium {{ border-left-color: #e9c46a; background-color: #fffdf5; }}
.severity-low {{ border-left-color: #a8dadc; background-color: #f4fbfb; }}
.severity-info {{ border-left-color: #4ea8de; background-color: #f4faff; }}
.badge {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; color: #fff; text-transform: uppercase; float: right; }}
.badge-critical {{ background-color: #e63946; }}
.badge-high {{ background-color: #f4a261; }}
.badge-medium {{ background-color: #e9c46a; color:#333; }}
.badge-low {{ background-color: #a8dadc; color:#333; }}
.badge-info {{ background-color: #4ea8de; }}
.remediation-block {{ margin-top: 8px; padding: 8px; background-color: #edf2f4; border-left: 3px solid #457b9d; font-size: 12px; }}
pre {{ background-color: #1d3557; color: #f1faee; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; white-space: pre-wrap; }}
.disclaimer {{ font-size: 9px; color: #888; text-align: center; margin-top: 35px; border-top: 1px dashed #ccc; padding-top: 8px; }}
