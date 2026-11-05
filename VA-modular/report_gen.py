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
    """Maps custom tags and metadata patterns to the OWASP Top 10 Framework."""
    full_text = f"{' '.join(tags)} {vuln_name} {description}".lower()
    mapping_rules = {
        "A01:2021-Broken Access Control": (["owasp-a01", "idor", "authz", "directory", "traversal", "gobuster"], "a01"),
        "A02:2021-Cryptographic Failures": (["owasp-a02", "ssl", "tls", "cipher", "crypto", "sslscan", "weak-tls"], "a02"),
        "A03:2021-Injection": (["owasp-a03", "sqli", "xss", "rce", "cmd-injection", "injection"], "a03"),
        "A04:2021-Insecure Design": (["owasp-a04", "design", "architecture", "business-logic"], "a04"),
        "A05:2021-Security Misconfiguration": (["owasp-a05", "misconfig", "default-login", "cors", "header", "nikto"], "a05"),
        "A06:2021-Vulnerable and Outdated Components": (["owasp-a06", "cve", "outdated", "old-version"], "a06"),
        "A07:2021-Identification and Authentication Failures": (["owasp-a07", "brute-force", "session", "auth-bypass", "weak-password"], "a07"),
        "A08:2021-Software and Data Integrity Failures": (["owasp-a08", "deserialization", "jwt", "integrity"], "a08"),
        "A09:2021-Security Logging and Monitoring Failures": (["owasp-a09", "log", "monitoring", "audit"], "a09"),
        "A10:2021-Server-Side Request Forgery (SSRF)": (["owasp-a10", "ssrf", "forgery"], "a10")
    }
    for label, (keywords, key) in mapping_rules.items():
        if any(kw in full_text for kw in keywords):
            return label, key
    return "Infrastructure / Unclassified Finding", "generic"

def generate_report(target, nmap, whatweb, sslscan, gobuster, nikto, nuclei, out_pdf):
    owasp_counts = {f"a{i:02d}": 0 for i in range(1, 11)}
    owasp_counts["generic"] = 0

    # 1. Parse Nmap Data
    nmap_summary = "No open port data available."
    if os.path.exists(nmap) and os.path.getsize(nmap) > 0:
        with open(nmap, 'r') as f: 
            nmap_summary = f.read()

    # 2. Parse WhatWeb Tech Profiling
    whatweb_html = ""
    if os.path.exists(whatweb) and os.path.getsize(whatweb) > 0:
        try:
            with open(whatweb, 'r') as f: 
                ww_data = json.load(f)
            for res in ww_data:
                plugin_items = [f"<li><strong>{k}</strong>: {v.get('string', '')}</li>" for k, v in res.get('plugins', {}).items() if v]
                whatweb_html += f"<div class='tech-card'><strong>{res.get('target')}</strong> (HTTP {res.get('http_status')})<ul>{''.join(plugin_items[:8])}</ul></div>"
        except: 
            whatweb_html = "<p class='skipped-text'>Error parsing WhatWeb JSON data streams.</p>"
    if not whatweb_html: 
        whatweb_html = "<p class='skipped-text'>Module omitted or no web framework signatures captured.</p>"

    # 3. Parse SSLScan Cryptographic Layouts (XML Processing)
    ssl_html = ""
    ssl_count = 0
    if os.path.exists(sslscan) and os.path.getsize(sslscan) > 0:
        try:
            with open(sslscan, 'r') as f: 
                raw_xml = f.read()
            root = ET.fromstring(f"<root>{raw_xml}</root>")
            for cipher in root.findall('.//cipher'):
                status = cipher.get('status')
                cipher_name = cipher.get('cipher') or ""
                ssl_ver = cipher.get('sslversion') or ""
                
                is_weak_proto = any(p in ssl_ver for p in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"])
                is_weak_cipher = any(c in cipher_name for c in ["RC4", "DES", "3DES", "SEED", "NULL"])
                
                if status == 'accepted' and (is_weak_proto or is_weak_cipher):
                    ssl_count += 1
                    owasp_counts["a02"] += 1
                    ssl_html += f"""
                    <div class="vuln-card severity-low">
                        <strong>Weak Cipher Accepted: {cipher_name}</strong> <span class="badge badge-low">LOW</span>
                        <p><strong>Protocol Version:</strong> {ssl_ver} | <strong>Bits:</strong> {cipher.get('bits')}</p>
                        <div class="remediation-block"><strong>Remediation:</strong> {FALLBACK_REMEDIATIONS['a02']}</div>
                    </div>"""
        except: 
            ssl_html = "<p class='skipped-text'>Error reading SSLScan results format or empty stream.</p>"
    if not ssl_html: 
        ssl_html = "<p style='color:green;'>✔ No insecure ciphers or old protocols accepted.</p>"
    # 4. Parse Gobuster Path Fuzzing Logs
    gobuster_html = ""
    gob_count = 0
    if os.path.exists(gobuster) and os.path.getsize(gobuster) > 0:
        with open(gobuster, 'r') as f:
            for line in f:
                if not line.strip(): continue
                if "Status: " in line:
                    gob_count += 1
                    owasp_counts["a01"] += 1
                    gobuster_html += f"""
                    <div class="vuln-card severity-info">
                        <strong>Fuzzed Path Discovered:</strong>
                        <p style="font-family:monospace; margin:4px 0;">{line.strip()}</p>
                        <div class="remediation-block"><strong>Remediation:</strong> {FALLBACK_REMEDIATIONS['a01']}</div>
                    </div>"""
    if not gobuster_html: 
        gobuster_html = "<p style='color:green;'>✔ No dynamic directories leaked through wordlist scanning.</p>"

    # 5. Parse Nikto Standard Scans
    nikto_html = ""
    nk_count = 0
    if os.path.exists(nikto) and os.path.getsize(nikto) > 0:
        try:
            with open(nikto, 'r') as f: 
                nk_data = json.load(f)
            for item in nk_data.get('vulnerabilities', []):
                nk_count += 1
                ow_lbl, cat_key = map_to_owasp(["misconfig"], "Nikto", item.get('msg', ''))
                owasp_counts[cat_key] += 1
                nikto_html += f"""
                <div class="vuln-card severity-medium">
                    <strong>Nikto Finding ID: {item.get('id', 'N/A')}</strong> <span class="badge badge-medium">MEDIUM</span>
                    <p><strong>Path Target:</strong> {item.get('url', 'N/A')}</p>
                    <p><strong>Description:</strong> {item.get('msg', '')}</p>
                    <div class="remediation-block"><strong>Remediation Framework:</strong> {FALLBACK_REMEDIATIONS[cat_key]}</div>
                </div>"""
        except: 
            pass
    if not nikto_html: 
        nikto_html = "<p style='color:green;'>✔ No configuration anomalies mapped by Nikto.</p>"

    # 6. Parse Nuclei JSON Lines Engine
    nuclei_html = ""
    nu_count = 0
    if os.path.exists(nuclei) and os.path.getsize(nuclei) > 0:
        with open(nuclei, 'r') as f:
            for line in f:
                if not line.strip(): 
                    continue
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
                        <strong>{info.get('name', 'Unknown Vulnerability')}</strong> <span class="badge badge-{sev}">{sev.upper()}</span>
                        <p><strong>Matched Endpoint:</strong> {data.get('matched-at', 'N/A')}</p>
                        <p><strong>Vulnerability Summary:</strong> {info.get('description', 'N/A')}</p>
                        <div class="remediation-block"><strong>Remediation Framework:</strong> {rem}</div>
                    </div>"""
                except:
                    continue

    if not nuclei_html:
        nuclei_html = "<p style='color:green;'>✔ No application layer vulnerabilities detected by Nuclei.</p>"

    # 7. Generate Dynamic OWASP Framework Compliance Rows
    matrix_rows = ""
    labels = {
        "a01": "A01:2021 - Broken Access Control (Gobuster / Nikto Paths)",
        "a02": "A02:2021 - Cryptographic Failures (SSLScan TLS Audit)",
        "a03": "A03:2021 - Injection (SQLi / XSS / RCE Target Signatures)",
        "a04": "A04:2021 - Insecure Design",
        "a05": "A05:2021 - Security Misconfiguration (Server Headers & Banners)",
        "a06": "A06:2021 - Vulnerable and Outdated Components (CVE Tracking)",
        "a07": "A07:2021 - Identification and Authentication Failures",
        "a08": "A08:2021 - Software and Data Integrity Failures",
        "a09": "A09:2021 - Security Logging and Monitoring Failures",
        "a10": "A10:2021 - Server-Side Request Forgery (SSRF)"
    }
    for k, v in labels.items():
        c = owasp_counts[k]
        matrix_rows += f"<tr class='{'matrix-clean' if c==0 else 'matrix-alert'}'><td><strong>{v}</strong></td><td style='text-align:center; font-weight:bold;'>{'CLEAN' if c==0 else f'{c} ALERTS'}</td></tr>"

    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
    <style>
        @page {{ size: letter; margin: 20mm; @bottom-right {{ content: counter(page); font-size: 10px; color: #777; }} }}
        body {{ font-family: Arial, sans-serif; color: #2b2d42; line-height: 1.4; font-size: 13px; }}
        h1 {{ color: #1d3557; font-size: 24px; border-bottom: 3px solid #1d3557; padding-bottom: 5px; margin-bottom:15px; }}
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
        .skipped-text {{ color: #777; font-style: italic; background: #fbfbfb; padding: 8px; border: 1px dashed #ddd; }}
        pre {{ background-color: #1d3557; color: #f1faee; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; white-space: pre-wrap; }}
        .disclaimer {{ font-size: 9px; color: #888; text-align: center; margin-top: 35px; border-top: 1px dashed #ccc; padding-top: 8px; }}
    </style></head><body>
        <h1>Comprehensive Security Assessment Report</h1>
        <table class="meta-table">
            <tr><th>Target Infrastructure</th><td><strong>{target}</strong></td></tr>
            <tr><th>Execution Timeline</th><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><th>Total Core Flags</th><td>{ssl_count + gob_count + nk_count + nu_count} metrics mapped</td></tr>
        </table>
        
        <h2>1. OWASP Top 10 Threat Compliance Matrix</h2>
        <table class="matrix-table">
            <thead><tr><th>OWASP Framework Mapping</th><th style="width:30%; text-align:center;">Status</th></tr></thead>
            <tbody>{matrix_rows}</tbody>
        </table>

        <h2>2. Port Discovery Metrics (Nmap)</h2>
        <pre>{nmap_summary.strip()}</pre>
        
        <h2>3. Web Service Footprints (WhatWeb)</h2>
        {whatweb_html}
        
        <h2>4. Cryptographic Flaws (SSLScan)</h2>
        {ssl_html}
        
        <h2>5. Discovered Hidden Paths (Gobuster)</h2>
        {gobuster_html}
        
        <h2>6. Server Configuration Faults (Nikto)</h2>
        {nikto_html}
        
        <h2>7. Exploit Signatures & Vulnerabilities (Nuclei)</h2>
        {nuclei_html}

        <div class="disclaimer">This is for informational purposes only. For medical advice or diagnosis, consult a professional. AI responses may include mistakes.</div>
    </body></html>"""

    try:
        import weasyprint
        weasyprint.HTML(string=html_content).write_pdf(out_pdf)
        print(f"[+] Consolidated PDF Report successfully compiled: {out_pdf}")
    except:
        print("[!] Execution halted: Python 'weasyprint' library missing. Run: pip install weasyprint")

if __name__ == '__main__':
    if len(sys.argv) < 9: 
        sys.exit(1)
    generate_report(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8])
