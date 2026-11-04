#!/usr/bin/env python3
import sys
import json
import os
from datetime import datetime

def generate_report(target, nmap_file, nuclei_file, output_pdf):
    # Read Nmap raw results
    nmap_summary = "No open port data available."
    if os.path.exists(nmap_file):
        with open(nmap_file, 'r') as f:
            nmap_summary = f.read()

    # Parse Nuclei JSON alerts
    vulns_html = ""
    vuln_count = 0
    if os.path.exists(nuclei_file):
        with open(nuclei_file, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    vuln_count += 1
                    info = data.get('info', {})
                    severity = info.get('severity', 'info').lower()
                    
                    vulns_html += f"""
                    <div class="vuln-card severity-{severity}">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>{info.get('name', 'Unknown Vulnerability')}</strong>
                            <span class="badge badge-{severity}">{severity.upper()}</span>
                        </div>
                        <p><strong>Target URL/Service:</strong> {data.get('matched-at', data.get('host', 'N/A'))}</p>
                        <p><strong>Description:</strong> {info.get('description', 'No description provided.')}</p>
                        {"<p><strong>Remediation:</strong> " + info.get('remediation') + "</p>" if info.get('remediation') else ""}
                    </div>
                    """
                except Exception:
                    continue

    if vuln_count == 0:
        vulns_html = "<p style='color: green;'>✔ No application-level or CVE vulnerabilities were discovered.</p>"

    # HTML Layout Strategy for WeasyPrint Print Layouts
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <style>
        @page {{ size: letter; margin: 20mm; @bottom-right {{ content: counter(page); font-size: 10px; color: #777; }} }}
        body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #2b2d42; line-height: 1.5; font-size: 14px; }}
        h1 {{ color: #1d3557; font-size: 26px; border-bottom: 3px solid #1d3557; padding-bottom: 8px; margin-bottom: 20px; }}
        h2 {{ color: #457b9d; font-size: 18px; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; break-after: avoid; }}
        .meta-table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; font-size: 13px; }}
        .meta-table th, .meta-table td {{ border: 1px solid #e5e5e5; padding: 10px; text-align: left; }}
        .meta-table th {{ background-color: #f8f9fa; color: #1d3557; width: 25%; }}
        .vuln-card {{ border: 1px solid #e0e0e0; border-left: 5px solid #ccc; padding: 15px; margin-bottom: 15px; break-inside: avoid; background-color: #fafafa; }}
        .severity-critical {{ border-left-color: #e63946; background-color: #fff5f5; }}
        .severity-high {{ border-left-color: #f4a261; background-color: #fff9f5; }}
        .severity-medium {{ border-left-color: #e9c46a; background-color: #fffdf5; }}
        .severity-low {{ border-left-color: #a8dadc; background-color: #f4fbfb; }}
        .severity-info {{ border-left-color: #4ea8de; background-color: #f4faff; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; text-transform: uppercase; }}
        .badge-critical {{ background-color: #e63946; }}
        .badge-high {{ background-color: #f4a261; }}
        .badge-medium {{ background-color: #e9c46a; color: #333; }}
        .badge-low {{ background-color: #a8dadc; color: #333; }}
        .badge-info {{ background-color: #4ea8de; }}
        pre {{ background-color: #1d3557; color: #f1faee; padding: 12px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 12px; white-space: pre-wrap; }}
        .disclaimer {{ font-size: 10px; color: #888; text-align: center; margin-top: 40px; border-top: 1px dashed #ccc; padding-top: 10px; }}
    </style>
    </head>
    <body>
        <h1>Vulnerability Assessment Summary</h1>
        <table class="meta-table">
            <tr><th>Target Host</th><td><strong>{target}</strong></td></tr>
            <tr><th>Scan Timeline</th><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><th>Total Vulnerabilities</th><td>{vuln_count} alerts raised</td></tr>
        </table>
        
        <h2>1. Infrastructure & Port Discovery</h2>
        <p>Active services running on target architecture mapped via stealth scan:</p>
        <pre>{nmap_summary.strip()}</pre>
        
        <h2>2. Target Software Vulnerabilities (CVE Engine)</h2>
        {vulns_html}

        <div class="disclaimer">
            This is for informational purposes only. For medical advice or diagnosis, consult a professional. AI responses may include mistakes.
        </div>
    </body>
    </html>
    """

    # Render directly out to production ready PDF file via Weasyprint
    try:
        import weasyprint
        weasyprint.HTML(string=html_content).write_pdf(output_pdf)
        print(f"[+] Consolidated PDF Report cleanly exported to: {output_pdf}")
    except ImportError:
        print("[!] Error: Python dependency 'weasyprint' missing. Please run: pip install weasyprint")

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: python3 report_gen.py <target> <nmap_txt> <nuclei_json> <out_pdf>")
        sys.exit(1)
    generate_report(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
