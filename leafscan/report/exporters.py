"""
LeafScan — CSV, HTML Exporters and JSON Schema Validation (Features 25-27)
"""
import csv
import json
from pathlib import Path

# Feature 27: JSON Schema Validation structure
FINDING_SCHEMA = {
    "type": "object",
    "required": ["title", "severity", "vuln_type", "url", "description", "remediation", "evidence"],
    "properties": {
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "vuln_type": {"type": "string"},
        "url": {"type": "string"},
        "description": {"type": "string"},
        "remediation": {"type": "string"},
        "evidence": {"type": "string"},
        "steps": {"type": "string"},
        "poc": {"type": "string"},
        "impact": {"type": "string"},
        "owasp": {"type": "string"}
    }
}

def validate_finding_json(finding):
    """
    Validates a finding structure according to the JSON Schema.
    Returns True if valid, False otherwise.
    """
    for field in FINDING_SCHEMA["required"]:
        if field not in finding:
            return False
    sev = finding.get("severity", "info").lower()
    if sev not in FINDING_SCHEMA["properties"]["severity"]["enum"]:
        return False
    return True

# Feature 25: CSV Exporter
def export_to_csv(findings, output_path):
    """
    Exports scanner findings to a CSV tabular report.
    """
    fields = ["title", "severity", "vuln_type", "url", "description", "remediation", "owasp"]
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)
        return True
    except Exception:
        return False

# Feature 26: HTML Exporter
def export_to_html(target, findings, scan_duration, profile, output_path):
    """
    Exports scanner findings to an interactive, responsive HTML report dashboard.
    """
    findings_list_html = ""
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        badge_color = "#ff4444" if sev == "critical" else "#ff9900" if sev == "high" else "#ffcc00" if sev == "medium" else "#88aaff" if sev == "low" else "#777"
        bg_color = "rgba(255, 68, 68, 0.05)" if sev == "critical" else "rgba(255, 153, 0, 0.05)" if sev == "high" else "rgba(255, 204, 0, 0.05)" if sev == "medium" else "rgba(136, 170, 255, 0.05)" if sev == "low" else "rgba(119, 119, 119, 0.05)"
        
        findings_list_html += f"""
        <div style="background:#fff; border:1px solid #eee; border-left:4px solid {badge_color}; border-radius:8px; padding:20px; margin-bottom:16px; box-shadow:0 2px 4px rgba(0,0,0,0.02);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <span style="background:{bg_color}; color:{badge_color}; padding:4px 10px; border-radius:4px; font-size:0.75rem; font-weight:700; text-transform:uppercase;">{sev}</span>
                <span style="color:#888; font-size:0.8rem; font-family:monospace;">{f.get('vuln_type', 'Unknown')} · {f.get('owasp', 'N/A')}</span>
            </div>
            <h3 style="margin:0 0 8px 0; font-size:1.1rem; color:#111;">Finding #{idx}: {f.get('title')}</h3>
            <p style="color:#555; font-size:0.9rem; line-height:1.5; margin:0 0 12px 0;"><strong>Description:</strong> {f.get('description')}</p>
            <p style="color:#555; font-size:0.9rem; line-height:1.5; margin:0 0 12px 0;"><strong>Target URL:</strong> <a href="{f.get('url')}" target="_blank" style="color:#00bb44; text-decoration:none; word-break:break-all;">{f.get('url')}</a></p>
            <div style="background:#f9f9f9; border-radius:6px; padding:12px; margin-bottom:12px; font-family:monospace; font-size:0.8rem; overflow-x:auto; border:1px solid #eaeaea;">
                <strong>Evidence:</strong><br>{f.get('evidence', 'No evidence captured.')}
            </div>
            <p style="color:#444; font-size:0.9rem; line-height:1.5; margin:0;"><strong>Remediation:</strong> {f.get('remediation')}</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>LeafScan v2.1.5 Security Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background:#f5f7fa; color:#333; margin:0; padding:40px 20px; }}
        .container {{ max-width:800px; margin:0 auto; }}
        header {{ background:#111; color:#fff; padding:30px; border-radius:12px; margin-bottom:24px; box-shadow:0 4px 12px rgba(0,0,0,0.05); }}
        h1 {{ margin:0 0 8px 0; font-size:1.8rem; font-weight:800; color:#00ff55; }}
        .meta-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; font-size:0.85rem; color:#aaa; margin-top:16px; border-top:1px solid #222; padding-top:16px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌿 LeafScan Security Report</h1>
            <p style="margin:0; color:#888;">Continuous Bug Bounty Scanner Dashboard</p>
            <div class="meta-grid">
                <div><strong>Target:</strong> {target}</div>
                <div><strong>Profile:</strong> {profile}</div>
                <div><strong>Scan Duration:</strong> {scan_duration:.2f}s</div>
                <div><strong>Total Findings:</strong> {len(findings)}</div>
            </div>
        </header>

        <div>
            {findings_list_html if findings else '<div style="background:#fff; border-radius:12px; padding:40px; text-align:center; box-shadow:0 4px 6px rgba(0,0,0,0.02);"><h3 style="margin:0 0 8px 0; color:#00bb44;">✓ Clean Scan</h3><p style="margin:0; color:#777;">No vulnerabilities detected on the target.</p></div>'}
        </div>
    </div>
</body>
</html>
"""
    try:
        Path(output_path).write_text(html, encoding="utf-8")
        return True
    except Exception:
        return False
