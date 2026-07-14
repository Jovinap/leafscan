"""
Leaf — Evidence Report Generator
Creates structured, evidence-backed vulnerability reports
"""
import json
import os
from datetime import datetime
from pathlib import Path

CVSS_BASE = {
    "critical": 9.5,
    "high":     8.0,
    "medium":   5.5,
    "low":      3.0,
    "info":     0.0,
}

CVSS_VECTOR = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high":     "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "medium":   "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low":      "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info":     "AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}

def generate_report_id():
    return f"LS-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

def get_framework_mappings(vuln_type, title):
    import os
    import re
    
    mappings = {}
    skills_dir = Path("/home/kali/.gemini/antigravity/scratch/leaf/.agents/skills")
    if not skills_dir.exists():
        skills_dir = Path(".agents/skills")
        if not skills_dir.exists():
            return mappings

    keywords = ["xss", "sqli", "port", "header", "cors", "ip address", "token", "key", "disclosure", "secret", "password", "tls", "ssl", "dns", "sitemap", "robots"]
    match_targets = f"{vuln_type} {title}".lower()
    matched_kws = [k for k in keywords if k in match_targets]
    
    if "sql" in match_targets:
        matched_kws.append("sql")
    if "cookie" in match_targets:
        matched_kws.append("cookie")

    try:
        for folder in skills_dir.iterdir():
            if not folder.is_dir():
                continue
            
            folder_name = folder.name.lower()
            if any(kw in folder_name for kw in matched_kws):
                skill_file = folder / "SKILL.md"
                if skill_file.exists():
                    with open(skill_file, "r", encoding="utf-8") as f:
                        frontmatter = []
                        lines = f.readlines()
                        in_fm = False
                        for line in lines:
                            stripped = line.strip()
                            if stripped == "---":
                                if not in_fm:
                                    in_fm = True
                                    continue
                                else:
                                    break
                            if in_fm:
                                frontmatter.append(stripped)
                        
                        for fm_line in frontmatter:
                            if ":" in fm_line:
                                key, val = fm_line.split(":", 1)
                                key = key.strip().lower()
                                val = val.strip().strip("'\"[]")
                                if not val:
                                    continue
                                if key == "mitre_attack":
                                    mappings["MITRE ATT&CK"] = val
                                elif key == "nist_csf":
                                    mappings["NIST CSF 2.0"] = val
                                elif key == "mitre_f3":
                                    mappings["MITRE F3 (Fraud)"] = val
                                elif key == "d3fend":
                                    mappings["MITRE D3FEND"] = val
                                elif key == "atlas":
                                    mappings["MITRE ATLAS"] = val
                                elif key == "ai_rmf":
                                    mappings["NIST AI RMF"] = val
                if mappings:
                    break
    except Exception:
        pass
        
    return mappings


def build_finding_md(f, idx):
    sev  = f.get("severity","info").upper()
    cvss = CVSS_BASE.get(f.get("severity","info"), 0.0)
    vec  = CVSS_VECTOR.get(f.get("severity","info"), "")
    
    # Extract framework mappings
    mappings = get_framework_mappings(f.get("vuln_type",""), f.get("title",""))
    mappings_block = ""
    if mappings:
        mappings_block = "\n### Framework & Compliance Mappings\n| Framework | Mapping ID |\n|---|---|\n"
        for fw, fwid in mappings.items():
            mappings_block += f"| {fw} | `{fwid}` |\n"
            
    return f"""
## Finding #{idx}: {f.get('title','Untitled')}

| Field | Value |
|---|---|
| **Severity** | `{sev}` |
| **Type** | {f.get('vuln_type','Unknown')} |
| **CVSS 3.1 Score** | {cvss} (`{vec}`) |
| **URL** | `{f.get('url','')}` |

### Description
{f.get('description', 'No description.')}

{mappings_block}

### Steps to Reproduce
{f.get('steps', 'No steps provided.')}

### Proof of Concept
```
{f.get('poc', 'N/A')}
```

### Evidence
```
{f.get('evidence', 'No evidence captured.')}
```

### Impact
{f.get('impact', 'No impact description.')}

---
"""

def generate_markdown_report(target, findings, scan_duration, profile, config=None):
    """Generate a full markdown report with all findings and evidence"""
    from leaf import __version__, __author__, __company__, __github__

    report_id = generate_report_id()
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    summary = {s: 0 for s in ("critical","high","medium","low","info")}
    for f in findings:
        sev = f.get("severity","info").lower()
        if sev in summary:
            summary[sev] += 1

    # Header
    md = f"""# Leaf Security Report
**Report ID:** `{report_id}`  
**Target:** `{target}`  
**Generated:** {now}  
**Scanner:** Leaf v{__version__} by {__author__} ({__company__})  
**GitHub:** {__github__}  
**Duration:** {scan_duration:.1f}s · **Profile:** {profile}  

---

## Executive Summary

| Severity | Count |
|---|---|
| 🔴 Critical | {summary['critical']} |
| 🟠 High | {summary['high']} |
| 🟡 Medium | {summary['medium']} |
| 🔵 Low | {summary['low']} |
| ⚪ Info | {summary['info']} |
| **Total** | **{len(findings)}** |

"""

    if not findings:
        md += "> ✅ **No vulnerabilities detected.** The target appears secure against all tested attack vectors.\n"
    else:
        md += "---\n\n## Detailed Findings\n"
        for i, f in enumerate(findings, 1):
            md += build_finding_md(f, i)

    md += f"""
---

## Disclaimer
> This report was generated by Leaf for authorized security testing only.  
> Unauthorized testing is illegal. Always obtain written permission before scanning.  
>  
> **Leaf** is an open-source tool by Leaf Security AI, JJ Groups of Company.  
> Built by A.P.Jovin · MIT License · {__github__}
"""
    return report_id, md

def save_report(target, findings, scan_duration, profile, config=None):
    """Save both JSON and Markdown reports, return paths"""
    from leaf.core.config import REPORTS_DIR, FINDINGS_DIR
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

    report_id, md = generate_markdown_report(target, findings, scan_duration, profile, config)
    safe_target   = target.replace("https://","").replace("http://","").replace("/","_").replace(":","_")
    ts            = datetime.now().strftime("%Y%m%d_%H%M%S")
    base          = f"{safe_target}_{ts}"

    # Save markdown
    md_path   = REPORTS_DIR / f"{base}.md"
    with open(md_path, "w") as f:
        f.write(md)

    # Save JSON
    json_path = FINDINGS_DIR / f"{base}.json"
    summary_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        f["mappings"] = get_framework_mappings(f.get("vuln_type",""), f.get("title",""))
        sev = f.get("severity", "info").lower()
        if sev in summary_counts:
            summary_counts[sev] += 1

    with open(json_path, "w") as f:
        from leaf import __version__, __author__
        json.dump({
            "report_id":       report_id,
            "target":          target,
            "scan_time":       datetime.now().isoformat(),
            "duration_seconds":round(scan_duration, 2),
            "profile":         profile,
            "scanner_version": __version__,
            "scanner_author":  __author__,
            "findings":        findings,
            "summary":         summary_counts,
        }, f, indent=2)

    return report_id, md_path, json_path

def list_reports():
    from leaf.core.config import REPORTS_DIR
    if not REPORTS_DIR.exists():
        return []
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.md"), reverse=True):
        stat = f.stat()
        reports.append({
            "file": f,
            "name": f.stem,
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime),
        })
    return reports

def ai_classify_finding(finding, config):
    """Use AI to classify a finding and add CVSS score, write-up template"""
    if not config.get("ai", {}).get("enabled"):
        return finding

    try:
        from leaf.core.ai_client import AIClient
        ai = AIClient(config)
        prompt = f"""You are a senior bug bounty security researcher. 
Analyze this vulnerability finding and respond with a JSON object:
{{
  "severity": "critical|high|medium|low|info",
  "cvss_score": <float>,
  "write_up_template": "<markdown template for bug report>",
  "recommendations": "<fix recommendations>"
}}

Finding:
Title: {finding.get('title')}
Type: {finding.get('vuln_type')}
URL: {finding.get('url')}
Evidence: {finding.get('evidence','')}
"""
        content = ai.call_ai(prompt, "You are a professional security advisor.")
        import re
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            ai_data = json.loads(json_match.group())
            finding["ai_severity"]       = ai_data.get("severity", finding.get("severity", "info"))
            finding["ai_cvss"]           = ai_data.get("cvss_score", CVSS_BASE.get(finding.get("severity", "info"), 0))
            finding["ai_writeup"]        = ai_data.get("write_up_template", "")
            finding["ai_recommendations"]= ai_data.get("recommendations", "")
    except Exception:
        pass
    return finding
