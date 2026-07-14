"""
Leaf Module — CVE Pattern Detection
Detects technology versions in HTTP headers and page content,
then checks against known CVE patterns for outdated software.
Technique: Banner/version grabbing (identical to WhatWeb, Wappalyzer, Nikto).
Reference: https://cve.mitre.org/, https://nvd.nist.gov/
"""
import requests
import re
from urllib.parse import urlparse

# Known vulnerable version patterns — (regex, tech, min_safe_version, CVEs, severity, description)
CVE_SIGNATURES = [
    # Apache
    (re.compile(r"Apache/([12]\.\d+\.\d+)", re.IGNORECASE),
     "Apache HTTP Server",
     "2.4.58",
     ["CVE-2023-31122", "CVE-2023-43622"],
     "high",
     "Apache version {ver} has known vulnerabilities. CVE-2023-31122 (mod_macro heap overflow) affects Apache < 2.4.58."),

    # Nginx
    (re.compile(r"nginx/([01]\.\d+\.\d+)", re.IGNORECASE),
     "Nginx",
     "1.25.3",
     ["CVE-2023-44487"],
     "medium",
     "Nginx {ver} may be vulnerable to HTTP/2 Rapid Reset (CVE-2023-44487) DoS attack."),

    # PHP
    (re.compile(r"PHP/([5678]\.\d+\.\d+)", re.IGNORECASE),
     "PHP",
     "8.2.0",
     ["CVE-2023-3247", "CVE-2022-31625"],
     "high",
     "PHP {ver} is outdated. PHP 5.x/7.x are end-of-life with many unpatched CVEs."),

    # WordPress (from generator tag or version file)
    (re.compile(r"WordPress[/ ]([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
     "WordPress",
     "6.4.0",
     ["CVE-2023-5561", "CVE-2023-2745"],
     "high",
     "WordPress {ver} is outdated. Older versions have known auth-bypass and XSS vulnerabilities."),

    # jQuery
    (re.compile(r"jquery[/ v]+([123]\.[0-9]+\.[0-9]+)", re.IGNORECASE),
     "jQuery",
     "3.7.0",
     ["CVE-2020-11022", "CVE-2020-11023"],
     "medium",
     "jQuery {ver} is vulnerable to XSS (CVE-2020-11022/11023). Upgrade to 3.7.0+."),

    # OpenSSL (from Server header)
    (re.compile(r"OpenSSL/([01]\.[0-9]+\.[0-9]+[a-z]?)", re.IGNORECASE),
     "OpenSSL",
     "3.0.0",
     ["CVE-2022-0778", "CVE-2021-3711"],
     "high",
     "OpenSSL {ver} is outdated. Several critical vulnerabilities affect OpenSSL 1.x."),

    # Apache Struts
    (re.compile(r"Struts[/ ]([123]\.[0-9]+\.[0-9]+)", re.IGNORECASE),
     "Apache Struts",
     "6.3.0",
     ["CVE-2023-50164"],
     "critical",
     "Apache Struts {ver} — CVE-2023-50164 allows RCE via file upload path traversal."),

    # Log4j pattern (from banner/headers)
    (re.compile(r"log4j[/ -]([12]\.[0-9]+\.[0-9]+)", re.IGNORECASE),
     "Log4j",
     "2.17.0",
     ["CVE-2021-44228"],
     "critical",
     "Log4j {ver} — CVE-2021-44228 (Log4Shell) is a critical RCE vulnerability. Upgrade immediately!"),

    # Spring Framework
    (re.compile(r"Spring(?:Framework)?[/ ]([45]\.[0-9]+\.[0-9]+)", re.IGNORECASE),
     "Spring Framework",
     "6.0.0",
     ["CVE-2022-22965"],
     "critical",
     "Spring {ver} — CVE-2022-22965 (Spring4Shell) allows RCE in certain configurations."),

    # Tomcat
    (re.compile(r"Apache Tomcat/([789]|10)\.[0-9]+\.[0-9]+", re.IGNORECASE),
     "Apache Tomcat",
     "10.1.16",
     ["CVE-2023-46589", "CVE-2023-45648"],
     "high",
     "Apache Tomcat {ver} has known HTTP request smuggling vulnerabilities."),
]


def _grab_tech_info(target: str, timeout: int, ua: str):
    """Fetch target and return (header_string, body_snippet)."""
    try:
        r = requests.get(target, timeout=timeout, headers={"User-Agent": ua},
                         verify=True, allow_redirects=True)
        headers_str = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        body_snippet = r.text[:5000]
        return headers_str, body_snippet, r
    except Exception:
        return "", "", None


def run(target: str, config: dict) -> list:
    """Detect known vulnerable software versions in HTTP headers and page content."""
    findings = []
    timeout  = config.get("scan", {}).get("timeout", 12)
    ua       = config.get("scan", {}).get("user_agent", "Leaf/2.0")

    headers_str, body_snippet, resp = _grab_tech_info(target, timeout, ua)
    if not resp:
        return []

    # Search both headers and body
    search_text = headers_str + "\n" + body_snippet

    for regex, tech, min_safe, cves, severity, desc_template in CVE_SIGNATURES:
        match = regex.search(search_text)
        if match:
            ver = match.group(1)
            cve_list = ", ".join(cves)
            description = desc_template.format(ver=ver)
            findings.append({
                "title":       f"Outdated {tech} v{ver} — Known CVEs Detected",
                "severity":    severity,
                "vuln_type":   "Outdated Software / Known CVE",
                "url":         target,
                "description": description + f"\nReferenced CVEs: {cve_list}",
                "remediation": (
                    f"Upgrade {tech} to version {min_safe} or later. "
                    f"Check {tech} security advisories. "
                    f"Reference: https://nvd.nist.gov/vuln/search?query={cves[0]}"
                ),
                "evidence":    f"Detected: '{match.group(0)}' in {'HTTP headers' if match.group(0) in headers_str else 'page content'}",
                "steps":       (
                    f"1. Fetch {target} and inspect Server/X-Powered-By headers\n"
                    f"2. Search response for version string: {match.group(0)}\n"
                    f"3. Cross-reference with NVD: https://nvd.nist.gov/vuln/search?query={cves[0]}"
                ),
                "poc":         f"curl -s -I {target} | grep -iE '{tech.lower()}|server|x-powered'",
                "impact":      f"Known exploits exist for {tech} {ver}. Attackers actively scan for these version patterns.",
            })

    return findings
