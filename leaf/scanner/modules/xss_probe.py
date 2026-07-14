"""
Leaf Module — XSS (Cross-Site Scripting) Probe
Uses passive reflection detection — checks if parameter values appear unescaped in response.
NO actual JavaScript execution or DOM manipulation is performed.
Reference: OWASP XSS Prevention Cheat Sheet, PortSwigger XSS research
"""
import requests
import urllib.parse
import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

# Distinctive probe string — not an actual attack payload
# We check if this string appears unescaped in the response
PROBE_MARKER = "Leaf_XSS_x7k9probe"
PROBE_PAYLOAD = f'"><{PROBE_MARKER}/>'

# Patterns that indicate unescaped reflection (potential XSS)
REFLECTION_PATTERNS = [
    re.compile(rf"<{re.escape(PROBE_MARKER)}", re.IGNORECASE),
    re.compile(rf'"{re.escape(PROBE_MARKER)}', re.IGNORECASE),
]

# Common XSS-prone parameters
COMMON_PARAMS = ["q", "s", "search", "query", "keyword", "name", "id",
                 "input", "value", "data", "msg", "message", "text",
                 "page", "lang", "redirect", "url", "next", "return"]

# Common URL patterns with injectable parameters
INJECTABLE_PATHS = [
    "?q={probe}",
    "?search={probe}",
    "?s={probe}",
    "?id={probe}",
    "?name={probe}",
    "?query={probe}",
    "?input={probe}",
]


def _test_reflection(session, url, timeout, ua):
    """Check if the probe string appears unescaped in the response."""
    try:
        r = session.get(url, timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
        content_type = r.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return False, ""
        body = r.text
        for pattern in REFLECTION_PATTERNS:
            if pattern.search(body):
                return True, body[:2000]
        return False, ""
    except Exception:
        return False, ""


def run(target: str, config: dict) -> list:
    """Probe for reflected XSS by checking if probe values appear unescaped in responses."""
    findings = []
    timeout  = config.get("scan", {}).get("timeout", 12)
    ua       = config.get("scan", {}).get("user_agent", "Leaf/2.0")

    session = requests.Session()
    session.headers["User-Agent"] = ua
    parsed  = urlparse(target)
    base    = f"{parsed.scheme}://{parsed.netloc}"

    # First: check existing URL parameters for reflection
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        for key in params:
            modified = dict(params)
            modified[key] = [PROBE_PAYLOAD]
            test_url = parsed._replace(query=urlencode(modified, doseq=True)).geturl()
            found, snippet = _test_reflection(session, test_url, timeout, ua)
            if found:
                findings.append({
                    "title":       f"Reflected XSS in Parameter: {key}",
                    "severity":    "high",
                    "vuln_type":   "Cross-Site Scripting (XSS)",
                    "url":         test_url,
                    "description": f"Parameter '{key}' reflects user input into the HTML response without "
                                   f"proper encoding. An attacker could inject malicious JavaScript that "
                                   f"executes in the victim's browser.",
                    "remediation": "HTML-encode all user-controlled output. Use Content-Security-Policy. "
                                   "Apply output encoding libraries (e.g., OWASP Java Encoder, DOMPurify).",
                    "evidence":    f"Probe string '{PROBE_MARKER}' appeared unescaped in HTTP response body.\nSnippet: {snippet[:300]}",
                    "steps":       f"1. Send GET request to: {test_url}\n2. Search response body for unescaped '{PROBE_MARKER}'",
                    "poc":         f"curl -s '{test_url}' | grep '{PROBE_MARKER}'",
                    "impact":      "Can steal session cookies, perform actions as the victim, or deface pages.",
                })

    # Second: probe common parameter patterns on the base URL
    tested_urls = set()
    for tpl in INJECTABLE_PATHS:
        probe_url = base + "/" + tpl.format(probe=urllib.parse.quote(PROBE_PAYLOAD))
        if probe_url in tested_urls:
            continue
        tested_urls.add(probe_url)
        found, snippet = _test_reflection(session, probe_url, timeout, ua)
        if found:
            param = tpl.split("?")[1].split("=")[0] if "?" in tpl else "unknown"
            findings.append({
                "title":       f"Reflected XSS Probe Hit: ?{param}",
                "severity":    "high",
                "vuln_type":   "Cross-Site Scripting (XSS)",
                "url":         probe_url,
                "description": f"Parameter '{param}' reflects input unescaped into the HTML response.",
                "remediation": "Apply output encoding for all reflected parameters. Use CSP.",
                "evidence":    f"Probe '{PROBE_MARKER}' reflected in response to: {probe_url[:200]}",
                "steps":       f"1. curl -s '{probe_url}' | grep '{PROBE_MARKER}'",
                "poc":         f"curl -s '{probe_url}' | grep '{PROBE_MARKER}'",
                "impact":      "Allows JavaScript injection in victim browser sessions.",
            })

    return findings
