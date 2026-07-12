"""
LeafScan Module — Security Misconfiguration Detection
Checks for CORS misconfigurations, directory listing, HTTP methods, cookie security.
Reference: OWASP A05:2021 - Security Misconfiguration
"""
import requests
from urllib.parse import urlparse


def _check_cors(session, target, timeout, ua):
    """Check for overly permissive CORS configuration."""
    findings = []
    try:
        # Test with a malicious origin
        evil_origin = "https://evil-attacker.leafscan-test.com"
        r = session.get(
            target,
            timeout=timeout,
            headers={"User-Agent": ua, "Origin": evil_origin},
            allow_redirects=True,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            findings.append({
                "title":       "CORS: Wildcard Origin Allowed (*)",
                "severity":    "medium",
                "vuln_type":   "CORS Misconfiguration",
                "url":         target,
                "description": "Access-Control-Allow-Origin: * allows any website to make "
                               "cross-origin requests to this endpoint. If combined with cookies "
                               "or authentication, this may enable CSRF or data theft.",
                "remediation": "Replace wildcard CORS with an allowlist of trusted origins. "
                               "Never use * with Access-Control-Allow-Credentials: true.",
                "evidence":    f"Response header: Access-Control-Allow-Origin: *",
                "steps":       f"1. curl -H 'Origin: {evil_origin}' -I {target}\n2. Observe ACAO header",
                "poc":         f"curl -H 'Origin: https://evil.com' -I {target} | grep -i access-control",
                "impact":      "Any website can read response data from cross-origin requests.",
            })
        elif acao == evil_origin:
            sev = "critical" if acac == "true" else "high"
            findings.append({
                "title":       "CORS: Arbitrary Origin Reflected",
                "severity":    sev,
                "vuln_type":   "CORS Misconfiguration",
                "url":         target,
                "description": f"The server reflects arbitrary Origin headers in Access-Control-Allow-Origin. "
                               f"Allow-Credentials: {acac}. An attacker can read cross-origin responses "
                               f"{'including authenticated data' if acac == 'true' else 'from unauthenticated requests'}.",
                "remediation": "Validate Origin against a strict allowlist. Never reflect the Origin header blindly.",
                "evidence":    f"Sent Origin: {evil_origin}\nReceived ACAO: {acao}\nACCA: {acac}",
                "steps":       f"1. curl -H 'Origin: {evil_origin}' -I {target}\n2. Observe reflected origin",
                "poc":         f"curl -H 'Origin: {evil_origin}' -I {target} | grep -i access-control",
                "impact":      "Allows cross-origin data theft" + (" with session credentials." if acac == "true" else "."),
            })
    except Exception:
        pass
    return findings


def _check_http_methods(session, target, timeout, ua):
    """Check for dangerous HTTP methods enabled (TRACE, PUT, DELETE)."""
    findings = []
    try:
        r = session.options(target, timeout=timeout, headers={"User-Agent": ua})
        allow = r.headers.get("Allow", "") + r.headers.get("Public", "")
        for method in ("TRACE", "PUT", "DELETE", "CONNECT"):
            if method in allow.upper():
                severity = "high" if method == "TRACE" else "medium"
                findings.append({
                    "title":       f"Dangerous HTTP Method Enabled: {method}",
                    "severity":    severity,
                    "vuln_type":   "Security Misconfiguration",
                    "url":         target,
                    "description": (
                        f"HTTP {method} is listed in the Allow header. "
                        + {
                            "TRACE": "HTTP TRACE enables Cross-Site Tracing (XST) attacks that can steal cookies.",
                            "PUT": "HTTP PUT may allow unauthorized file uploads.",
                            "DELETE": "HTTP DELETE may allow unauthorized resource deletion.",
                            "CONNECT": "HTTP CONNECT may allow proxy tunneling abuse.",
                        }.get(method, "")
                    ),
                    "remediation": f"Disable HTTP {method} in your web server config. "
                                   "Only allow GET, POST, HEAD, OPTIONS as required.",
                    "evidence":    f"OPTIONS {target} → Allow: {allow}",
                    "steps":       f"1. curl -X OPTIONS -I {target}\n2. Observe Allow header containing {method}",
                    "poc":         f"curl -X OPTIONS -I {target} | grep Allow",
                    "impact":      f"HTTP {method} may allow unintended operations on the server.",
                })
    except Exception:
        pass
    return findings


def _check_cookie_security(session, target, timeout, ua):
    """Check Set-Cookie headers for security attributes."""
    findings = []
    try:
        r = session.get(target, timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("httponly") and "httponly" not in str(cookie).lower():
                issues.append("missing HttpOnly flag")
            samesite = cookie.get_nonstandard_attr("samesite") if hasattr(cookie, 'get_nonstandard_attr') else None
            if not samesite:
                issues.append("missing SameSite attribute")

            if issues:
                sev = "high" if "missing Secure flag" in issues or "missing HttpOnly flag" in issues else "low"
                findings.append({
                    "title":       f"Insecure Cookie: {cookie.name}",
                    "severity":    sev,
                    "vuln_type":   "Cookie Security",
                    "url":         target,
                    "description": f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}. "
                                   "Missing flags enable cookie theft and CSRF attacks.",
                    "remediation": (
                        f"Set cookie with: Set-Cookie: {cookie.name}=...; "
                        "Secure; HttpOnly; SameSite=Strict"
                    ),
                    "evidence":    f"Set-Cookie: {cookie.name}={cookie.value[:20]}... [{', '.join(issues)}]",
                    "steps":       f"1. curl -I {target}\n2. Inspect Set-Cookie response header",
                    "poc":         f"curl -I {target} | grep -i set-cookie",
                    "impact":      "Session cookies without Secure/HttpOnly can be stolen via XSS or network MitM.",
                })
    except Exception:
        pass
    return findings


def _check_directory_listing(session, target, timeout, ua):
    """Check if directory listing is enabled on common paths."""
    findings = []
    test_paths = ["images/", "assets/", "static/", "uploads/", "files/", "media/"]
    for path in test_paths:
        try:
            url = target.rstrip("/") + "/" + path
            r = session.get(url, timeout=timeout, headers={"User-Agent": ua})
            if r.status_code == 200 and "Index of /" in r.text:
                findings.append({
                    "title":       f"Directory Listing Enabled: /{path}",
                    "severity":    "medium",
                    "vuln_type":   "Security Misconfiguration",
                    "url":         url,
                    "description": f"Directory listing is enabled at /{path}. "
                                   "Browsable directories expose file structure and may reveal sensitive files.",
                    "remediation": "Disable directory listing in your web server config "
                                   "(Options -Indexes in Apache; autoindex off in Nginx).",
                    "evidence":    f"GET {url} → HTTP {r.status_code}, body contains 'Index of /'",
                    "steps":       f"1. curl -s {url} | grep 'Index of'\n2. Browse to {url}",
                    "poc":         f"curl -s {url} | grep 'Index of'",
                    "impact":      "Attackers can enumerate all files in the directory.",
                })
                break  # One example is sufficient
        except Exception:
            pass
    return findings


def run(target: str, config: dict) -> list:
    """Run all misconfiguration checks."""
    timeout = config.get("scan", {}).get("timeout", 12)
    ua      = config.get("scan", {}).get("user_agent", "LeafScan/2.0")

    session = requests.Session()
    session.headers["User-Agent"] = ua

    findings = []
    findings += _check_cors(session, target, timeout, ua)
    findings += _check_http_methods(session, target, timeout, ua)
    findings += _check_cookie_security(session, target, timeout, ua)
    findings += _check_directory_listing(session, target, timeout, ua)
    return findings
