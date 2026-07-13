"""
LeafScan — Passive Audit & Compliance Modules (Features 1-12)
Runs configuration audit, response header verification, and passive file discovery.
"""
import urllib.parse
import requests

def run(target, config):
    findings = []
    
    # Extract settings
    timeout = config.get("scan", {}).get("timeout", 10)
    user_agent = config.get("scan", {}).get("user_agent", "LeafScan")
    
    headers = {"User-Agent": user_agent}
    
    # Custom headers injection support (Feature 15)
    custom_headers = config.get("scan", {}).get("custom_headers", {})
    if custom_headers:
        headers.update(custom_headers)

    parsed = urllib.parse.urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Try fetching homepage to inspect response headers
    try:
        r = requests.get(target, headers=headers, timeout=timeout, allow_redirects=True)
        resp_headers = r.headers
    except Exception:
        resp_headers = {}
        r = None

    # Feature 4: Cookie Flag Inspector
    if r is not None and r.cookies:
        for cookie in r.cookies:
            missing = []
            if not cookie.secure:
                missing.append("Secure")
            # In python requests, httponly is stored in _rest attributes
            httponly = cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly')
            if not httponly:
                missing.append("HttpOnly")
            samesite = cookie.get_nonstandard_attr('SameSite') or cookie.get_nonstandard_attr('samesite')
            if not samesite:
                missing.append("SameSite")
                
            if missing:
                findings.append({
                    "title": f"Insecure Cookie Configuration: {cookie.name}",
                    "severity": "low",
                    "vuln_type": "Configuration",
                    "url": target,
                    "description": f"The cookie '{cookie.name}' is missing security flags: {', '.join(missing)}.",
                    "remediation": f"Configure cookies to include 'Secure', 'HttpOnly', and 'SameSite=Lax/Strict' flags in the Set-Cookie header.",
                    "evidence": f"Cookie: {cookie.name}={cookie.value}\nFlags present: Secure={cookie.secure}",
                    "steps": "1. Fetch target URL.\n2. Inspect Set-Cookie header in the response.",
                    "poc": f"Set-Cookie: {cookie.name}={cookie.value}",
                    "impact": "Session tokens or sensitive identifier cookies can be accessed via XSS attacks or transmitted over unencrypted HTTP channels.",
                    "owasp": "A05:2021-Security Misconfiguration"
                })

    # Feature 5: CORS Wildcard Checker
    cors_origin = resp_headers.get("Access-Control-Allow-Origin", "")
    if cors_origin == "*":
        findings.append({
            "title": "Permissive CORS Access-Control-Allow-Origin: *",
            "severity": "medium",
            "vuln_type": "Configuration",
            "url": target,
            "description": "The server responds with an Access-Control-Allow-Origin header set to a wildcard, allowing any domain to read its contents.",
            "remediation": "Restrict the Access-Control-Allow-Origin header to authorized origins only instead of using a wildcard.",
            "evidence": f"Access-Control-Allow-Origin: {cors_origin}",
            "steps": "1. Send a request to the target.\n2. Read the Access-Control-Allow-Origin header in the response.",
            "poc": f"Access-Control-Allow-Origin: {cors_origin}",
            "impact": "Malicious sites can read response contents via client-side scripts, bypassing Same-Origin Policy protections.",
            "owasp": "A05:2021-Security Misconfiguration"
        })

    # Feature 6: CSP Validator
    csp = resp_headers.get("Content-Security-Policy", "")
    if not csp:
        findings.append({
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "medium",
            "vuln_type": "Compliance",
            "url": target,
            "description": "Content-Security-Policy header is missing, leaving the application vulnerable to Cross-Site Scripting (XSS) and clickjacking.",
            "remediation": "Implement a strong Content-Security-Policy header defining trusted sources for scripts, styles, and other resources.",
            "evidence": "Header not present.",
            "steps": "1. Request homepage.\n2. Verify the presence of Content-Security-Policy header.",
            "poc": "HTTP/1.1 200 OK\n(Missing Content-Security-Policy header)",
            "impact": "Higher susceptibility to client-side attacks such as XSS, clickjacking, and script injection.",
            "owasp": "A05:2021-Security Misconfiguration"
        })

    # Feature 7: HSTS Auditor
    hsts = resp_headers.get("Strict-Transport-Security", "")
    if target.startswith("https://") and not hsts:
        findings.append({
            "title": "Missing Strict-Transport-Security (HSTS)",
            "severity": "low",
            "vuln_type": "Compliance",
            "url": target,
            "description": "HTTP Strict-Transport-Security is missing or misconfigured on this HTTPS target.",
            "remediation": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to response headers.",
            "evidence": "Strict-Transport-Security header is absent.",
            "steps": "1. Request site via HTTPS.\n2. Observe response headers.",
            "poc": "HTTP/1.1 200 OK\n(Missing Strict-Transport-Security header)",
            "impact": "Users are vulnerable to SSL stripping and man-in-the-middle (MITM) redirection attacks.",
            "owasp": "A05:2021-Security Misconfiguration"
        })

    # Feature 8: Referrer-Policy Auditor
    ref_policy = resp_headers.get("Referrer-Policy", "")
    if not ref_policy or ref_policy.lower() == "unsafe-url":
        findings.append({
            "title": "Weak or Missing Referrer-Policy Header",
            "severity": "info",
            "vuln_type": "Compliance",
            "url": target,
            "description": "The Referrer-Policy header is missing or configured to 'unsafe-url', which may leak sensitive parameters to external sites.",
            "remediation": "Implement a safer default policy such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
            "evidence": f"Referrer-Policy: {ref_policy or 'Missing'}",
            "steps": "1. Fetch the target URL.\n2. Verify the Referrer-Policy response header.",
            "poc": f"Referrer-Policy: {ref_policy or 'Missing'}",
            "impact": "Sensitive URL query parameters or session IDs may leak to third-party referrers.",
            "owasp": "A04:2021-Cryptographic Failures"
        })

    # Feature 9: X-Content-Type-Options Check
    x_content_type = resp_headers.get("X-Content-Type-Options", "")
    if x_content_type.lower() != "nosniff":
        findings.append({
            "title": "Missing X-Content-Type-Options: nosniff",
            "severity": "low",
            "vuln_type": "Compliance",
            "url": target,
            "description": "X-Content-Type-Options header is missing or not set to 'nosniff'.",
            "remediation": "Configure your web server to return the 'X-Content-Type-Options: nosniff' header.",
            "evidence": f"X-Content-Type-Options: {x_content_type or 'Missing'}",
            "steps": "1. Request static assets.\n2. Inspect response headers.",
            "poc": f"X-Content-Type-Options: {x_content_type or 'Missing'}",
            "impact": "Forces browsers to guess MIME types (sniffing), exposing the site to cross-site script inclusion (XSSI).",
            "owasp": "A05:2021-Security Misconfiguration"
        })

    # Feature 10: Legacy X-XSS-Protection Warning
    x_xss = resp_headers.get("X-XSS-Protection", "")
    if x_xss and "1" in x_xss:
        findings.append({
            "title": "Legacy X-XSS-Protection Header Active",
            "severity": "info",
            "vuln_type": "Compliance",
            "url": target,
            "description": "The legacy X-XSS-Protection header is present. Modern browsers rely on CSP; this header is obsolete and may introduce client-side bypasses.",
            "remediation": "Disable the X-XSS-Protection header and transition strictly to a robust Content-Security-Policy (CSP).",
            "evidence": f"X-XSS-Protection: {x_xss}",
            "steps": "1. Request target homepage.\n2. Notice X-XSS-Protection header in the response.",
            "poc": f"X-XSS-Protection: {x_xss}",
            "impact": "Legacy browser quirks can sometimes be abused to disable specific scripts by exploiting filter heuristics.",
            "owasp": "A05:2021-Security Misconfiguration"
        })

    # Feature 11: Server Header Footprint Check
    server = resp_headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "title": "Verbose Server Banner Disclosure",
            "severity": "info",
            "vuln_type": "Information Disclosure",
            "url": target,
            "description": f"The Server header discloses precise software version details: '{server}'.",
            "remediation": "Configure the web server to strip versions or return a generic server name (e.g. Server: Apache).",
            "evidence": f"Server: {server}",
            "steps": "1. Request homepage.\n2. Inspect the Server header in HTTP response.",
            "poc": f"Server: {server}",
            "impact": "Attackers can quickly profile exact system versions to look up targeting exploit campaigns.",
            "owasp": "A01:2021-Broken Access Control"
        })

    # Feature 12: Technology Stack Identifier
    powered_by = resp_headers.get("X-Powered-By", "")
    if powered_by:
        findings.append({
            "title": "Technology Stack Disclosure: X-Powered-By",
            "severity": "info",
            "vuln_type": "Information Disclosure",
            "url": target,
            "description": f"The server discloses its running framework via the X-Powered-By header: '{powered_by}'.",
            "remediation": "Configure your framework or server config to omit the X-Powered-By header entirely.",
            "evidence": f"X-Powered-By: {powered_by}",
            "steps": "1. Send standard HTTP request.\n2. Observe X-Powered-By header.",
            "poc": f"X-Powered-By: {powered_by}",
            "impact": "Discloses technology stack dependencies, aiding in target profiling.",
            "owasp": "A01:2021-Broken Access Control"
        })

    # Feature 1: Robots.txt Analyzer
    try:
        robots_url = f"{base_url}/robots.txt"
        r_rob = requests.get(robots_url, headers=headers, timeout=timeout)
        if r_rob.status_code == 200 and "user-agent" in r_rob.text.lower():
            sensitive_keywords = ["admin", "api", "private", "secret", "config", "backup"]
            matched_disallows = []
            for line in r_rob.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if any(k in path.lower() for k in sensitive_keywords):
                        matched_disallows.append(path)
            if matched_disallows:
                findings.append({
                    "title": "Sensitive Directory Disclosures in robots.txt",
                    "severity": "info",
                    "vuln_type": "Information Disclosure",
                    "url": robots_url,
                    "description": f"The robots.txt file discloses directories that contain sensitive keywords: {', '.join(matched_disallows)}.",
                    "remediation": "Do not list sensitive or private directories inside robots.txt. Instead, use authentication gates or IP constraints.",
                    "evidence": f"Discovered disallows:\n" + "\n".join(matched_disallows),
                    "steps": "1. Fetch robots.txt.\n2. Look for sensitive Disallow directives.",
                    "poc": f"Disallow: {matched_disallows[0]}",
                    "impact": "Discloses location of admin panels, API targets, or private directories directly to automated crawlers.",
                    "owasp": "A01:2021-Broken Access Control"
                })
    except Exception:
        pass

    # Feature 2: Sitemap.xml Auditor
    try:
        sitemap_url = f"{base_url}/sitemap.xml"
        r_site = requests.get(sitemap_url, headers=headers, timeout=timeout)
        if r_site.status_code == 200 and "<loc>" in r_site.text:
            findings.append({
                "title": "Sitemap XML Discovery File Available",
                "severity": "info",
                "vuln_type": "Information Disclosure",
                "url": sitemap_url,
                "description": "An XML sitemap is publicly accessible. This aids search engines but also maps the system structure for target analysis.",
                "remediation": "Confirm if the sitemap needs to disclose all administrative or internal endpoints, and filter if needed.",
                "evidence": f"Sitemap XML content length: {len(r_site.text)} bytes.",
                "steps": "1. Attempt to fetch /sitemap.xml.\n2. Verify it returns valid XML map.",
                "poc": f"GET {sitemap_url} HTTP/1.1\n\nHTTP/1.1 200 OK",
                "impact": "Allows rapid reconnaissance of application URLs and endpoints.",
                "owasp": "A01:2021-Broken Access Control"
            })
    except Exception:
        pass

    # Feature 3: Security.txt Checker
    try:
        # Check standard paths: /.well-known/security.txt and /security.txt
        for path in ["/.well-known/security.txt", "/security.txt"]:
            sec_url = f"{base_url}{path}"
            r_sec = requests.get(sec_url, headers=headers, timeout=timeout)
            if r_sec.status_code == 200 and "contact" in r_sec.text.lower():
                findings.append({
                    "title": "Security.txt Contact Standard Discovered",
                    "severity": "info",
                    "vuln_type": "Compliance",
                    "url": sec_url,
                    "description": f"Discovered valid security contact policy mapping at: '{path}'. Useful for responsible disclosure guidance.",
                    "remediation": "Ensure contact email and pgp keys listed are kept current.",
                    "evidence": f"Security.txt text preview:\n{r_sec.text[:150]}...",
                    "steps": f"1. Fetch target '{path}'.\n2. Verify policy parameters.",
                    "poc": f"GET {sec_url} HTTP/1.1\n\nHTTP/1.1 200 OK",
                    "impact": "Good compliance posture: enables white-hat hackers to submit vulnerability alerts.",
                    "owasp": "A05:2021-Security Misconfiguration"
                })
                break
    except Exception:
        pass

    return findings
