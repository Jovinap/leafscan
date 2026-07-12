"""
LeafScan Module — HTTP Security Headers
Checks for missing or misconfigured HTTP security response headers.
Reference: OWASP Secure Headers Project (https://owasp.org/www-project-secure-headers/)
"""
import requests

# Headers that MUST be present for security
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS not set — browser connections are not enforced to use HTTPS, "
                       "leaving users vulnerable to downgrade and MitM attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP header missing — no policy restricting script sources. "
                       "This increases XSS risk by allowing inline scripts and arbitrary origins.",
        "remediation": "Define a strict CSP, e.g.: Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options missing — page can be embedded in iframes, "
                       "enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options not set — browsers may MIME-sniff responses "
                       "and execute non-script resources as scripts.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy missing — full URL (including query parameters) "
                       "may be sent to third parties via the Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header absent — browser features (camera, "
                       "geolocation, microphone) are not explicitly restricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

# Headers that must NOT be present (information disclosure)
BANNED_HEADERS = {
    "Server": {
        "severity": "low",
        "description": "Server header exposes the web server software and version, "
                       "aiding fingerprinting and targeted attacks.",
        "remediation": "Remove or obscure the Server header in your web server configuration.",
    },
    "X-Powered-By": {
        "severity": "low",
        "description": "X-Powered-By discloses the backend technology stack "
                       "(e.g., PHP, Express), helping attackers target known vulnerabilities.",
        "remediation": "Remove X-Powered-By from responses (e.g., app.disable('x-powered-by') in Express).",
    },
    "X-AspNet-Version": {
        "severity": "low",
        "description": "X-AspNet-Version reveals the exact ASP.NET runtime version, "
                       "enabling version-specific exploit targeting.",
        "remediation": "Set <httpRuntime enableVersionHeader='false'/> in web.config",
    },
}


def run(target: str, config: dict) -> list:
    """Check HTTP security headers for the given target."""
    findings = []
    timeout  = config.get("scan", {}).get("timeout", 12)
    ua       = config.get("scan", {}).get("user_agent", "LeafScan/2.0")

    try:
        resp = requests.get(
            target,
            timeout=timeout,
            headers={"User-Agent": ua},
            verify=True,
            allow_redirects=True,
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check required headers
        for hdr, meta in REQUIRED_HEADERS.items():
            if hdr.lower() not in headers:
                findings.append({
                    "title":       f"Missing Security Header: {hdr}",
                    "severity":    meta["severity"],
                    "vuln_type":   "Security Misconfiguration",
                    "url":         target,
                    "description": meta["description"],
                    "remediation": meta["remediation"],
                    "evidence":    f"HTTP {resp.status_code} response from {target} — header '{hdr}' absent.",
                    "steps":       f"1. Fetch {target}\n2. Inspect response headers\n3. Confirm '{hdr}' is missing.",
                    "poc":         f"curl -I {target} | grep -i '{hdr.lower()}'  # Returns nothing",
                    "impact":      f"Absence of {hdr} weakens defense-in-depth against common browser attacks.",
                })

        # Check banned headers
        for hdr, meta in BANNED_HEADERS.items():
            if hdr.lower() in headers:
                value = resp.headers.get(hdr, "")
                findings.append({
                    "title":       f"Information Disclosure via Header: {hdr}",
                    "severity":    meta["severity"],
                    "vuln_type":   "Information Disclosure",
                    "url":         target,
                    "description": meta["description"],
                    "remediation": meta["remediation"],
                    "evidence":    f"{hdr}: {value}",
                    "steps":       f"1. Fetch {target}\n2. Observe response header: {hdr}: {value}",
                    "poc":         f"curl -I {target} | grep -i '{hdr.lower()}'",
                    "impact":      "Reveals technology stack details to potential attackers.",
                })

    except requests.exceptions.SSLError:
        findings.append({
            "title":       "SSL/TLS Certificate Error",
            "severity":    "medium",
            "vuln_type":   "TLS/SSL Issue",
            "url":         target,
            "description": "The server presented an invalid or untrusted TLS certificate.",
            "remediation": "Ensure a valid, CA-signed certificate is installed.",
            "evidence":    f"SSL verification failed for {target}",
            "steps":       f"1. Visit {target} in a browser\n2. Note certificate warning",
            "poc":         f"curl -v {target}  # Shows SSL handshake failure",
            "impact":      "Allows man-in-the-middle attacks on encrypted connections.",
        })
    except Exception:
        pass  # Network/timeout errors — module skips gracefully

    return findings
