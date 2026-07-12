"""
LeafScan Module — Information Disclosure Detection
Identifies accidental exposure of sensitive data in HTTP responses.
Reference: OWASP Testing Guide OTG-INFO-004, CWE-200
"""
import requests
import re

# Patterns that indicate sensitive data exposure
DISCLOSURE_PATTERNS = [
    # AWS credentials
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
     "AWS Access Key ID",
     "critical",
     "An AWS Access Key ID was found in the response. This may grant access to AWS resources."),

    # Generic API keys (common patterns)
    (re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", re.IGNORECASE),
     "API Key",
     "high",
     "An API key value was exposed in the page response."),

    # JWT tokens
    (re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
     "JWT Token",
     "high",
     "A JSON Web Token (JWT) was found in the response. Exposed JWTs may allow session hijacking."),

    # Private keys
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "Private Key",
     "critical",
     "A private key was exposed in the HTTP response. This completely compromises any associated encryption."),

    # Email addresses in stack traces
    (re.compile(r"(?:Exception|Error|Traceback|at [\w.]+\([\w.]+\.java:\d+\))", re.IGNORECASE),
     "Stack Trace / Error Disclosure",
     "medium",
     "A stack trace or error message was found in the response, disclosing internal code paths."),

    # Internal IP addresses
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"),
     "Internal IP Address",
     "low",
     "An internal/private IP address was found in the response, revealing internal network topology."),

    # Database connection strings
    (re.compile(r"(?:mysql|postgresql|mongodb|redis|jdbc|sqlserver)://[^\s\"'<>]{5,}", re.IGNORECASE),
     "Database Connection String",
     "critical",
     "A database connection string was found in the response, potentially exposing credentials."),

    # Password in response
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?(\S{4,})", re.IGNORECASE),
     "Password Disclosure",
     "critical",
     "A password value appears to be present in the HTTP response body."),

    # Google API keys
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}", re.IGNORECASE),
     "Google API Key",
     "high",
     "A Google API Key was found. Verify it is restricted by referrer and not abusable."),

    # GitHub tokens
    (re.compile(r"gh[ps]_[a-zA-Z0-9]{36}", re.IGNORECASE),
     "GitHub Personal Access Token",
     "critical",
     "A GitHub Personal Access Token was found. This may grant access to private repos."),
]


def run(target: str, config: dict) -> list:
    """Scan the target response for sensitive information disclosure patterns."""
    findings = []
    timeout  = config.get("scan", {}).get("timeout", 12)
    ua       = config.get("scan", {}).get("user_agent", "LeafScan/2.0")

    try:
        r = requests.get(
            target,
            timeout=timeout,
            headers={"User-Agent": ua},
            verify=True,
            allow_redirects=True,
        )
        body = r.text

        for pattern, finding_type, severity, description in DISCLOSURE_PATTERNS:
            match = pattern.search(body)
            if match:
                # Safely excerpt the match (redact sensitive values)
                raw_match = match.group(0)
                if len(raw_match) > 20 and severity == "critical":
                    # Partial redaction for very sensitive values
                    shown = raw_match[:8] + "..." + raw_match[-4:]
                else:
                    shown = raw_match[:80]

                findings.append({
                    "title":       f"Sensitive Data Exposed: {finding_type}",
                    "severity":    severity,
                    "vuln_type":   "Information Disclosure",
                    "url":         target,
                    "description": description,
                    "remediation": (
                        f"Remove all sensitive data from HTTP responses. "
                        f"Ensure secrets are never committed to source code or served in pages. "
                        f"Use environment variables and secrets managers (HashiCorp Vault, AWS Secrets Manager). "
                        f"Review CWE-200: Exposure of Sensitive Information."
                    ),
                    "evidence":    f"Pattern matched in HTTP response body: '{shown}'",
                    "steps":       (
                        f"1. curl -s {target} | grep -iE '{finding_type.lower().replace(' ', '|')}'\n"
                        f"2. Review page source for exposed values"
                    ),
                    "poc":         f"curl -s {target} | grep -P '{pattern.pattern[:60]}'",
                    "impact":      f"Exposure of {finding_type.lower()} may allow unauthorized access to systems or data.",
                })
                # Avoid duplicate finding for same pattern type
    except Exception:
        pass

    return findings
