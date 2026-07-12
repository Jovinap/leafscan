"""
LeafScan Module — SQL Injection Probe
Sends time-based and error-based probe queries. Detects SQL errors in responses only.
Does NOT extract data. NO destructive operations (no DROP, INSERT, UPDATE, DELETE).
Reference: OWASP SQL Injection Testing Guide (OTG-INPVAL-005)
"""
import requests
import time
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode

# Error-based probe — triggers DB error messages in response
# Using a single quote (canonical and documented by OWASP)
ERROR_PROBE = "'"

# DB error patterns in responses — purely observational
ERROR_PATTERNS = [
    re.compile(r"sql syntax.*?near", re.IGNORECASE),
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning.*?mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark.*?string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"pg::syntaxerror", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
    re.compile(r"org\.postgresql\.util\.psqlexception", re.IGNORECASE),
    re.compile(r"microsoft sql native client", re.IGNORECASE),
    re.compile(r"odbc sql server driver", re.IGNORECASE),
    re.compile(r"sqlexception\b", re.IGNORECASE),
    re.compile(r"ORA-\d{4,5}", re.IGNORECASE),  # Oracle
    re.compile(r"sqlite3\.operationalerror", re.IGNORECASE),
]


def _detect_error_sqli(session, url, timeout, ua):
    """Check if single-quote probe triggers a SQL error in the response."""
    try:
        r = session.get(url, timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
        body = r.text
        for pattern in ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                return True, match.group(0)[:150]
        return False, ""
    except Exception:
        return False, ""


def run(target: str, config: dict) -> list:
    """Probe URL parameters for SQL injection vulnerabilities via error detection."""
    findings = []
    timeout  = config.get("scan", {}).get("timeout", 12)
    ua       = config.get("scan", {}).get("user_agent", "LeafScan/2.0")

    session = requests.Session()
    session.headers["User-Agent"] = ua
    parsed  = urlparse(target)

    # Only test existing URL parameters (conservative approach)
    if not parsed.query:
        return []

    params = parse_qs(parsed.query, keep_blank_values=True)

    for key in params:
        # Append single quote to existing value
        original_val = params[key][0] if params[key] else ""
        modified = dict(params)
        modified[key] = [original_val + ERROR_PROBE]
        test_url = parsed._replace(query=urlencode(modified, doseq=True)).geturl()

        found, db_error = _detect_error_sqli(session, test_url, timeout, ua)
        if found:
            findings.append({
                "title":       f"SQL Injection (Error-Based) in Parameter: {key}",
                "severity":    "critical",
                "vuln_type":   "SQL Injection",
                "url":         test_url,
                "description": f"Parameter '{key}' appears to be vulnerable to SQL injection. "
                               f"A single quote probe triggered a database error message in the response. "
                               f"This indicates unsanitized input is being passed directly to a SQL query.",
                "remediation": (
                    "Use parameterized queries / prepared statements exclusively. "
                    "NEVER concatenate user input into SQL strings. "
                    "Apply input validation and use an ORM. "
                    "Reference: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ),
                "evidence":    f"Probe: GET {test_url}\nDB error in response: {db_error}",
                "steps":       (
                    f"1. Send: curl '{test_url}'\n"
                    f"2. Observe DB error message in response body\n"
                    f"3. Confirm vulnerability with sqlmap (authorized testing only)"
                ),
                "poc":         f"curl -s '{test_url}' | grep -iE 'sql|syntax|ORA-|mysql'",
                "impact":      "May allow data extraction, authentication bypass, or full database compromise.",
            })

    return findings
