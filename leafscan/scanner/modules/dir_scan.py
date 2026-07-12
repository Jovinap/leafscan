"""
LeafScan Module — Directory & File Discovery
Probes for common sensitive paths/files using a curated wordlist.
Technique: HTTP-based directory enumeration (same as dirb/gobuster/feroxbuster).
Reference: OWASP Testing Guide OTG-INFO-006
"""
import requests
import concurrent.futures
from urllib.parse import urljoin

# Curated list of high-value sensitive paths (not an attack list — all publicly known)
PATHS = [
    # Admin panels
    "admin/", "admin/login", "administrator/", "wp-admin/", "phpmyadmin/",
    "adminer.php", "manager/html", "console", "webadmin/",
    # Config / backup files
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.php", "config.yml", "config.yaml", "configuration.php",
    "database.yml", "settings.py", "local_settings.py",
    "wp-config.php", "web.config", "appsettings.json",
    # Backup archives
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "db.sql", "site.zip", "www.tar.gz",
    # Git / VCS exposure
    ".git/HEAD", ".git/config", ".svn/wc.db", ".hg/",
    # Composer / NPM
    "composer.json", "package.json", "package-lock.json",
    "yarn.lock", "composer.lock",
    # Logs
    "debug.log", "error.log", "access.log", "server.log",
    "laravel.log", "app.log", "logs/",
    # API docs
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api/swagger.json", "api-docs", "api/docs",
    # Common CMS paths
    "xmlrpc.php", "readme.html", "license.txt",
    "wp-json/wp/v2/users",
    # Monitoring / health checks
    "actuator", "actuator/env", "actuator/health", "actuator/mappings",
    "metrics", "health", "_status", "server-status", "server-info",
    # Cloud metadata (SSRF)
    "v1.0/task", "latest/meta-data/",
    # Misc
    "robots.txt", "sitemap.xml", ".htaccess", "crossdomain.xml",
    "phpinfo.php", "info.php", "test.php", "shell.php",
]

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "private_key", "db_password", "database_password", "aws_secret",
    "credential", "s3_bucket",
]


def _probe(session, base_url, path, timeout):
    """Return finding dict or None."""
    url = urljoin(base_url.rstrip("/") + "/", path)
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False)
        # Interesting responses: 200, 206, 301→sensitive, 403 (exists but restricted)
        if r.status_code == 200:
            content = r.text[:4000].lower()
            severity = "low"

            # Escalate severity based on content
            for kw in SENSITIVE_KEYWORDS:
                if kw in content:
                    severity = "high"
                    break

            if ".git" in path and r.status_code == 200:
                severity = "critical"
            elif path in (".env", ".env.local", ".env.production"):
                severity = "critical"
            elif path in ("phpinfo.php", "info.php"):
                severity = "high"
            elif "actuator" in path:
                severity = "high"
            elif path.endswith((".sql", ".zip", ".tar.gz", "backup")):
                severity = "critical"

            return {
                "title":       f"Sensitive Path Exposed: /{path}",
                "severity":    severity,
                "vuln_type":   "Sensitive File Exposure",
                "url":         url,
                "description": f"The path '/{path}' returned HTTP {r.status_code}, indicating "
                               "it is publicly accessible. This path typically contains sensitive data.",
                "remediation": f"Restrict access to '/{path}' via server config, .htaccess rules, "
                               "or WAF policies. If it is a dev artifact, remove it from production.",
                "evidence":    f"GET {url} → HTTP {r.status_code} ({len(r.content)} bytes)",
                "steps":       f"1. curl -v {url}\n2. Review response content for secrets",
                "poc":         f"curl -s {url} | head -50",
                "impact":      f"Exposure of {path} may reveal credentials, source code, or system config.",
            }
    except Exception:
        pass
    return None


def run(target: str, config: dict) -> list:
    """Enumerate sensitive files and directories on the target."""
    findings = []
    threads  = config.get("scan", {}).get("threads", 10)
    timeout  = config.get("scan", {}).get("timeout", 12)
    ua       = config.get("scan", {}).get("user_agent", "LeafScan/2.0")

    session = requests.Session()
    session.headers["User-Agent"] = ua

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_probe, session, target, path, timeout): path for path in PATHS}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    findings.append(result)
            except Exception:
                pass

    return findings
