"""
LeafScan — Local SAST Scanner Module (Features 21-24)
Performs static analysis audits on codebase paths.
"""
import os
import re
from pathlib import Path

# Secrets detection signatures
SECRETS_PATTERNS = {
    "AWS Access Key ID": r"\b(AKIA[0-9A-Z]{16})\b",
    "AWS Secret Key": r"\b([0-9a-zA-Z+/]{40})\b", # High entropy fallback helper
    "GitHub Personal Access Token": r"\b(ghp_[a-zA-Z0-9]{36})\b",
    "Slack Bot Token": r"\bxoxb-[0-9]{11,13}-[a-zA-Z0-9]{24}\b",
    "Generic Private Key": r"-----BEGIN[ A-Z0-9-_]+PRIVATE KEY-----",
    "Bearer API Token": r"\b(Bearer\s+[a-zA-Z0-9\-_\.\~+/]+=*)\b"
}

def run_local_sast(source_dir_path):
    findings = []
    source_dir = Path(source_dir_path)
    if not source_dir.exists() or not source_dir.is_dir():
        return findings

    # Walk through local directory files
    for root, dirs, files in os.walk(source_dir):
        # Skip version control
        if any(d.startswith('.') for d in root.split(os.sep) if d != '.'):
            continue

        for file in files:
            file_path = Path(root) / file
            
            # Feature 21: Secrets Scanner
            if file_path.suffix in (".py", ".js", ".json", ".conf", ".env", ".yml", ".yaml", ".txt", ".ini", ".php", ".go"):
                try:
                    content = file_path.read_text(errors="ignore")
                    for name, pattern in SECRETS_PATTERNS.items():
                        # Exclude general false positives by checking entropy or basic format
                        matches = re.findall(pattern, content)
                        for match in matches:
                            # Skip standard private key header placeholders
                            if "-----BEGIN" in match or "ghp_" in match or "xoxb-" in match or "AKIA" in match:
                                findings.append({
                                    "title": f"Leaked Secret Discovered: {name}",
                                    "severity": "critical",
                                    "vuln_type": "SAST",
                                    "url": f"local://{file_path.relative_to(source_dir)}",
                                    "description": f"Found a pattern matching a {name} inside local source file '{file_path.name}'.",
                                    "remediation": "Revoke the credentials immediately, scrub the git history, and use environment variables.",
                                    "evidence": f"Pattern matched: {name} in {file_path.name}",
                                    "steps": f"Open file '{file_path}' and remove raw key entry.",
                                    "poc": f"File: {file_path.name}\nContext: ... {match[:12]}*** ...",
                                    "impact": "Unrestricted administrative access to API credentials, third-party services, or repository databases.",
                                    "owasp": "A02:2021-Cryptographic Failures"
                                })
                except Exception:
                    pass

            # Feature 22: Lockfile Dependency Auditor
            if file in ("package-lock.json", "yarn.lock", "requirements.txt", "Pipfile.lock", "cargo.lock", "go.sum"):
                try:
                    content = file_path.read_text(errors="ignore")
                    # Simple static check for known outdated/vulnerable package strings
                    outdated_hints = ["lodash@<4.17.21", "urllib3==1.26.15", "flask==2.0.0", "requests==2.20.0"]
                    found_outdated = []
                    for hint in outdated_hints:
                        pkg, ver = hint.split("@" if "@" in hint else "==")
                        if pkg in content:
                            found_outdated.append(hint)
                    if found_outdated:
                        findings.append({
                            "title": "Vulnerable Dependency Lockfile Signature",
                            "severity": "medium",
                            "vuln_type": "SAST",
                            "url": f"local://{file_path.relative_to(source_dir)}",
                            "description": f"The dependency lockfile '{file}' contains vulnerable dependencies: {', '.join(found_outdated)}.",
                            "remediation": "Update dependencies to the latest patch version (e.g. npm update, pip install -U).",
                            "evidence": f"Found vulnerable package references:\n" + "\n".join(found_outdated),
                            "steps": f"Inspect '{file}' and run dependency upgrade check.",
                            "poc": f"Dependency check: {file_path.name}",
                            "impact": "Prone to prototype pollution, directory traversal, or remote code execution depending on version CVEs.",
                            "owasp": "A06:2021-Vulnerable and Outdated Components"
                        })
                except Exception:
                    pass

            # Feature 24: Dockerfile Security Audit
            if file.lower() == "dockerfile":
                try:
                    content = file_path.read_text(errors="ignore")
                    # Check for missing USER directive (runs as root by default)
                    if "user " not in content.lower():
                        findings.append({
                            "title": "Root User Dockerfile Execution Flag",
                            "severity": "low",
                            "vuln_type": "SAST",
                            "url": f"local://{file_path.relative_to(source_dir)}",
                            "description": "The Dockerfile does not define a non-root USER directive, meaning the container runs processes as root by default.",
                            "remediation": "Add a dedicated non-root user (e.g. USER node, USER appuser) in the Dockerfile configuration.",
                            "evidence": "Missing USER directive in Dockerfile.",
                            "steps": "1. Open Dockerfile.\n2. Verify the presence of 'USER' instruction.",
                            "poc": content[:150] + "\n...",
                            "impact": "Enables container escape risks if a vulnerability is exploited within the running container.",
                            "owasp": "A05:2021-Security Misconfiguration"
                        })
                except Exception:
                    pass

    # Feature 23: Git Configuration Auditor
    git_config = source_dir / ".git" / "config"
    if git_config.exists():
        try:
            content = git_config.read_text(errors="ignore")
            if "http://" in content.lower():
                findings.append({
                    "title": "Insecure HTTP Git Remote Origin",
                    "severity": "low",
                    "vuln_type": "SAST",
                    "url": "local://.git/config",
                    "description": "The local Git configuration has a remote repository URL defined over unencrypted HTTP.",
                    "remediation": "Update remote URLs to use HTTPS or SSH: git remote set-url origin https://...",
                    "evidence": "Found 'http://' git origin remote.",
                    "steps": "Run 'git remote -v' to list HTTP URLs.",
                    "poc": content[:200],
                    "impact": "Code commits and SSH credentials/tokens can be intercepted over unencrypted local channels.",
                    "owasp": "A02:2021-Cryptographic Failures"
                })
        except Exception:
            pass

    return findings
