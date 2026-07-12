"""
LeafScan Module — Port Scanner
Identifies open TCP ports using socket-based connection tests.
Technique: TCP connect scan (same as nmap -sT).
Reference: https://nmap.org/book/man-port-scanning-techniques.html
"""
import socket
import concurrent.futures
from urllib.parse import urlparse

# Common web/admin ports to probe
COMMON_PORTS = {
    21:   ("FTP",       "medium", "FTP service exposed — may allow anonymous login or brute-force."),
    22:   ("SSH",       "info",   "SSH service accessible — ensure key-auth only and fail2ban is active."),
    23:   ("Telnet",    "high",   "Telnet is plaintext and deprecated — replace with SSH immediately."),
    25:   ("SMTP",      "info",   "SMTP port open — verify relay restrictions and auth requirements."),
    53:   ("DNS",       "info",   "DNS port open — check for open resolver and zone-transfer misconfig."),
    80:   ("HTTP",      "info",   "HTTP port open — ensure redirection to HTTPS is enforced."),
    110:  ("POP3",      "low",    "POP3 exposed — email retrieval may be unauthenticated or unencrypted."),
    143:  ("IMAP",      "low",    "IMAP exposed — consider restricting to localhost or VPN."),
    161:  ("SNMP",      "medium", "SNMP port open — default community strings may expose system info."),
    389:  ("LDAP",      "medium", "LDAP exposed — may leak directory information if unauthenticated."),
    443:  ("HTTPS",     "info",   "HTTPS service running — verify certificate and cipher suite strength."),
    445:  ("SMB",       "high",   "SMB exposed — high-risk: EternalBlue and ransomware target this port."),
    1433: ("MSSQL",     "high",   "MSSQL database port exposed to internet — restrict to localhost."),
    1521: ("Oracle DB", "high",   "Oracle DB port exposed — should not be internet-accessible."),
    2049: ("NFS",       "high",   "NFS exposed — may allow unauthorized filesystem access."),
    3000: ("Node.js",   "medium", "Node.js dev server exposed — should not run in production."),
    3306: ("MySQL",     "high",   "MySQL database port exposed — restrict to localhost or VPN."),
    3389: ("RDP",       "high",   "RDP exposed — frequent brute-force target. Use VPN or change port."),
    4444: ("Metasploit","critical","Port 4444 open — commonly associated with Metasploit reverse shells."),
    5432: ("PostgreSQL","high",   "PostgreSQL exposed — restrict to localhost or internal network."),
    5900: ("VNC",       "high",   "VNC exposed — remote desktop may allow unauthenticated access."),
    6379: ("Redis",     "critical","Redis exposed — default config has NO authentication; critical risk."),
    7001: ("WebLogic",  "high",   "WebLogic server port — frequent target for deserialization RCE."),
    8080: ("HTTP Alt",  "low",    "Alternate HTTP port open — may run dev server or proxy."),
    8443: ("HTTPS Alt", "low",    "Alternate HTTPS port open — verify same security as port 443."),
    8888: ("Jupyter",   "critical","Jupyter Notebook — often runs without auth; critical if exposed."),
    9200: ("Elasticsearch","critical","Elasticsearch — default has no auth; exposes all data publicly."),
    27017:("MongoDB",   "critical","MongoDB — default config has no auth; exposes all databases."),
}


def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def run(target: str, config: dict) -> list:
    """Scan common ports on the target host and report open ones."""
    findings = []
    parsed   = urlparse(target)
    host     = parsed.hostname or target.split("/")[0]
    threads  = min(config.get("scan", {}).get("threads", 10), 50)
    timeout  = min(config.get("scan", {}).get("timeout", 12), 5)  # cap at 5s per port

    try:
        # Resolve hostname to verify it exists
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return []  # Can't resolve — skip port scan

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_check_port, host, port, timeout): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    for port in sorted(open_ports):
        service, severity, description = COMMON_PORTS[port]

        # Skip "info" severity ports that are expected (80, 443, 22)
        if severity == "info" and port in (80, 443):
            continue

        findings.append({
            "title":       f"Open Port {port}/{service}",
            "severity":    severity,
            "vuln_type":   "Exposed Network Service",
            "url":         f"{host}:{port}",
            "description": description,
            "remediation": (
                f"If port {port} ({service}) is not required to be publicly accessible, "
                f"restrict access using firewall rules (iptables/ufw/security groups). "
                f"If required, ensure authentication and encryption are enforced."
            ),
            "evidence":    f"TCP connection to {host}:{port} succeeded (resolved IP: {ip})",
            "steps":       (
                f"1. Run: nc -zv {host} {port}\n"
                f"2. Confirm TCP handshake completes\n"
                f"3. Identify service banner if present"
            ),
            "poc":         f"nmap -sV -p {port} {host}",
            "impact":      f"Exposure of {service} on port {port} increases attack surface.",
        })

    return findings
