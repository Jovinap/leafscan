"""
LeafScan Module — TLS/SSL Configuration Analyzer
Checks TLS version support, certificate validity, expiry, and cipher weaknesses.
Reference: OWASP TLS Cheat Sheet, Mozilla SSL Config Guide
"""
import ssl
import socket
import datetime
from urllib.parse import urlparse


def _get_cert_info(host: str, port: int = 443, timeout: int = 10):
    """Return (cert_dict, protocol_version, cipher_tuple) or raise."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cert    = tls.getpeercert()
            version = tls.version()
            cipher  = tls.cipher()
    return cert, version, cipher


def _supports_old_tls(host: str, port: int, timeout: int, version_const) -> bool:
    """Return True if server accepts a legacy TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except Exception:
        return False


def run(target: str, config: dict) -> list:
    """Analyze TLS configuration for common misconfigurations."""
    findings = []
    parsed   = urlparse(target)
    host     = parsed.hostname
    timeout  = config.get("scan", {}).get("timeout", 12)

    if not host:
        return []

    # Only relevant for HTTPS targets
    scheme = parsed.scheme or "https"
    if scheme not in ("https",):
        # Check if HTTPS is even available
        try:
            import requests
            r = requests.head(f"https://{host}", timeout=timeout, verify=False)
        except Exception:
            return []

    try:
        cert, version, cipher = _get_cert_info(host, 443, timeout)

        # 1. Certificate expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left  = (not_after - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append({
                        "title":       "Expired TLS Certificate",
                        "severity":    "critical",
                        "vuln_type":   "TLS/SSL Issue",
                        "url":         target,
                        "description": f"The TLS certificate expired on {not_after_str}. "
                                       "Browsers will show security warnings; connections may be rejected.",
                        "remediation": "Renew the certificate immediately. Use Let's Encrypt for free auto-renewal.",
                        "evidence":    f"Certificate notAfter: {not_after_str} ({abs(days_left)} days ago)",
                        "steps":       f"1. Run: echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -dates",
                        "poc":         f"openssl s_client -connect {host}:443 < /dev/null 2>&1 | grep -E 'notAfter|Verify return code'",
                        "impact":      "Expired cert breaks HTTPS trust; users see browser warnings; automated clients reject connections.",
                    })
                elif days_left < 30:
                    findings.append({
                        "title":       f"TLS Certificate Expiring Soon ({days_left} days)",
                        "severity":    "medium",
                        "vuln_type":   "TLS/SSL Issue",
                        "url":         target,
                        "description": f"Certificate expires in {days_left} days ({not_after_str}). "
                                       "Urgent renewal recommended to prevent service disruption.",
                        "remediation": "Renew certificate before expiry. Enable auto-renewal (certbot --auto-renew).",
                        "evidence":    f"Certificate notAfter: {not_after_str}",
                        "steps":       f"1. Run: echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -dates",
                        "poc":         f"openssl s_client -connect {host}:443 < /dev/null 2>&1 | grep notAfter",
                        "impact":      "Certificate expiry causes complete HTTPS outage and broken trust.",
                    })
            except Exception:
                pass

        # 2. Weak cipher check
        if cipher:
            cipher_name = cipher[0] if cipher else ""
            weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"]
            for weak in weak_ciphers:
                if weak.upper() in cipher_name.upper():
                    findings.append({
                        "title":       f"Weak TLS Cipher Suite: {cipher_name}",
                        "severity":    "high",
                        "vuln_type":   "TLS/SSL Issue",
                        "url":         target,
                        "description": f"Server negotiated weak cipher suite '{cipher_name}'. "
                                       "Weak ciphers can be broken via cryptanalytic attacks.",
                        "remediation": "Configure server to prefer ECDHE+AES256+GCM cipher suites only. "
                                       "See Mozilla SSL Config Generator: https://ssl-config.mozilla.org/",
                        "evidence":    f"Negotiated cipher: {cipher_name}",
                        "steps":       f"1. Run: nmap --script ssl-enum-ciphers -p 443 {host}",
                        "poc":         f"openssl s_client -connect {host}:443 -cipher {weak.lower()} 2>&1 | grep Cipher",
                        "impact":      "Weak ciphers allow decryption of TLS traffic by a network attacker.",
                    })
                    break

        # 3. TLS 1.0 support check
        if _supports_old_tls(host, 443, timeout, ssl.TLSVersion.TLSv1):
            findings.append({
                "title":       "TLS 1.0 Supported (Deprecated Protocol)",
                "severity":    "medium",
                "vuln_type":   "TLS/SSL Issue",
                "url":         target,
                "description": "Server accepts TLS 1.0 connections. TLS 1.0 was deprecated in 2020 "
                               "(RFC 8996) and has known vulnerabilities (POODLE, BEAST).",
                "remediation": "Disable TLS 1.0 and 1.1 in your web server config. "
                               "Enforce TLS 1.2 minimum (TLS 1.3 preferred).",
                "evidence":    f"TLS 1.0 handshake succeeded with {host}:443",
                "steps":       f"1. Run: nmap --script ssl-enum-ciphers -p 443 {host}\n2. Check for TLSv1.0 entries",
                "poc":         f"openssl s_client -connect {host}:443 -tls1 2>&1 | grep 'Protocol :'",
                "impact":      "Allows POODLE and BEAST downgrade attacks on encrypted sessions.",
            })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title":       "Invalid/Self-Signed TLS Certificate",
            "severity":    "high",
            "vuln_type":   "TLS/SSL Issue",
            "url":         target,
            "description": f"Certificate verification failed: {e}. "
                           "Self-signed or improperly issued certs are not trusted by browsers.",
            "remediation": "Replace with a CA-signed certificate (free via Let's Encrypt).",
            "evidence":    str(e),
            "steps":       f"1. Visit {target} in browser\n2. Check certificate warning details",
            "poc":         f"curl -v {target} 2>&1 | grep 'SSL certificate'",
            "impact":      "Browsers show security warnings; users may be MitM'd without realizing it.",
        })
    except ConnectionRefusedError:
        pass  # HTTPS not running on this host — port_scan will catch it
    except Exception:
        pass

    return findings
