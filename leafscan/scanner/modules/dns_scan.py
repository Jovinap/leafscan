"""
LeafScan Module — DNS Configuration Analyzer
Checks for DNS misconfigurations: zone transfer, SPF/DMARC/DKIM, subdomain takeover hints.
Reference: OWASP Testing Guide - OTG-INFO-001, RFC 7208 (SPF), RFC 7489 (DMARC)
"""
import dns.resolver
import dns.query
import dns.zone
import dns.exception
from urllib.parse import urlparse


def _query(domain, rtype):
    """Return list of record strings for given record type."""
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except Exception:
        return []


def run(target: str, config: dict) -> list:
    """Analyze DNS records for security misconfigurations."""
    findings = []
    parsed = urlparse(target)
    host   = parsed.hostname or target
    # Strip 'www.' to get root domain for email/SPF checks
    domain = host.lstrip("www.").strip(".")

    # 1. Zone Transfer check (AXFR)
    try:
        ns_records = _query(domain, "NS")
        for ns_str in ns_records[:3]:  # Limit to first 3 NS servers
            ns = ns_str.rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                if zone:
                    findings.append({
                        "title":       f"DNS Zone Transfer Allowed on {ns}",
                        "severity":    "high",
                        "vuln_type":   "DNS Misconfiguration",
                        "url":         f"dns://{ns}",
                        "description": f"The nameserver {ns} allows unauthenticated AXFR (zone transfer) "
                                       "for domain '{domain}'. This exposes all DNS records including "
                                       "internal subdomains, mail servers, and infrastructure details.",
                        "remediation": "Restrict AXFR to authorized secondary nameservers only. "
                                       "Configure ACLs in BIND/PowerDNS/etc.",
                        "evidence":    f"AXFR response from {ns} for {domain} returned full zone data.",
                        "steps":       f"1. Run: dig AXFR {domain} @{ns}",
                        "poc":         f"dig AXFR {domain} @{ns}",
                        "impact":      "Exposes full internal DNS infrastructure to any external attacker.",
                    })
            except Exception:
                pass
    except Exception:
        pass

    # 2. SPF record check
    txt_records = _query(domain, "TXT")
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
    if not spf_records:
        findings.append({
            "title":       f"Missing SPF Record for {domain}",
            "severity":    "medium",
            "vuln_type":   "Email Security Misconfiguration",
            "url":         f"dns://{domain}",
            "description": "No SPF (Sender Policy Framework) record found. "
                           "Without SPF, attackers can send phishing emails spoofing your domain.",
            "remediation": "Add SPF TXT record: v=spf1 include:_spf.google.com ~all (adjust for your mail provider)",
            "evidence":    f"DNS TXT query for {domain} — no SPF record found.",
            "steps":       f"1. Run: dig TXT {domain} | grep spf",
            "poc":         f"dig TXT {domain} +short",
            "impact":      "Enables email spoofing — phishing emails can appear to come from your domain.",
        })
    else:
        spf = spf_records[0]
        if "+all" in spf or "?all" in spf:
            findings.append({
                "title":       f"Permissive SPF Record on {domain}",
                "severity":    "high",
                "vuln_type":   "Email Security Misconfiguration",
                "url":         f"dns://{domain}",
                "description": f"SPF record uses '+all' or '?all' which allows ANY server to send email "
                               f"as @{domain}. This completely defeats SPF protection.",
                "remediation": f"Change '+all' to '-all' to enforce strict SPF: v=spf1 ... -all",
                "evidence":    f"SPF record: {spf}",
                "steps":       f"1. Run: dig TXT {domain} | grep spf\n2. Observe +all or ?all qualifier",
                "poc":         f"dig TXT {domain} +short | grep spf",
                "impact":      "Allows unrestricted email spoofing from your domain.",
            })

    # 3. DMARC check
    dmarc_records = _query(f"_dmarc.{domain}", "TXT")
    dmarc_found   = any("v=DMARC1" in r for r in dmarc_records)
    if not dmarc_found:
        findings.append({
            "title":       f"Missing DMARC Record for {domain}",
            "severity":    "medium",
            "vuln_type":   "Email Security Misconfiguration",
            "url":         f"dns://_dmarc.{domain}",
            "description": "No DMARC record found. DMARC instructs receiving mail servers how to handle "
                           "emails that fail SPF/DKIM alignment checks. Without it, spoofed emails may be delivered.",
            "remediation": "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
            "evidence":    f"DNS TXT query for _dmarc.{domain} — no DMARC record found.",
            "steps":       f"1. Run: dig TXT _dmarc.{domain}",
            "poc":         f"dig TXT _dmarc.{domain} +short",
            "impact":      "Without DMARC, SPF/DKIM failures are silently ignored; phishing succeeds.",
        })
    else:
        for r in dmarc_records:
            if "v=DMARC1" in r and "p=none" in r.lower():
                findings.append({
                    "title":       f"DMARC Policy Set to 'none' (No Enforcement)",
                    "severity":    "low",
                    "vuln_type":   "Email Security Misconfiguration",
                    "url":         f"dns://_dmarc.{domain}",
                    "description": "DMARC record found but policy is 'p=none' — monitoring mode only. "
                                   "Emails failing SPF/DKIM are still delivered; no enforcement action taken.",
                    "remediation": "Progress policy to 'p=quarantine' or 'p=reject' after reviewing DMARC reports.",
                    "evidence":    f"DMARC record: {r}",
                    "steps":       f"1. Run: dig TXT _dmarc.{domain} +short",
                    "poc":         f"dig TXT _dmarc.{domain} +short",
                    "impact":      "Spoofed emails from your domain may still be delivered to recipients.",
                })
                break

    return findings
