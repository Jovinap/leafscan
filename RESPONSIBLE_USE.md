## Responsible Use Policy — LeafScan v2.0

**Leaf Security AI (JJ Groups of Company) · Created by A.P.Jovin**

---

LeafScan is an authorized vulnerability scanner designed for:

- **Authorized penetration testing** on systems you own
- **Bug bounty** research on in-scope targets with explicit program authorization
- **Internal security assessments** with written organizational approval
- **Security education** in controlled lab environments

### You MUST have authorization before scanning

LeafScan requires explicit authorization **before every scan**:

1. **System ownership** — You own or directly control the system.
2. **Written permission** — You have explicit written authorization from the system owner.
3. **Bug bounty program scope** — The target is within the documented scope of an active bug bounty program.

### What LeafScan does (safe, documented techniques)

- Checks HTTP response headers for security misconfigurations
- Probes common TCP ports using TCP connect scanning (same as nmap -sT)
- Verifies TLS certificate validity, expiry, and cipher strength
- Checks DNS records for SPF/DMARC/zone-transfer misconfigurations
- Discovers common sensitive paths using HTTP requests (same as gobuster)
- Detects version strings in headers and matches against public CVE databases
- Identifies information disclosure patterns (API keys, stack traces) in responses
- Probes for reflected XSS by checking if safe marker strings appear unescaped

### What LeafScan does NOT do

- ❌ Execute exploit payloads or shellcode
- ❌ Attempt to gain unauthorized access
- ❌ Extract, exfiltrate, or modify any data
- ❌ Perform denial-of-service attacks
- ❌ Brute-force credentials or authentication systems
- ❌ Deploy malware or backdoors

### Legal notice

Unauthorized computer access is a criminal offense in most jurisdictions:

- **USA**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **UK**: Computer Misuse Act 1990
- **EU**: Directive 2013/40/EU on attacks against information systems
- **India**: IT Act 2000, Section 43 / Section 66
- **International**: Budapest Convention on Cybercrime

**The Leaf Security AI team and JJ Groups of Company accept no liability for misuse of this tool.**

### Reporting vulnerabilities responsibly

When you find a vulnerability using LeafScan:

1. **Do not exploit further** — Stop at detection, do not exfiltrate data
2. **Report responsibly** — Use the vendor's security disclosure contact or bug bounty platform
3. **Allow remediation time** — Follow standard 90-day responsible disclosure before public release
4. **Document authorization** — Keep records of your written permission

---

*By using LeafScan, you agree to these terms. For questions: apjovin@leafsecurity.ai*
