# 🌿 Leaf v2.0

<div align="center">

```
  ██╗     ███████╗ █████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║     ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     █████╗  ███████║█████╗  ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██╔══╝  ██╔══██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████╗███████╗██║  ██║██║     ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**World's First Continuous Bug Bounty Scanner**  
*By [Leaf Security AI](https://leafsecurity.ai) — [JJ Groups of Company](https://jjgroups.com)*  
*Created by [A.P.Jovin](https://github.com/apjovin)*

[![PyPI version](https://img.shields.io/pypi/v/leaf?color=green&label=leaf)](https://pypi.org/project/leaf/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-red)](https://github.com/Jovinap/leaf)

</div>

---

> ⚠️ **AUTHORIZED USE ONLY** — Leaf is designed for **authorized security testing only**. You must own the target system or have explicit written permission before scanning. Unauthorized scanning is illegal. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

---

## 📦 Install

### One-line installer (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Jovinap/leaf/main/install.sh | bash
```

### pip install

```bash
pip install leaf
```

### From source

```bash
git clone https://github.com/Jovinap/leaf.git
cd leaf
pip install -e .
```

---

## 🚀 Quick Start

```bash
# 1. First-time setup (configure AI, platform, scan profile)
leaf setup

# 2. Scan your own application (interactive authorization prompt)
leaf scan https://your-app.com

# 3. Scan with --i-have-permission flag to skip the prompt
leaf scan https://your-app.com --i-have-permission

# 4. View the generated report
leaf report list
leaf report show 1
```

---

## 🔍 Scan Modules

Leaf includes 10 detection modules using **publicly documented, established techniques** — the same methods used by Nmap, Nikto, and OWASP ZAP:

| Module | Description | Technique |
|---|---|---|
| `ports` | Open TCP port detection | TCP connect scan (nmap -sT) |
| `headers` | HTTP security headers audit | OWASP Secure Headers Project |
| `tls` | TLS certificate & cipher analysis | ssl module / openssl-equivalent |
| `dns` | SPF/DMARC/zone-transfer check | DNS queries (RFC 7208, 7489) |
| `dirs` | Sensitive file/dir discovery | HTTP enumeration (gobuster-style) |
| `xss` | Reflected XSS passive probe | Marker reflection detection |
| `sqli` | SQL injection error detection | Error-based probe (OWASP OTG) |
| `cve` | Outdated software/CVE matching | Banner version fingerprinting |
| `info` | Sensitive data exposure | Pattern matching (CWE-200) |
| `misconfig` | CORS/cookie/HTTP method checks | OWASP A05:2021 |

### Example — Run specific modules

```bash
leaf scan https://example.com -m headers,tls,ports --i-have-permission
leaf scan https://example.com -m xss,sqli -p stealth --i-have-permission
```

---

## ⚙️ Scan Profiles

| Profile | Threads | Delay | Use Case |
|---|---|---|---|
| `stealth` | 2 | 2.0s | Minimize detection; slow but quiet |
| `default` | 8 | 0.3s | Balanced speed and coverage |
| `aggressive` | 20 | 0.0s | Maximum speed; noisier |

```bash
leaf scan https://example.com -p stealth --i-have-permission
```

---

## 📋 Command Reference

```
leaf scan <target>              Scan a target URL
leaf scan <target> -m <mods>   Run specific modules
leaf scan <target> -p stealth  Use stealth profile
leaf scan <target> --verbose   Verbose output

leaf setup                     First-run setup wizard
leaf history                   View past scan history
leaf history -n 50             Show last 50 scans

leaf report list               List saved reports
leaf report show <id>          Show a report
leaf report show 1             Show most recent report

leaf auth login                Log in to Leaf platform
leaf auth logout               Log out
leaf auth status               Show auth status

leaf config show               Show current config
leaf config set scan.threads 5 Update a config value
leaf config set ai.enabled true Enable AI classification

leaf update                    Update to latest version
leaf --version                 Show version
leaf help                      Show this reference
```

---

## 📊 Output Format

Leaf generates **two report formats** saved to `~/.leaf/`:

### Markdown Report (`~/.leaf/reports/`)
Human-readable with executive summary, CVSS scores, evidence, and remediation guidance.

```markdown
# Leaf Security Report
**Report ID:** `LS-20241215-143022`
**Target:** `https://example.com`

## Executive Summary
| Severity | Count |
|---|---|
| 🔴 Critical | 1 |
| 🟠 High | 3 |
| 🟡 Medium | 5 |
| 🔵 Low | 2 |

## Finding #1: Missing Security Header: Strict-Transport-Security
| Field | Value |
|---|---|
| Severity | HIGH |
| CVSS 3.1 Score | 8.0 |
| URL | https://example.com |

### Evidence
HTTP 200 response — header 'Strict-Transport-Security' absent.

### Remediation
Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### JSON Report (`~/.leaf/findings/`)
Machine-readable for integration with compliance platforms and bug bounty tools.

```json
{
  "report_id": "LS-20241215-143022",
  "target": "https://example.com",
  "scanner_version": "2.0.0",
  "findings": [
    {
      "title": "Missing Security Header: Strict-Transport-Security",
      "severity": "high",
      "vuln_type": "Security Misconfiguration",
      "evidence": "HTTP 200 — header absent",
      "remediation": "Add: Strict-Transport-Security: max-age=31536000..."
    }
  ]
}
```

---

## 🤖 AI Integration

Connect an AI model to automatically classify findings and generate bug report write-ups:

```bash
leaf config set ai.enabled true
leaf config set ai.api_key YOUR_OPENROUTER_KEY
leaf config set ai.model openai/gpt-4o-mini
```

Supports: **OpenAI, Anthropic Claude, Ollama (local), OpenRouter, any OpenAI-compatible API**.

---

## 🕒 Scan History

Leaf maintains a local scan history at `~/.leaf/scan_history.json`:

```bash
leaf history
```

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  #  Report ID            Target                  Findings  Date  │
  ├──────────────────────────────────────────────────────────────────┤
  │  1  LS-20241215-143022   https://example.com     11        2024  │
  │  2  LS-20241214-092211   https://staging.app.io  3         2024  │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Authorization & Legal

### Before scanning — you MUST have one of:
1. **Ownership** — You own or directly operate the system
2. **Written permission** — Explicit signed authorization from the system owner
3. **Bug bounty scope** — Target is within an active bug bounty program's documented scope

### Interactive authorization gate

Every `leaf scan` run includes an authorization confirmation:

```
⚠  AUTHORIZATION REQUIRED

  Target: https://target.com

  By confirming, you declare that:
  1. You own this system, OR
  2. You have explicit written permission to test it.
  3. You accept full legal responsibility for this scan.

  Do you confirm you are authorized to scan this target? [y/N]:
```

Use `--i-have-permission` to skip in automated/CI environments:

```bash
leaf scan https://staging.yourapp.com --i-have-permission
```

### Laws and regulations
Unauthorized scanning is illegal under:
- **USA**: CFAA (18 U.S.C. § 1030)
- **UK**: Computer Misuse Act 1990
- **EU**: Directive 2013/40/EU
- **India**: IT Act 2000

---

## 🛠 Configuration

Config file: `~/.leaf/config.toml`

```toml
[platform]
api_url  = "https://app.leafsecurity.ai"
username = "your-username"

[scan]
threads  = 8
timeout  = 12
delay    = 0.3
profile  = "default"

[ai]
enabled  = false
api_key  = ""
model    = "openai/gpt-4o-mini"
api_url  = "https://openrouter.ai/api/v1"

[output]
verbose       = false
save_findings = true
save_reports  = true
```

---

## 🏗️ Project Structure

```
leaf/
├── leaf/
│   ├── __init__.py         # Version, metadata
│   ├── cli.py              # CLI entrypoint (click)
│   ├── core/
│   │   ├── config.py       # Config management (~/.leaf/config.toml)
│   │   ├── auth.py         # Platform API client
│   │   └── setup_wizard.py # First-run interactive wizard
│   ├── scanner/
│   │   ├── engine.py       # Scan orchestrator + authorization gate
│   │   └── modules/
│   │       ├── port_scan.py    # TCP port scanner
│   │       ├── header_scan.py  # HTTP security headers
│   │       ├── tls_scan.py     # TLS/SSL analysis
│   │       ├── dns_scan.py     # DNS misconfiguration
│   │       ├── dir_scan.py     # Directory/file discovery
│   │       ├── xss_probe.py    # XSS reflection probe
│   │       ├── sqli_probe.py   # SQL injection error detection
│   │       ├── cve_patterns.py # CVE version matching
│   │       ├── info_disclosure.py  # Sensitive data exposure
│   │       └── misconfig.py    # CORS/cookie/methods
│   ├── report/
│   │   └── generator.py    # JSON + Markdown report generation
│   └── ui/
│       └── tui.py          # Rich-based terminal UI
├── install.sh              # One-line bash installer
├── pyproject.toml          # Modern Python build config
├── setup.py                # Legacy pip compatibility
├── RESPONSIBLE_USE.md      # Authorization & legal policy
└── README.md
```

---

## 📈 Roadmap

- [x] Core scanning engine with 10 modules
- [x] Rich terminal UI with color output
- [x] JSON + Markdown report generation
- [x] CVSS 3.1 scoring
- [x] AI-powered finding classification
- [x] Scan history and tracking
- [x] Setup wizard with AI provider selection
- [ ] Continuous monitoring daemon (`leaf daemon start`)
- [ ] Web dashboard UI
- [ ] GitHub Actions integration
- [ ] Slack/Discord webhook notifications
- [ ] Custom module SDK

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-module`
3. Follow the module template in `leaf/scanner/modules/`
4. Ensure all scanning techniques are documented and ethical
5. Submit a pull request with tests

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📄 License

**MIT License** — see [LICENSE](LICENSE) for details.

```
Copyright (c) 2024 A.P.Jovin, Leaf Security AI, JJ Groups of Company
```

---

## 🙋 About

**Leaf** is built and maintained by [A.P.Jovin](mailto:apjovin@leafsecurity.ai), CEO of [Leaf Security AI](https://leafsecurity.ai) — a division of **JJ Groups of Company**.

- 🌐 Website: [leafsecurity.ai](https://leafsecurity.ai)  
- 📧 Email: [apjovin@leafsecurity.ai](mailto:apjovin@leafsecurity.ai)  
- 🐛 Issues: [GitHub Issues](https://github.com/Jovinap/leaf/issues)  
- 💬 Discord: [Leaf Security Community](https://discord.gg/leafsecurity)

---

<div align="center">
<sub>🌿 Built with ❤️ by Leaf Security AI · JJ Groups of Company · MIT Licensed Open Source</sub>
</div>
