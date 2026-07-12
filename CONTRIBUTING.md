# Contributing to LeafScan

Thank you for your interest in contributing to LeafScan!

## Adding a Scan Module

Each module lives in `leafscan/scanner/modules/` and must implement a `run(target, config)` function:

```python
"""
LeafScan Module — Your Module Name
Brief description. Reference any public techniques/tools.
Reference: link to OWASP/RFC/CVE etc.
"""
import requests

def run(target: str, config: dict) -> list:
    """
    Returns a list of finding dicts. Each finding must have:
      - title:       str  (short descriptive title)
      - severity:    str  (critical/high/medium/low/info)
      - vuln_type:   str  (OWASP category or CWE type)
      - url:         str  (the affected URL or resource)
      - description: str  (what the issue is)
      - remediation: str  (how to fix it)
      - evidence:    str  (what was found / HTTP response snippet)
      - steps:       str  (how to reproduce)
      - poc:         str  (curl or command to reproduce)
      - impact:      str  (business/security impact)
    """
    findings = []
    # ... your detection logic ...
    return findings
```

Then register it in `leafscan/scanner/engine.py` in the `_load_modules()` function.

## Ethical Guidelines

All modules must:
- Use only documented, publicly-known detection techniques
- NOT execute exploit payloads or exfiltrate data
- NOT make destructive requests (no DROP, DELETE, data modification)
- Reference the technique source (OWASP, CVE, RFC, etc.)

## Pull Request Process

1. Fork and create a feature branch
2. Add your module with tests
3. Run `pytest` to confirm no regressions
4. Submit PR with a clear description of what the module detects
