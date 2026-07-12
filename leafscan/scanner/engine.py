"""
LeafScan — Core Scan Engine
Orchestrates all scan modules, manages authorization gate, and collects findings.

Scanning techniques are based on publicly documented, established security research
methods (similar to Nmap, Nikto, OWASP ZAP). No custom exploit payloads are used.
"""
import time
import threading
import traceback
from datetime import datetime

# ── Module registry ────────────────────────────────────────────────────────────
def _load_modules():
    """Lazily import all scanner modules to keep startup fast."""
    from leafscan.scanner.modules import (
        port_scan, header_scan, tls_scan, dns_scan,
        dir_scan, xss_probe, sqli_probe, cve_patterns,
        info_disclosure, misconfig,
    )
    return {
        "ports":    ("🔍", port_scan.run),
        "headers":  ("🛡️ ", header_scan.run),
        "tls":      ("🔐", tls_scan.run),
        "dns":      ("🌐", dns_scan.run),
        "dirs":     ("📂", dir_scan.run),
        "xss":      ("⚡", xss_probe.run),
        "sqli":     ("💉", sqli_probe.run),
        "cve":      ("☢️ ", cve_patterns.run),
        "info":     ("📋", info_disclosure.run),
        "misconfig":("⚙️ ", misconfig.run),
    }

ALL_MODULES = list(_load_modules().keys()) if False else [
    "ports","headers","tls","dns","dirs","xss","sqli","cve","info","misconfig"
]

# ── Authorization gate ─────────────────────────────────────────────────────────
def require_authorization(target: str, flag_confirmed: bool = False) -> bool:
    """
    LEGAL GATE: Every scan must be explicitly authorized by the user.
    Returns True only if the user confirms they own or have written permission.
    """
    if flag_confirmed:
        return True

    from leafscan.ui.tui import console, HAS_RICH, warn

    if HAS_RICH and console:
        console.print()
        console.print("[bold red]⚠  AUTHORIZATION REQUIRED[/bold red]")
        console.print("[dim]LeafScan only performs authorized security testing.[/dim]")
        console.print()
        console.print(f"  Target: [bold white]{target}[/bold white]")
        console.print()
        console.print("  [bold]By confirming, you declare that:[/bold]")
        console.print("  [green]1.[/green] You own this system, OR")
        console.print("  [green]2.[/green] You have explicit written permission to test it.")
        console.print("  [green]3.[/green] You accept full legal responsibility for this scan.")
        console.print()
        console.print("  [dim]Unauthorized scanning is illegal under the CFAA and similar laws.[/dim]")
        console.print()

        from rich.prompt import Confirm
        return Confirm.ask(
            "[bold yellow]  Do you confirm you are authorized to scan this target?[/bold yellow]",
            default=False,
        )
    else:
        print("\n⚠  AUTHORIZATION REQUIRED")
        print(f"  Target: {target}")
        print("  You must own this system or have written permission to test it.")
        ans = input("  Do you confirm authorization? [y/N]: ").strip().lower()
        return ans == "y"


# ── Scan history ───────────────────────────────────────────────────────────────
def save_history_entry(target, report_id, finding_count, profile):
    """Append a scan record to the local history file."""
    try:
        import json
        from leafscan.core.config import CONFIG_DIR
        history_file = CONFIG_DIR / "scan_history.json"
        history = []
        if history_file.exists():
            try:
                with open(history_file) as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.insert(0, {
            "report_id":     report_id,
            "target":        target,
            "timestamp":     datetime.now().isoformat(),
            "findings":      finding_count,
            "profile":       profile,
        })
        # Keep last 200 entries
        history = history[:200]
        with open(history_file, "w") as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass


def load_history():
    """Return list of past scan entries."""
    try:
        import json
        from leafscan.core.config import CONFIG_DIR
        history_file = CONFIG_DIR / "scan_history.json"
        if not history_file.exists():
            return []
        with open(history_file) as f:
            return json.load(f)
    except Exception:
        return []


# ── Engine ─────────────────────────────────────────────────────────────────────
class ScanEngine:
    def __init__(self, target: str, config: dict, modules=None, verbose=False):
        self.target   = target.rstrip("/")
        self.config   = config
        self.modules  = modules or ALL_MODULES
        self.verbose  = verbose
        self.findings = []
        self._lock    = threading.Lock()

    def add_finding(self, finding: dict):
        """Thread-safe finding collector."""
        with self._lock:
            self.findings.append(finding)

    def run(self, live_callback=None, module_callback=None) -> list:
        """Execute all requested scan modules and return findings."""
        module_map = _load_modules()
        from leafscan.ui.tui import print_module_result

        for mod_name in self.modules:
            if mod_name not in module_map:
                continue
            icon, fn = module_map[mod_name]
            t0 = time.time()
            try:
                results = fn(self.target, self.config)
                elapsed = time.time() - t0
                for f in results:
                    self.add_finding(f)
                    if live_callback:
                        live_callback(f)
                if module_callback:
                    module_callback(mod_name, len(results))
                print_module_result(mod_name, icon, len(results), elapsed)
            except Exception as e:
                elapsed = time.time() - t0
                err_msg = str(e)
                print_module_result(mod_name, icon, 0, elapsed, error=err_msg)
                if self.verbose:
                    traceback.print_exc()

        return self.findings


def summarize(findings: list) -> dict:
    """Return severity count dict from a list of findings."""
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in out:
            out[sev] += 1
    return out


def run_scan(target, config, modules=None, authorized=False, verbose=False, live_callback=None, module_callback=None):
    """
    Top-level entry point for a scan run.
    Returns (findings, scan_duration_seconds).
    """
    from leafscan.ui.tui import print_scan_start, print_summary, warn

    profile = config.get("scan", {}).get("profile", "default")

    # Authorization gate
    if not require_authorization(target, authorized):
        warn("Scan aborted — authorization not confirmed.")
        return [], 0.0

    active_modules = modules or ALL_MODULES
    print_scan_start(target, profile, active_modules)

    engine = ScanEngine(target, config, modules=active_modules, verbose=verbose)
    t0 = time.time()
    findings = engine.run(live_callback=live_callback, module_callback=module_callback)
    elapsed  = time.time() - t0

    print_summary(findings, elapsed)
    return findings, elapsed
