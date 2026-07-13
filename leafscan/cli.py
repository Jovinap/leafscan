"""
LeafScan v2.0 — CLI Entrypoint
World's First Continuous Bug Bounty Scanner
By Leaf Security AI (JJ Groups of Company) · Created by A.P.Jovin

RESPONSIBLE USE: This tool is for AUTHORIZED security testing only.
Unauthorized scanning is illegal. Always obtain written permission before scanning.
"""
import sys
import click
from pathlib import Path

from leafscan import __version__, __author__, __company__, __github__

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    from leafscan.ui.tui import console, HAS_RICH, ASCII_LOGO
    if HAS_RICH:
        console.print(ASCII_LOGO, style="bold green")
        console.print(f"\n  [bold green]LeafScan[/bold green] v[bold]{__version__}[/bold]")
        console.print(f"  [dim]By {__author__} · {__company__}[/dim]")
        console.print(f"  [dim]{__github__}[/dim]\n")
    else:
        print(f"LeafScan v{__version__} by {__author__} ({__company__})")
    ctx.exit()


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, is_eager=True, expose_value=False,
              callback=print_version, help="Show version and exit.")
@click.pass_context
def main(ctx):
    """
    🌿 LeafScan v2.0 — Authorized Vulnerability Scanner

    \b
    World's First Continuous Bug Bounty Scanner
    By Leaf Security AI (JJ Groups of Company)
    Created by A.P.Jovin · MIT License

    \b
    RESPONSIBLE USE:
      Only scan systems you own or have written permission to test.
      Unauthorized scanning is illegal under the CFAA and similar laws.

    \b
    QUICK START:
      leafscan setup                         First-run configuration wizard
      leafscan scan https://target.com       Scan a target (requires authorization)
      leafscan history                       View past scan history
      leafscan report list                   List saved reports
      leafscan update                        Update LeafScan to latest version
    """
    if ctx.invoked_subcommand is None:
        # Check if first run
        from leafscan.core.config import is_first_run
        if is_first_run():
            click.echo("\n  No config found. Run: leafscan setup\n")
        else:
            click.echo(ctx.get_help())


# ── leafscan setup ─────────────────────────────────────────────────────────────
@main.command()
def setup():
    """Run the first-time setup wizard (configure AI, platform, scan profiles)."""
    from leafscan.core.setup_wizard import run_setup
    try:
        run_setup()
    except KeyboardInterrupt:
        click.echo("\n\n  Setup interrupted. Run 'leafscan setup' to try again.\n")
        sys.exit(0)


# ── leafscan scan ──────────────────────────────────────────────────────────────
@main.command()
@click.argument("target")
@click.option("--modules", "-m", default=None,
              help="Comma-separated list of modules: ports,headers,tls,dns,dirs,xss,sqli,cve,info,misconfig")
@click.option("--profile", "-p", default=None,
              type=click.Choice(["stealth", "default", "aggressive"]),
              help="Scan profile: stealth, default, or aggressive.")
@click.option("--output", "-o", default=None,
              help="Save report to a custom directory or file prefix.")
@click.option("--json-only", is_flag=True, default=False,
              help="Only save JSON output (no markdown report).")
@click.option("--verbose", "-V", is_flag=True, default=False,
              help="Show verbose/debug output including errors.")
@click.option("--i-have-permission", "authorized", is_flag=True, default=False,
              help="Confirm you own or have written authorization to test this target.")
@click.option("--no-save", is_flag=True, default=False,
              help="Do not save report to disk (print to terminal only).")
@click.option("--continuous", "-c", is_flag=True, default=False,
              help="Run scan continuously in a loop.")
@click.option("--submit", "-s", is_flag=True, default=False,
              help="Auto-submit findings to the Leaf Security AI platform.")
def scan(target, modules, profile, output, json_only, verbose, authorized, no_save, continuous, submit):
    """
    Scan a target for vulnerabilities.

    \b
    TARGET must be a full URL (e.g. https://example.com) or hostname.

    \b
    AUTHORIZATION:
      You MUST confirm you own the target or have written permission.
      Use --i-have-permission flag to skip the interactive prompt,
      or respond 'y' to the authorization prompt.

    \b
    EXAMPLES:
      leafscan scan https://example.com --i-have-permission
      leafscan scan https://app.local -m headers,tls,ports -p stealth
      leafscan scan https://target.com -m xss,sqli --verbose
    """
    from leafscan.core.config import load_config, SCAN_PROFILES
    from leafscan.scanner.engine import run_scan, ALL_MODULES
    from leafscan.report.generator import save_report, ai_classify_finding
    from leafscan.scanner.engine import save_history_entry
    from leafscan.ui.tui import print_banner, success, warn, error, info, console, HAS_RICH

    print_banner()

    # Normalize target URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Load config
    cfg = load_config()

    # Run authorization gate once before the loop
    from leafscan.scanner.engine import require_authorization
    if not require_authorization(target, authorized):
        warn("Scan aborted — authorization not confirmed.")
        sys.exit(0)

    # Initialize LeafAPI client if authenticated
    api = None
    from leafscan.core.auth import LeafAPI
    try:
        api = LeafAPI()
    except Exception:
        pass

    def live_callback(finding):
        if api and api.is_authenticated():
            # Real-time scan event
            api.push_scan_event("finding", finding)
            if submit or cfg.get("daemon", {}).get("auto_submit", True):
                # Auto-submit finding to database
                api.submit_finding("zybrai", finding)

    def module_callback(mod_name, count):
        if api and api.is_authenticated():
            api.push_scan_event("module_done", {"module": mod_name, "count": count})

    # Apply profile override
    if profile:
        cfg["scan"]["profile"] = profile
    p = cfg["scan"].get("profile", "default")
    if p in SCAN_PROFILES:
        for k, v in SCAN_PROFILES[p].items():
            if k in cfg["scan"] and k != "description":
                cfg["scan"][k] = v

    # Parse modules
    active_modules = ALL_MODULES
    if modules:
        active_modules = [m.strip() for m in modules.split(",") if m.strip()]
        invalid = [m for m in active_modules if m not in ALL_MODULES]
        if invalid:
            error(f"Unknown modules: {', '.join(invalid)}")
            info(f"Valid modules: {', '.join(ALL_MODULES)}")
            sys.exit(1)

    import time
    interval = cfg.get("daemon", {}).get("interval_minutes", 30) * 60

    try:
        while True:
            # Run scan
            findings, elapsed = run_scan(
                target,
                config=cfg,
                modules=active_modules,
                authorized=True,  # Bypassed because gate checked above
                verbose=verbose,
                live_callback=live_callback,
                module_callback=module_callback,
            )

            # AI classification (if enabled)
            if cfg.get("ai", {}).get("enabled"):
                from leafscan.report.generator import ai_classify_finding
                info("Running AI classification on findings...")
                findings = [ai_classify_finding(f, cfg) for f in findings]

            # Save report
            if not no_save and cfg.get("output", {}).get("save_reports", True):
                try:
                    report_id, md_path, json_path = save_report(
                        target, findings, elapsed, cfg["scan"].get("profile", "default"), cfg
                    )
                    save_history_entry(target, report_id, len(findings), cfg["scan"].get("profile", "default"))

                    if HAS_RICH and console:
                        console.print()
                        console.print(f"  [bold green]✓ Report saved[/bold green]")
                        console.print(f"    [dim]Markdown:[/dim] [link={md_path}]{md_path}[/link]")
                        console.print(f"    [dim]JSON:    [/dim] [link={json_path}]{json_path}[/link]")
                        console.print(f"    [dim]ID:      [/dim] {report_id}")
                        console.print()
                    else:
                        print(f"\n  ✓ Report: {md_path}")
                        print(f"  ✓ JSON:   {json_path}")
                except Exception as e:
                    warn(f"Could not save report: {e}")
            elif no_save and findings:
                import json
                click.echo(json.dumps(findings, indent=2))

            if not continuous:
                break

            info(f"Continuous mode active. Sleeping for {interval} seconds before next run...")
            time.sleep(interval)
            print_banner("Running next scheduled scan round...")

    except KeyboardInterrupt:
        warn("\nScan interrupted by user.")
        sys.exit(0)


# ── leafscan history ───────────────────────────────────────────────────────────
@main.command()
@click.option("--limit", "-n", default=20, help="Number of entries to show.")
def history(limit):
    """View past scan history."""
    from leafscan.scanner.engine import load_history
    from leafscan.ui.tui import console, HAS_RICH, print_banner, print_divider

    print_banner("Scan History")

    entries = load_history()
    if not entries:
        click.echo("  No scan history yet. Run: leafscan scan https://target.com\n")
        return

    if HAS_RICH and console:
        from rich.table import Table
        from rich import box
        tbl = Table(box=box.ROUNDED, border_style="green", header_style="bold green")
        tbl.add_column("#",          width=4,  justify="right")
        tbl.add_column("Report ID",  width=18)
        tbl.add_column("Target",     width=35)
        tbl.add_column("Findings",   width=10, justify="center")
        tbl.add_column("Profile",    width=10)
        tbl.add_column("Date",       width=20)

        for i, e in enumerate(entries[:limit], 1):
            count = e.get("findings", 0)
            cnt_str = f"[bold red]{count}[/bold red]" if count else "[dim]0[/dim]"
            tbl.add_row(
                str(i),
                e.get("report_id", "?"),
                e.get("target", "?")[:35],
                cnt_str,
                e.get("profile", "?"),
                e.get("timestamp", "?")[:19],
            )
        console.print(tbl)
        console.print(f"\n  [dim]Showing {min(limit, len(entries))} of {len(entries)} scans.[/dim]\n")
    else:
        for i, e in enumerate(entries[:limit], 1):
            print(f"  {i}. {e.get('report_id')} | {e.get('target')} | {e.get('findings',0)} findings | {e.get('timestamp','')[:19]}")


# ── leafscan report ────────────────────────────────────────────────────────────
@main.group()
def report():
    """Manage saved vulnerability reports."""
    pass


@report.command("list")
@click.option("--limit", "-n", default=20)
def report_list(limit):
    """List saved reports."""
    from leafscan.report.generator import list_reports
    from leafscan.ui.tui import console, HAS_RICH, print_banner

    print_banner("Saved Reports")
    reports = list_reports()

    if not reports:
        click.echo("  No reports saved yet. Run: leafscan scan https://target.com\n")
        return

    if HAS_RICH and console:
        from rich.table import Table
        from rich import box
        tbl = Table(box=box.ROUNDED, border_style="green", header_style="bold green")
        tbl.add_column("#",      width=4, justify="right")
        tbl.add_column("Name",   width=50)
        tbl.add_column("Size",   width=10, justify="right")
        tbl.add_column("Date",   width=20)
        for i, r in enumerate(reports[:limit], 1):
            tbl.add_row(str(i), r["name"][:50], f"{r['size']:,}B", str(r["mtime"])[:19])
        console.print(tbl)
        console.print()
    else:
        for i, r in enumerate(reports[:limit], 1):
            print(f"  {i}. {r['name']} ({r['size']}B) — {r['mtime']}")


@report.command("show")
@click.argument("name_or_number")
def report_show(name_or_number):
    """Show a specific saved report."""
    from leafscan.report.generator import list_reports
    from leafscan.core.config import REPORTS_DIR

    reports = list_reports()
    if not reports:
        click.echo("No reports found.")
        return

    target_report = None
    if name_or_number.isdigit():
        idx = int(name_or_number) - 1
        if 0 <= idx < len(reports):
            target_report = reports[idx]
    else:
        for r in reports:
            if name_or_number in r["name"]:
                target_report = r
                break

    if not target_report:
        click.echo(f"Report not found: {name_or_number}")
        sys.exit(1)

    click.echo(target_report["file"].read_text())


# ── leafscan update ────────────────────────────────────────────────────────────
@main.command()
def update():
    """Update LeafScan to the latest version from PyPI."""
    import subprocess
    from leafscan.ui.tui import console, HAS_RICH, print_banner, success, info, warn

    print_banner("Update")
    info(f"Current version: {__version__}")
    info("Checking PyPI for latest version...")

    try:
        import requests
        r = requests.get("https://pypi.org/pypi/leafscan/json", timeout=10)
        if r.ok:
            latest = r.json()["info"]["version"]
            info(f"Latest version: {latest}")
            if latest == __version__:
                success("LeafScan is already up to date!")
                return
        else:
            latest = None
    except Exception:
        latest = None
        warn("Could not check PyPI — proceeding with pip upgrade anyway.")

    if HAS_RICH and console:
        from rich.prompt import Confirm
        if not Confirm.ask(f"[bold green]?[/bold green] Upgrade to latest version?", default=True):
            return

    info("Running: pip install --upgrade leafscan")
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "leafscan"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Self-heal PEP 668 externally-managed-environment restriction on Kali/Debian/Ubuntu
        if result.returncode != 0 and "externally-managed-environment" in result.stderr:
            info("Externally-managed environment detected. Appending --break-system-packages...")
            cmd.append("--break-system-packages")
            result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            success("LeafScan updated successfully! Restart your terminal or run 'leafscan --version'.")
        else:
            warn(f"Update may have failed:\n{result.stderr}")
    except Exception as e:
        warn(f"Could not run pip: {e}")
        info("Try manually: pip install --upgrade leafscan")


# ── leafscan auth ──────────────────────────────────────────────────────────────
@main.group()
def auth():
    """Manage Leaf Security AI platform authentication."""
    pass


@auth.command("login")
@click.option("--url", default=None, help="Platform API URL override.")
def auth_login(url):
    """Log in to the Leaf Security AI platform."""
    import getpass
    from leafscan.core.auth import LeafAPI
    from leafscan.core.config import load_config, save_config
    from leafscan.ui.tui import prompt, success, warn, error, print_banner

    print_banner("Platform Login")
    cfg = load_config()
    if url:
        cfg["platform"]["api_url"] = url

    username = prompt("Username")
    password = getpass.getpass("  Password: ")

    api = LeafAPI(api_url=cfg["platform"]["api_url"])
    ok, msg = api.login(username, password)
    if ok:
        cfg["platform"]["token"]    = api.token
        cfg["platform"]["username"] = username
        save_config(cfg)
        success(f"Logged in as @{username}")
    else:
        error(f"Login failed: {msg}")
        sys.exit(1)


@auth.command("logout")
def auth_logout():
    """Log out and clear saved credentials."""
    from leafscan.core.config import load_config, save_config
    from leafscan.ui.tui import success
    cfg = load_config()
    cfg["platform"]["token"]    = ""
    cfg["platform"]["username"] = ""
    save_config(cfg)
    success("Logged out.")


@auth.command("status")
def auth_status():
    """Show current authentication status."""
    from leafscan.core.auth import LeafAPI
    from leafscan.core.config import load_config
    from leafscan.ui.tui import console, HAS_RICH, success, warn

    cfg = load_config()
    username = cfg.get("platform", {}).get("username", "")
    token    = cfg.get("platform", {}).get("token", "")
    api_url  = cfg.get("platform", {}).get("api_url", "")

    if token and username:
        success(f"Logged in as @{username} — {api_url}")
    else:
        warn("Not authenticated. Run: leafscan auth login")


# ── leafscan config ────────────────────────────────────────────────────────────
@main.command("config")
@click.argument("action", type=click.Choice(["show", "set", "reset"]))
@click.argument("key_value", nargs=-1)
def config_cmd(action, key_value):
    """
    Manage LeafScan configuration.

    \b
    EXAMPLES:
      leafscan config show
      leafscan config set scan.threads 20
      leafscan config set ai.enabled true
      leafscan config reset
    """
    from leafscan.core.config import load_config, save_config, DEFAULT_CONFIG, CONFIG_FILE
    from leafscan.ui.tui import console, HAS_RICH, success, info, warn, error

    if action == "show":
        import json
        cfg = load_config()
        if HAS_RICH and console:
            import toml
            console.print(f"\n  [dim]Config file: {CONFIG_FILE}[/dim]\n")
            console.print_json(json.dumps(cfg))
        else:
            import json
            print(json.dumps(load_config(), indent=2))

    elif action == "set":
        if len(key_value) < 2:
            error("Usage: leafscan config set <section.key> <value>")
            sys.exit(1)
        key, val = key_value[0], key_value[1]
        cfg = load_config()
        parts = key.split(".")
        if len(parts) != 2:
            error("Key must be in format: section.key (e.g. scan.threads)")
            sys.exit(1)
        section, k = parts
        if section not in cfg:
            cfg[section] = {}
        # Type coercion
        if val.lower() in ("true", "yes"): val = True
        elif val.lower() in ("false", "no"): val = False
        elif val.isdigit(): val = int(val)
        else:
            try: val = float(val)
            except ValueError: pass
        cfg[section][k] = val
        save_config(cfg)
        success(f"Set {key} = {val}")

    elif action == "reset":
        save_config(DEFAULT_CONFIG)
        success("Config reset to defaults.")


# ── leafscan help (alias) ──────────────────────────────────────────────────────
@main.command("help")
def help_cmd():
    """Show detailed help and command reference."""
    from leafscan.ui.tui import console, HAS_RICH, print_banner, print_divider, ASCII_LOGO

    print_banner("Command Reference")

    if HAS_RICH and console:
        console.print("""
  [bold green]SCANNING[/bold green]
  [green]leafscan scan <target>[/green]                    Scan a target URL
  [green]leafscan scan <target> --i-have-permission[/green] Skip auth prompt (you confirmed authorization)
  [green]leafscan scan <target> -m headers,tls,ports[/green] Only run specific modules
  [green]leafscan scan <target> -p stealth[/green]         Use stealth scan profile
  [green]leafscan scan <target> --verbose[/green]          Show detailed module output

  [bold green]SCAN MODULES[/bold green]
  ports     · TCP port scanner (common web/admin ports)
  headers   · HTTP security headers check
  tls       · TLS/SSL certificate and cipher analysis
  dns       · DNS misconfiguration (SPF, DMARC, zone transfer)
  dirs      · Sensitive file/directory discovery
  xss       · Reflected XSS probe (passive reflection detection)
  sqli      · SQL injection probe (error-based detection)
  cve       · Outdated software / known CVE pattern matching
  info      · Sensitive data exposure (API keys, tokens, stack traces)
  misconfig · CORS, cookie security, HTTP methods, directory listing

  [bold green]REPORTS & HISTORY[/bold green]
  [green]leafscan history[/green]                          View scan history
  [green]leafscan report list[/green]                      List saved reports
  [green]leafscan report show <id>[/green]                 Show report content

  [bold green]SETUP & AUTH[/bold green]
  [green]leafscan setup[/green]                            First-run setup wizard
  [green]leafscan auth login[/green]                       Log in to platform
  [green]leafscan auth logout[/green]                      Log out
  [green]leafscan auth status[/green]                      Show auth status
  [green]leafscan config show[/green]                      Show current config
  [green]leafscan config set <key> <value>[/green]         Update a config value
  [green]leafscan update[/green]                           Update to latest version
  [green]leafscan --version[/green]                        Show version

  [bold green]RESPONSIBLE USE[/bold green]
  [dim]• Only scan systems you own or have explicit written permission to test[/dim]
  [dim]• Unauthorized scanning is illegal under CFAA, Computer Misuse Act, etc.[/dim]
  [dim]• Reports are for authorized compliance, bug bounty, or internal use only[/dim]
  [dim]• See: https://github.com/Jovinap/leafscan/blob/main/RESPONSIBLE_USE.md[/dim]
""")
    else:
        print("\n  Run 'leafscan --help' for command reference.\n")


# ── leafscan chain ─────────────────────────────────────────────────────────────
@main.command()
@click.argument("report_id_or_file", required=False)
def chain(report_id_or_file):
    """
    Simulate an exploit chain from scan findings.
    
    If REPORT_ID_OR_FILE is omitted, the latest scan report will be analyzed.
    """
    from leafscan.ui.tui import console, HAS_RICH, print_banner, info, error
    from leafscan.core.config import load_config
    from leafscan.core.chain_simulator import simulate_exploit_chain

    print_banner("Exploit Chain Simulation")

    # Load findings
    data, err_msg = _load_findings_helper(report_id_or_file)
    if err_msg:
        error(err_msg)
        sys.exit(1)

    target = data.get("target", "unknown-target")
    findings = data.get("findings", [])
    info(f"Target: {target}")
    info(f"Loaded {len(findings)} findings from report: {data.get('report_id')}")

    cfg = load_config()
    result = simulate_exploit_chain(findings, target, cfg)

    if HAS_RICH and console:
        from rich.markdown import Markdown
        console.print(Markdown(result))
    else:
        print(result)


# ── leafscan patch ─────────────────────────────────────────────────────────────
@main.command()
@click.argument("finding_index_or_id")
@click.option("--dir", "source_dir", required=True, help="Local directory of the target codebase.")
@click.option("--report", "report_id_or_file", default=None, help="The report containing the finding (uses latest if omitted).")
def patch(finding_index_or_id, source_dir, report_id_or_file):
    """
    Generate an AI code patch to remediate a finding.
    
    FINDING_INDEX_OR_ID is the index (1-based number) of the finding in the report.
    """
    from leafscan.ui.tui import console, HAS_RICH, print_banner, info, error
    from leafscan.core.config import load_config
    from leafscan.core.patch_generator import generate_git_patch

    print_banner("AI Code Patch Generator")

    # Load findings
    data, err_msg = _load_findings_helper(report_id_or_file)
    if err_msg:
        error(err_msg)
        sys.exit(1)

    findings = data.get("findings", [])
    if not findings:
        error("No findings present in the report to patch.")
        sys.exit(1)

    target_finding = None
    if finding_index_or_id.isdigit():
        idx = int(finding_index_or_id) - 1
        if 0 <= idx < len(findings):
            target_finding = findings[idx]
    else:
        # Search by title match
        for f in findings:
            if finding_index_or_id.lower() in f.get("title", "").lower():
                target_finding = f
                break

    if not target_finding:
        error(f"Finding not found matching: '{finding_index_or_id}'")
        sys.exit(1)

    info(f"Target Finding: {target_finding.get('title')}")
    info(f"Local Source Directory: {source_dir}")

    cfg = load_config()
    result = generate_git_patch(target_finding, source_dir, cfg)

    if HAS_RICH and console:
        console.print(result)
    else:
        print(result)


def _load_findings_helper(report_name_or_id):
    from leafscan.report.generator import list_reports
    from leafscan.core.config import FINDINGS_DIR
    import json

    reports = list_reports()
    if not reports:
        return None, "No reports found. Run a scan first."

    target_report = None
    if not report_name_or_id:
        target_report = reports[0]
    elif report_name_or_id.isdigit():
        idx = int(report_name_or_id) - 1
        if 0 <= idx < len(reports):
            target_report = reports[idx]
    else:
        for r in reports:
            if report_name_or_id in r["name"]:
                target_report = r
                break

    if not target_report:
        return None, f"Report '{report_name_or_id}' not found."

    json_path = FINDINGS_DIR / f"{target_report['name']}.json"
    if not json_path.exists():
        return None, f"JSON findings file not found at: {json_path}"

    try:
        with open(json_path) as f:
            data = json.load(f)
            return data, None
    except Exception as e:
        return None, f"Failed to load JSON findings: {e}"


if __name__ == "__main__":
    main()
