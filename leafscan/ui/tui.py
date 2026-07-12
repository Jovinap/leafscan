"""
LeafScan — Beautiful Terminal UI (Rich-based)
Shows banners, scan progress, findings, summaries
"""
import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.rule import Rule
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import box
    from rich.align import Align
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console(highlight=False) if HAS_RICH else None

SEVERITY_COLORS  = {"critical":"bold red","high":"red","medium":"yellow","low":"cyan","info":"dim white"}
SEVERITY_EMOJIS  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
SEVERITY_BADGES  = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]","info":"[INFO]"}

ASCII_LOGO = r"""
  ██╗     ███████╗ █████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║     ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     █████╗  ███████║█████╗  ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██╔══╝  ██╔══██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████╗███████╗██║  ██║██║     ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"""

def print_banner(subtitle=None):
    if HAS_RICH:
        from leafscan import __version__, __author__, __company__, __github__
        console.print(ASCII_LOGO, style="bold green")
        console.print(
            Panel.fit(
                Align.center(
                    f"[bold white]{subtitle or 'World\'s First Continuous Bug Bounty Scanner'}[/bold white]\n"
                    f"[dim]v{__version__} · Built by {__author__} · {__company__}[/dim]\n"
                    f"[dim green]{__github__}[/dim green]"
                ),
                border_style="green",
                padding=(0, 4),
            )
        )
        console.print()
    else:
        print(ASCII_LOGO)
        print("  World's First Continuous Bug Bounty Scanner")
        print("  https://github.com/Jovinap/leafscan\n")

def print_divider(title=""):
    if HAS_RICH:
        console.print(Rule(f"[bold green]{title}[/bold green]" if title else "", style="green"))
    else:
        print("─" * 60 + (f" {title} " if title else ""))

def print_scan_start(url, profile, modules):
    if HAS_RICH:
        console.print(f"\n[bold green]▶  Target:[/bold green]  [bold white]{url}[/bold white]")
        console.print(f"   [dim]Profile:  {profile}[/dim]")
        console.print(f"   [dim]Modules:  {', '.join(modules)}[/dim]")
        console.print(f"   [dim]Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
    else:
        print(f"\n▶ Target: {url} | Profile: {profile}\n")

def print_module_result(mod_name, icon, count, elapsed, error=None):
    if HAS_RICH:
        if error:
            console.print(f"  {icon}  [dim]{mod_name:<22}[/dim] [red]✗ {error[:50]}[/red] [dim]({elapsed:.1f}s)[/dim]")
        elif count > 0:
            console.print(f"  {icon}  [bold]{mod_name:<22}[/bold] [bold red]● {count} finding{'s' if count!=1 else ''}[/bold red] [dim]({elapsed:.1f}s)[/dim]")
        else:
            console.print(f"  {icon}  [dim]{mod_name:<22}[/dim] [green]✓ Clean[/green] [dim]({elapsed:.1f}s)[/dim]")
    else:
        status = f"✗ {error}" if error else (f"● {count} findings" if count else "✓ Clean")
        print(f"  {icon}  {mod_name}: {status} ({elapsed:.1f}s)")

def print_finding_live(finding, idx):
    sev = finding.get("severity","info").lower()
    col = SEVERITY_COLORS.get(sev,"white")
    emoji = SEVERITY_EMOJIS.get(sev,"⚪")
    badge = SEVERITY_BADGES.get(sev,"[?]")
    if HAS_RICH:
        console.print(f"\n  {emoji} [{col}]{badge}[/{col}] [bold white]{finding.get('title','?')}[/bold white]")
        console.print(f"     [dim]URL:[/dim] {finding.get('url','')[:90]}")
        if finding.get("evidence"):
            console.print(f"     [dim]Evidence:[/dim] [italic]{finding['evidence'][:100]}[/italic]")
    else:
        print(f"\n  {emoji} {badge} {finding.get('title','?')}")
        print(f"     {finding.get('url','')}")

def print_summary(findings, elapsed):
    from leafscan.scanner.engine import summarize
    summary = summarize(findings)
    if HAS_RICH:
        console.print()
        print_divider("Scan Complete")
        console.print()
        tbl = Table(box=box.ROUNDED, border_style="green", header_style="bold green", show_header=True)
        tbl.add_column("Severity", style="bold", width=14)
        tbl.add_column("Count", justify="center", width=8)
        tbl.add_column("Severity Bar", width=30)
        for sev, cnt in summary.items():
            col = SEVERITY_COLORS.get(sev,"white")
            emoji = SEVERITY_EMOJIS.get(sev,"⚪")
            bar = "■" * min(cnt, 25)
            tbl.add_row(
                f"{emoji} [{col}]{sev.upper()}[/{col}]",
                f"[{col}]{cnt}[/{col}]" if cnt else "[dim]0[/dim]",
                f"[{col}]{bar}[/{col}]",
            )
        tbl.add_row("[bold]TOTAL[/bold]", f"[bold]{len(findings)}[/bold]", f"[dim]in {elapsed:.1f}s[/dim]")
        console.print(tbl)
    else:
        print("\n=== Summary ===")
        for sev, cnt in summary.items():
            print(f"  {sev.upper()}: {cnt}")
        print(f"  TOTAL: {len(findings)} in {elapsed:.1f}s")

def prompt(question, default=None, password=False):
    if HAS_RICH:
        return Prompt.ask(f"[bold green]?[/bold green] {question}", default=default, password=password)
    else:
        suffix = f" [{default}]" if default else ""
        return input(f"? {question}{suffix}: ") or default

def confirm(question, default=True):
    if HAS_RICH:
        return Confirm.ask(f"[bold green]?[/bold green] {question}", default=default)
    else:
        ans = input(f"? {question} [Y/n]: ").strip().lower()
        return ans in ("", "y", "yes")

def info(msg):
    if HAS_RICH:
        console.print(f"  [dim]ℹ {msg}[/dim]")
    else:
        print(f"  ℹ {msg}")

def success(msg):
    if HAS_RICH:
        console.print(f"  [bold green]✓ {msg}[/bold green]")
    else:
        print(f"  ✓ {msg}")

def error(msg):
    if HAS_RICH:
        console.print(f"  [bold red]✗ {msg}[/bold red]")
    else:
        print(f"  ✗ {msg}")

def warn(msg):
    if HAS_RICH:
        console.print(f"  [bold yellow]⚠ {msg}[/bold yellow]")
    else:
        print(f"  ⚠ {msg}")
