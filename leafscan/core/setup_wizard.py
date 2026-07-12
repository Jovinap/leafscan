"""
LeafScan — First-Run Interactive Setup Wizard
Runs automatically when leafscan is first installed
"""
import sys
import os
import platform
from pathlib import Path

def run_setup():
    from leafscan.ui.tui import (
        print_banner, print_divider, prompt, confirm, info, success, warn, error, console, HAS_RICH
    )
    from leafscan.core.config import (
        load_config, save_config, CONFIG_DIR, CONFIG_FILE, FINDINGS_DIR, REPORTS_DIR
    )
    from leafscan.core.auth import LeafAPI

    print_banner("Setup Wizard — Let's get you configured!")

    if HAS_RICH and console:
        console.print("  Welcome to [bold green]LeafScan v2.0[/bold green] — World's First Continuous Bug Bounty Scanner\n")
        console.print("  [dim]Built by A.P.Jovin · Leaf Security AI · JJ Groups of Company[/dim]")
        console.print("  [dim]MIT Licensed Open Source · https://github.com/Jovinap/leafscan[/dim]\n")

    # System info
    print_divider("System Information")
    sys_info = {
        "OS":       f"{platform.system()} {platform.release()}",
        "Python":   sys.version.split()[0],
        "User":     os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "Home":     str(Path.home()),
        "Config":   str(CONFIG_FILE),
        "Findings": str(FINDINGS_DIR),
    }
    for k, v in sys_info.items():
        info(f"{k:<12} {v}")

    if HAS_RICH and console:
        console.print()

    # Platform configuration
    print_divider("Platform Configuration")

    cfg = load_config()

    if HAS_RICH and console:
        console.print("  [dim]Connect LeafScan to your Leaf Security AI platform instance[/dim]\n")

    api_url = prompt(
        "Platform API URL",
        default=cfg.get("platform", {}).get("api_url", "http://localhost:5000")
    )
    cfg["platform"]["api_url"] = api_url.rstrip("/")

    # AI configuration
    print_divider("AI Integration (Optional)")
    if HAS_RICH and console:
        console.print("  [dim]Connect an AI model to classify findings and generate write-ups[/dim]\n")

    use_ai = confirm("Enable AI-powered finding classification?", default=False)
    if use_ai:
        ai_providers = [
            ("openrouter",   "OpenRouter (openrouter.ai) — Recommended"),
            ("openai",       "OpenAI (api.openai.com)"),
            ("anthropic",    "Anthropic (api.anthropic.com)"),
            ("ollama",       "Ollama (localhost — fully local/free)"),
            ("custom",       "Custom endpoint"),
        ]
        if HAS_RICH and console:
            from rich.table import Table
            from rich import box
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("No.", style="green", width=4)
            t.add_column("Provider")
            for i, (k, v) in enumerate(ai_providers, 1):
                t.add_row(str(i), v)
            console.print(t)

        choice = prompt("Select AI provider [1-5]", default="1")
        try:
            idx = int(choice) - 1
            provider_key, _ = ai_providers[idx]
        except Exception:
            provider_key = "openrouter"

        if provider_key == "ollama":
            api_url_ai = "http://localhost:11434/v1"
            ai_key = "ollama"
            ai_model = prompt("Ollama model name", default="llama3.2")
        elif provider_key == "openai":
            api_url_ai = "https://api.openai.com/v1"
            ai_key = prompt("OpenAI API key", default="", password=True)
            ai_model = prompt("Model", default="gpt-4o-mini")
        elif provider_key == "anthropic":
            api_url_ai = "https://api.anthropic.com"
            ai_key = prompt("Anthropic API key", default="", password=True)
            ai_model = prompt("Model", default="claude-3-haiku-20240307")
        elif provider_key == "custom":
            api_url_ai = prompt("Custom API URL")
            ai_key = prompt("API key", default="", password=True)
            ai_model = prompt("Model name", default="gpt-4o-mini")
        else:  # openrouter
            api_url_ai = "https://openrouter.ai/api/v1"
            ai_key = prompt("OpenRouter API key (from openrouter.ai/keys)", default="", password=True)
            ai_model = prompt("Model", default="openai/gpt-4o-mini")

        cfg["ai"]["enabled"]  = True
        cfg["ai"]["api_url"]  = api_url_ai
        cfg["ai"]["api_key"]  = ai_key
        cfg["ai"]["model"]    = ai_model
        success(f"AI configured: {ai_model}")
    else:
        cfg["ai"]["enabled"] = False
        info("AI integration skipped — you can enable it later with: leafscan config set ai.enabled true")

    # Scan defaults
    print_divider("Scan Profile")
    if HAS_RICH and console:
        from leafscan.core.config import SCAN_PROFILES
        from rich.table import Table
        from rich import box
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
        t.add_column("Profile"); t.add_column("Threads"); t.add_column("Delay"); t.add_column("Description")
        for name, p in SCAN_PROFILES.items():
            t.add_row(name, str(p["threads"]), f"{p['delay']}s", p["description"])
        console.print(t)

    profile = prompt("Default scan profile", default="default")
    if profile not in ("default", "stealth", "aggressive"):
        profile = "default"
    cfg["scan"]["profile"] = profile
    success(f"Profile set: {profile}")

    # Authentication
    print_divider("Platform Authentication")
    if HAS_RICH and console:
        console.print(f"  [dim]Log in to link LeafScan with your Leaf Security AI account[/dim]\n")
        console.print(f"  [dim]Platform: {cfg['platform']['api_url']}[/dim]\n")

    do_login = confirm("Login to Leaf Security AI platform now?", default=True)
    if do_login:
        username = prompt("Username")
        import getpass
        password = getpass.getpass("  Password: ")

        api = LeafAPI(api_url=cfg["platform"]["api_url"])
        ok, msg = api.login(username, password)
        if ok:
            cfg["platform"]["token"]    = api.token
            cfg["platform"]["username"] = username
            success(f"Authenticated as @{username}!")
        else:
            warn(f"Login failed: {msg} — you can login later with: leafscan auth login")
    else:
        info("Skipped — login later with: leafscan auth login")

    # Save config
    save_config(cfg)
    success(f"Config saved to {CONFIG_FILE}")

    # Done!
    print_divider()
    if HAS_RICH and console:
        console.print(f"""
  [bold green]🌿 LeafScan is ready![/bold green]

  [bold]Quick Commands:[/bold]
  [green]leafscan scan https://example.com[/green]              Scan a target
  [green]leafscan scan https://target.com -c -s[/green]        Continuous + auto-submit
  [green]leafscan scan https://target.com -m xss,sqli[/green]  Specific modules only
  [green]leafscan programs[/green]                              List bug bounty programs
  [green]leafscan report list[/green]                          View saved reports
  [green]leafscan help[/green]                                  Full command reference

  [dim]Docs:   https://github.com/Jovinap/leafscan/wiki[/dim]
  [dim]Issues: https://github.com/Jovinap/leafscan/issues[/dim]
""")
    else:
        print("\n✅ Setup complete! Run: leafscan help\n")

    return True
