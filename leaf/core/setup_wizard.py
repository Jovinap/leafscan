"""
Leaf — First-Run Interactive Setup Wizard
Runs automatically when leaf is first installed
"""
import sys
import os
import platform
from pathlib import Path

def run_setup():
    from leaf.ui.tui import (
        print_banner, print_divider, prompt, confirm, info, success, warn, error, console, HAS_RICH
    )
    from leaf.core.config import (
        load_config, save_config, CONFIG_DIR, CONFIG_FILE, FINDINGS_DIR, REPORTS_DIR
    )
    from leaf.core.auth import LeafAPI

    # Non-interactive check (use defaults if no tty)
    is_interactive = sys.stdin.isatty()
    if not is_interactive:
        warn("Non-interactive terminal detected. Auto-applying defaults.")
        def prompt(question, default=None, password=False):
            return default
        def confirm(question, default=True):
            return default

    print_banner("Setup Wizard — Let's get you configured!")

    if HAS_RICH and console:
        console.print("  Welcome to [bold green]Leaf v2.0[/bold green] — World's First Continuous Bug Bounty Scanner\n")
        console.print("  [dim]Built by A.P.Jovin · Leaf Security AI · JJ Groups of Company[/dim]")
        console.print("  [dim]MIT Licensed Open Source · https://github.com/Jovinap/leaf[/dim]\n")

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
        console.print("  [dim]Connect Leaf to your Leaf Security AI platform instance[/dim]\n")

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
            ("google",       "Google Gemini (generativelanguage.googleapis.com)"),
            ("groq",         "Groq (api.groq.com)"),
            ("mistral",      "Mistral AI (api.mistral.ai)"),
            ("together",     "Together AI (api.together.xyz)"),
            ("cohere",       "Cohere (api.cohere.com)"),
            ("deepseek",     "DeepSeek (api.deepseek.com)"),
            ("perplexity",   "Perplexity (api.perplexity.ai)"),
            ("ollama",       "Ollama (localhost — fully local/free)"),
            ("openclaw",     "OpenClaw Proxy"),
            ("hermes",       "Hermes 3 (Nous Research)"),
            ("newclaw",      "NewClaw Inference"),
            ("cowork",       "CoWork Collaborative AI"),
            ("opencode",     "OpenCode Code Assistant"),
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

        choice = prompt(f"Select AI provider [1-{len(ai_providers)}]", default="1")
        try:
            idx = int(choice) - 1
            provider_key, _ = ai_providers[idx]
        except Exception:
            provider_key = "openrouter"

        # Import AI provider configurations
        from leaf.core.ai_client import AI_PROVIDERS
        p_info = AI_PROVIDERS.get(provider_key, {"url": "", "default_model": "gpt-4o-mini"})

        if provider_key == "ollama":
            api_url_ai = prompt("Ollama API URL", default=p_info["url"])
            ai_key = "ollama"
            ai_model = prompt("Ollama model name", default=p_info["default_model"])
        elif provider_key == "custom":
            api_url_ai = prompt("Custom API URL")
            ai_key = prompt("API key", default="", password=True)
            ai_model = prompt("Model name", default="gpt-4o-mini")
        else:
            api_url_ai = prompt(f"{provider_key.capitalize()} API URL", default=p_info["url"])
            ai_key = prompt(f"{provider_key.capitalize()} API key", default="", password=True)
            ai_model = prompt("Model", default=p_info["default_model"])

        cfg["ai"]["enabled"]  = True
        cfg["ai"]["provider"] = provider_key
        cfg["ai"]["api_url"]  = api_url_ai
        cfg["ai"]["api_key"]  = ai_key
        cfg["ai"]["model"]    = ai_model
        success(f"AI configured: {provider_key} ({ai_model})")
    else:
        cfg["ai"]["enabled"] = False
        info("AI integration skipped — you can enable it later with: leaf config set ai.enabled true")

    # Scan defaults
    print_divider("Scan Profile")
    if HAS_RICH and console:
        from leaf.core.config import SCAN_PROFILES
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
        console.print(f"  [dim]Log in to link Leaf with your Leaf Security AI account[/dim]\n")
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
            warn(f"Login failed: {msg} — you can login later with: leaf auth login")
    else:
        info("Skipped — login later with: leaf auth login")

    # Save config
    save_config(cfg)
    success(f"Config saved to {CONFIG_FILE}")

    # Done!
    print_divider()
    if HAS_RICH and console:
        console.print(f"""
  [bold green]🌿 Leaf is ready![/bold green]

  [bold]Quick Commands:[/bold]
  [green]leaf scan https://example.com[/green]              Scan a target
  [green]leaf scan https://target.com -c -s[/green]        Continuous + auto-submit
  [green]leaf scan https://target.com -m xss,sqli[/green]  Specific modules only
  [green]leaf programs[/green]                              List bug bounty programs
  [green]leaf report list[/green]                          View saved reports
  [green]leaf help[/green]                                  Full command reference

  [dim]Docs:   https://github.com/Jovinap/leaf/wiki[/dim]
  [dim]Issues: https://github.com/Jovinap/leaf/issues[/dim]
""")
    else:
        print("\n✅ Setup complete! Run: leaf help\n")

    return True
