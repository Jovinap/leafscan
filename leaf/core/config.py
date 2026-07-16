"""
Leaf — Configuration Management
Stores settings in ~/.leaf/config.toml
"""
import os
import toml
from pathlib import Path

CONFIG_DIR   = Path.home() / ".leaf"
CONFIG_FILE  = CONFIG_DIR / "config.toml"
FINDINGS_DIR = CONFIG_DIR / "findings"
REPORTS_DIR  = CONFIG_DIR / "reports"
LOGS_DIR     = CONFIG_DIR / "logs"

DEFAULT_CONFIG = {
    "platform": {
        "api_url":  "http://localhost:5000",
        "token":    "",
        "username": "",
    },
    "scan": {
        "threads":       10,
        "timeout":       12,
        "delay":         0.3,
        "user_agent":    "Leaf/2.0 (Security Scanner; https://github.com/Jovinap/leaf)",
        "follow_redirects": True,
        "max_depth":     3,
        "profile":       "default",   # default | stealth | aggressive
    },
    "daemon": {
        "enabled":          False,
        "interval_minutes": 30,
        "auto_submit":      True,
        "min_severity":     "medium",
    },
    "output": {
        "verbose":       False,
        "save_findings": True,
        "color":         True,
        "save_reports":  True,
    },
    "ai": {
        "enabled":    False,
        "provider":   "openrouter",
        "api_key":    "",
        "model":      "openai/gpt-4o-mini",
        "api_url":    "https://openrouter.ai/api/v1",
    },
}

SCAN_PROFILES = {
    "stealth": {
        "threads": 2, "timeout": 20, "delay": 2.0,
        "description": "Slow & quiet — minimizes detection",
    },
    "default": {
        "threads": 8, "timeout": 12, "delay": 0.3,
        "description": "Balanced speed and stealth",
    },
    "aggressive": {
        "threads": 20, "timeout": 8, "delay": 0.0,
        "description": "Fast & loud — maximum coverage",
    },
}

def ensure_dirs():
    # Automatically migrate old configs from ~/.leafscan to ~/.leaf if needed
    old_config_dir = Path.home() / ".leafscan"
    old_config_file = old_config_dir / "config.toml"
    if old_config_file.exists() and not CONFIG_FILE.exists():
        try:
            import shutil
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(old_config_file, CONFIG_FILE)
            old_findings = old_config_dir / "findings"
            if old_findings.exists():
                shutil.copytree(old_findings, FINDINGS_DIR, dirs_exist_ok=True)
            old_reports = old_config_dir / "reports"
            if old_reports.exists():
                shutil.copytree(old_reports, REPORTS_DIR, dirs_exist_ok=True)
        except Exception:
            pass

    for d in [CONFIG_DIR, FINDINGS_DIR, REPORTS_DIR, LOGS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def load_config():
    ensure_dirs()
    if not CONFIG_FILE.exists():
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        cfg = toml.load(CONFIG_FILE)
        for section, values in DEFAULT_CONFIG.items():
            if section not in cfg:
                cfg[section] = values
            else:
                for key, val in values.items():
                    if key not in cfg[section]:
                        cfg[section][key] = val
        return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    ensure_dirs()
    with open(CONFIG_FILE, "w") as f:
        toml.dump(cfg, f)

def is_first_run():
    return not CONFIG_FILE.exists()

def get_token():
    return load_config().get("platform", {}).get("token", "")

def set_token(token, username=""):
    cfg = load_config()
    cfg["platform"]["token"] = token
    cfg["platform"]["username"] = username
    save_config(cfg)

def get_api_url():
    return load_config().get("platform", {}).get("api_url", "http://localhost:5000")
