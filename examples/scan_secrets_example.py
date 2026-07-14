#!/usr/bin/env python3
"""
Leaf API Example — Programmatic Secrets & Information Disclosure Auditing

This example demonstrates how to import and run Leaf's core scanning engine
programmatically to analyze targets and local directory trees for leaked tokens.
"""

import os
import json
from leaf.core.config import DEFAULT_CONFIG
from leaf.scanner.engine import ScanEngine
from leaf.scanner.modules import sast_checks, info_disclosure

def run_local_sast_audit(directory_path: str):
    print(f"[*] Starting local SAST codebase audit on: {directory_path}")
    if not os.path.exists(directory_path):
        print(f"[!] Error: Directory {directory_path} does not exist.")
        return

    findings = sast_checks.run_local_sast(directory_path)
    print(f"[+] Local SAST audit finished. Found {len(findings)} issues:")
    for idx, finding in enumerate(findings, 1):
        print(f"  {idx}. [{finding.get('severity').upper()}] {finding.get('title')}")
        print(f"     Location: {finding.get('url')}")
        print(f"     Evidence: {finding.get('evidence')}\n")

def run_web_disclosure_scan(target_url: str):
    print(f"[*] Starting web-exposed asset scan on: {target_url}")
    # Initialize engine with default config
    config = DEFAULT_CONFIG
    findings = info_disclosure.run(target_url, config)
    
    print(f"[+] Web scan finished. Found {len(findings)} exposed data vulnerabilities:")
    for idx, finding in enumerate(findings, 1):
        print(f"  {idx}. [{finding.get('severity').upper()}] {finding.get('title')}")
        print(f"     Source URL: {finding.get('url')}")
        print(f"     Evidence:   {finding.get('evidence')}\n")

if __name__ == "__main__":
    # 1. Audit the current leaf repository directory
    current_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    run_local_sast_audit(current_dir)
    
    # 2. Run scan on a mock/local web target (or fallback)
    run_web_disclosure_scan("http://localhost:65535")
