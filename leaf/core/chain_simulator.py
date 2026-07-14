"""
Leaf — AI Exploit Chaining Simulator
Analyzes scan findings and simulates possible multi-stage attack paths.
"""
import json
from pathlib import Path
from leaf.core.ai_client import AIClient

def simulate_exploit_chain(findings, target_host, config):
    """
    Simulates how findings can be chained together to achieve higher severity impact (e.g. RCE or full breach).
    """
    if not findings:
        return "No findings to simulate a chain. Target is secure."

    # Prepare a summary of findings
    summary_lines = []
    for idx, f in enumerate(findings, 1):
        summary_lines.append(
            f"{idx}. [{f.get('severity','info').upper()}] {f.get('title')} (Type: {f.get('vuln_type','Unknown')}) - URL: {f.get('url','')}"
        )
    findings_text = "\n".join(summary_lines)

    prompt = f"""You are an advanced offensive security simulation engine.
Analyze these security findings detected on target: '{target_host}' and construct an attack graph / chain.

Findings:
{findings_text}

Provide:
1. An ASCII attack path diagram showing how the findings can be chained together by an attacker (e.g. [Port Scan] -> [Information Disclosure] -> [SQLi] -> [RCE]).
2. A step-by-step description of the simulated chain.
3. The ultimate impact of the attack path.
4. Mitigation sequence.

Be highly technical and precise. Format your response in clean markdown."""

    ai = AIClient(config)
    if not ai.enabled:
        return "⚠️ AI Integration is disabled. Enable it to simulate exploit chains: 'leaf config set ai.enabled true'"

    return ai.call_ai(prompt, "You are a cyber security architect specialized in threat modeling.")
