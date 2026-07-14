"""
Leaf — AI Code Patch Generator
Generates a standard Git diff patch file (.patch) to automatically remediate a scanner finding.
"""
import os
import re
from pathlib import Path
from leaf.core.ai_client import AIClient

def generate_git_patch(finding, source_dir_path, config):
    """
    Search the source directory for files relevant to the finding,
    and call AI to write a git diff-compatible patch.
    """
    ai = AIClient(config)
    if not ai.enabled:
        return "⚠️ AI Integration is disabled. Enable it to generate code patches: 'leaf config set ai.enabled true'"

    source_dir = Path(source_dir_path)
    if not source_dir.exists() or not source_dir.is_dir():
        return f"Error: source directory '{source_dir_path}' does not exist or is not a directory."

    # Try to find relevant files based on finding URL path
    target_url = finding.get("url", "")
    target_file_matches = []
    
    # Simple heuristic to extract potential filename from URL
    path_parts = [p for p in target_url.replace("https://", "").replace("http://", "").split("/") if p]
    filename_hint = ""
    if path_parts:
        last_part = path_parts[-1]
        if "." in last_part or len(last_part) > 2:
            filename_hint = last_part.split("?")[0]

    # Look for files matching the hint in the source directory
    if filename_hint:
        for root, dirs, files in os.walk(source_dir):
            # Skip hidden directories like .git
            if any(d.startswith('.') for d in root.split(os.sep)):
                continue
            for f in files:
                if f.lower() == filename_hint.lower():
                    target_file_matches.append(Path(root) / f)

    if not target_file_matches:
        # Fallback: scan for files of relevant types (e.g. py, js, php, go) that might contain the vulnerable endpoint
        for root, dirs, files in os.walk(source_dir):
            if any(d.startswith('.') for d in root.split(os.sep)):
                continue
            for f in files:
                if f.endswith((".py", ".js", ".php", ".go", ".html", ".ts", ".java", ".c", ".cpp")):
                    # Quick grep for partial path match
                    p = Path(root) / f
                    try:
                        content = p.read_text(errors="ignore")
                        for part in path_parts[-2:]:
                            if part and part in content:
                                target_file_matches.append(p)
                                break
                    except Exception:
                        pass

    if not target_file_matches:
        return f"Could not find any files matching target path details: '{filename_hint}' in directory '{source_dir_path}'."

    # Read the top match code context (limit to 1 file for precision)
    target_file = target_file_matches[0]
    try:
        code_content = target_file.read_text(errors="ignore")
    except Exception as e:
        return f"Failed to read file '{target_file}': {e}"

    # Limit code content to avoid token limits
    lines = code_content.splitlines()
    if len(lines) > 250:
        # Just grab the middle/relevant section or first 250 lines
        code_content = "\n".join(lines[:250]) + "\n... [TRUNCATED] ..."

    # Build prompt
    prompt = f"""You are an expert secure code developer.
Analyze this vulnerability and the code file from the target project.
Generate a valid Git unified diff patch to remediate this vulnerability.

Vulnerability Finding:
- Title: {finding.get('title')}
- Type: {finding.get('vuln_type')}
- Description: {finding.get('description')}
- Evidence: {finding.get('evidence')}

File Path: {target_file.relative_to(source_dir)}
Code Content:
```
{code_content}
```

Instructions:
1. Return ONLY the standard git diff patch format (with headers like '--- a/...' and '+++ b/...').
2. Do not include markdown code block formatting (like ```diff or ```) around the patch itself.
3. Ensure the patch is syntactically correct and can be applied directly via 'git apply'.
"""

    patch_text = ai.call_ai(prompt, "You are a senior security patching engineer. You output only unified diff patches.")
    
    # Strip any markdown backticks if AI added them
    patch_text = re.sub(r"^```(diff)?\n", "", patch_text)
    patch_text = re.sub(r"\n```$", "", patch_text)
    
    # Save the patch file
    patch_path = source_dir / "leaf_remediation.patch"
    try:
        patch_path.write_text(patch_text, encoding="utf-8")
        return f"✓ Git patch generated successfully and saved to:\n  [bold green]{patch_path}[/bold green]\n\nApply it with:\n  [dim]git apply leaf_remediation.patch[/dim]"
    except Exception as e:
        return f"Error writing patch file: {e}\n\nGenerated Patch:\n{patch_text}"
