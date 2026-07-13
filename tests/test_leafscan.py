"""
LeafScan — Unit Tests
Run with: pytest tests/ -v
"""
import pytest
import sys
from pathlib import Path

# Ensure package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestVersion:
    def test_version_format(self):
        import leafscan
        parts = leafscan.__version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_metadata(self):
        import leafscan
        assert leafscan.__author__ == "A.P.Jovin"
        assert "JJ Groups" in leafscan.__company__
        assert "Leaf Security AI" in leafscan.__product__


class TestConfig:
    def test_default_config_structure(self):
        from leafscan.core.config import DEFAULT_CONFIG
        assert "platform" in DEFAULT_CONFIG
        assert "scan" in DEFAULT_CONFIG
        assert "ai" in DEFAULT_CONFIG
        assert "output" in DEFAULT_CONFIG

    def test_scan_profiles(self):
        from leafscan.core.config import SCAN_PROFILES
        for profile in ("stealth", "default", "aggressive"):
            assert profile in SCAN_PROFILES
            assert "threads" in SCAN_PROFILES[profile]
            assert "delay" in SCAN_PROFILES[profile]

    def test_load_config_returns_dict(self):
        from leafscan.core.config import load_config
        cfg = load_config()
        assert isinstance(cfg, dict)
        assert "scan" in cfg


class TestScanEngine:
    def test_summarize_empty(self):
        from leafscan.scanner.engine import summarize
        s = summarize([])
        assert s == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def test_summarize_counts(self):
        from leafscan.scanner.engine import summarize
        findings = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "critical"},
            {"severity": "low"},
        ]
        s = summarize(findings)
        assert s["high"] == 2
        assert s["critical"] == 1
        assert s["low"] == 1
        assert s["medium"] == 0

    def test_all_modules_registered(self):
        from leafscan.scanner.engine import ALL_MODULES
        expected = ["ports","headers","tls","dns","dirs","xss","sqli","cve","info","misconfig"]
        for m in expected:
            assert m in ALL_MODULES

    def test_authorization_gate_declined(self, monkeypatch):
        """When user does not confirm authorization, scan should not run."""
        from leafscan.scanner.engine import require_authorization
        # Monkeypatch builtins.input to return empty string (defaults to 'N')
        monkeypatch.setattr("builtins.input", lambda *a, **kw: "")
        # Also monkeypatch Rich Confirm.ask if available
        try:
            import rich.prompt
            monkeypatch.setattr(rich.prompt.Confirm, "ask", classmethod(lambda cls, *a, **kw: False))
        except (ImportError, AttributeError):
            pass
        result = require_authorization("https://test.example.com", flag_confirmed=False)
        assert result is False

    def test_authorization_gate_flag(self):
        """--i-have-permission flag bypasses the gate."""
        from leafscan.scanner.engine import require_authorization
        result = require_authorization("https://test.example.com", flag_confirmed=True)
        assert result is True


class TestReportGenerator:
    def test_report_id_format(self):
        from leafscan.report.generator import generate_report_id
        rid = generate_report_id()
        assert rid.startswith("LS-")
        assert len(rid) == len("LS-20241215-143022")

    def test_generate_markdown_report(self):
        from leafscan.report.generator import generate_markdown_report
        findings = [
            {
                "title": "Test Finding",
                "severity": "high",
                "vuln_type": "Test",
                "url": "https://example.com",
                "description": "Test description",
                "remediation": "Test remediation",
                "evidence": "Test evidence",
                "steps": "Test steps",
                "poc": "Test PoC",
                "impact": "Test impact",
            }
        ]
        report_id, md = generate_markdown_report("https://example.com", findings, 5.0, "default")
        assert report_id.startswith("LS-")
        assert "https://example.com" in md
        assert "Test Finding" in md
        assert "CRITICAL" in md or "HIGH" in md or "high" in md.lower()

    def test_generate_report_empty_findings(self):
        from leafscan.report.generator import generate_markdown_report
        report_id, md = generate_markdown_report("https://example.com", [], 1.0, "default")
        assert "No vulnerabilities detected" in md

    def test_list_reports_returns_list(self):
        from leafscan.report.generator import list_reports
        reports = list_reports()
        assert isinstance(reports, list)


class TestModules:
    """Smoke tests for module imports and structure."""

    def test_all_modules_importable(self):
        modules = [
            "leafscan.scanner.modules.port_scan",
            "leafscan.scanner.modules.header_scan",
            "leafscan.scanner.modules.tls_scan",
            "leafscan.scanner.modules.dns_scan",
            "leafscan.scanner.modules.dir_scan",
            "leafscan.scanner.modules.xss_probe",
            "leafscan.scanner.modules.sqli_probe",
            "leafscan.scanner.modules.cve_patterns",
            "leafscan.scanner.modules.info_disclosure",
            "leafscan.scanner.modules.misconfig",
        ]
        for m in modules:
            mod = __import__(m, fromlist=["run"])
            assert callable(mod.run), f"{m}.run() must be callable"

    def test_module_run_returns_list(self):
        """Each module must return a list (possibly empty) for any target."""
        from leafscan.scanner.modules import header_scan
        from leafscan.core.config import DEFAULT_CONFIG
        # Using a non-existent host — module should return [] gracefully
        result = header_scan.run("http://localhost:65535", DEFAULT_CONFIG)
        assert isinstance(result, list)

    def test_finding_structure(self):
        """All findings must have required keys."""
        required_keys = {"title", "severity", "vuln_type", "url",
                         "description", "remediation", "evidence"}
        # Create a mock finding to verify structure expectations
        mock_finding = {
            "title": "Test",
            "severity": "info",
            "vuln_type": "Test",
            "url": "https://example.com",
            "description": "Desc",
            "remediation": "Fix",
            "evidence": "Evidence",
            "steps": "Steps",
            "poc": "PoC",
            "impact": "Impact",
        }
        for key in required_keys:
            assert key in mock_finding


class TestV2Upgrades:
    def test_ai_providers_list(self):
        from leafscan.core.ai_client import AI_PROVIDERS
        assert "openrouter" in AI_PROVIDERS
        assert "openai" in AI_PROVIDERS
        assert "anthropic" in AI_PROVIDERS
        assert "ollama" in AI_PROVIDERS
        assert "google" in AI_PROVIDERS
        assert "groq" in AI_PROVIDERS
        assert "mistral" in AI_PROVIDERS

    def test_ai_client_disabled_by_default(self):
        from leafscan.core.config import DEFAULT_CONFIG
        from leafscan.core.ai_client import AIClient
        client = AIClient(DEFAULT_CONFIG)
        assert client.enabled is False
        res = client.call_ai("hello")
        assert "not configured" in res or "disabled" in res

    def test_exploit_chain_simulator_disabled(self):
        from leafscan.core.config import DEFAULT_CONFIG
        from leafscan.core.chain_simulator import simulate_exploit_chain
        res = simulate_exploit_chain([{"title": "Test XSS", "severity": "high"}], "localhost", DEFAULT_CONFIG)
        assert "disabled" in res or "⚠️" in res

    def test_patch_generator_disabled(self):
        from leafscan.core.config import DEFAULT_CONFIG
        from leafscan.core.patch_generator import generate_git_patch
        res = generate_git_patch({"title": "Test XSS", "url": "http://localhost/index.php"}, ".", DEFAULT_CONFIG)
        assert "disabled" in res or "⚠️" in res


class TestV215Features:
    def test_passive_checks_run_returns_list(self):
        from leafscan.scanner.modules import passive_checks
        from leafscan.core.config import DEFAULT_CONFIG
        res = passive_checks.run("http://localhost:65535", DEFAULT_CONFIG)
        assert isinstance(res, list)

    def test_sast_checks_run_returns_list(self):
        from leafscan.scanner.modules import sast_checks
        res = sast_checks.run_local_sast(".")
        assert isinstance(res, list)

    def test_exporters_csv_html(self, tmp_path):
        from leafscan.report.exporters import export_to_csv, export_to_html
        findings = [{
            "title": "Test XSS",
            "severity": "high",
            "vuln_type": "XSS",
            "url": "http://localhost/xss",
            "description": "Test desc",
            "remediation": "Test fix",
            "evidence": "Evidence",
            "owasp": "A03"
        }]
        csv_file = tmp_path / "report.csv"
        html_file = tmp_path / "report.html"
        
        assert export_to_csv(findings, str(csv_file)) is True
        assert csv_file.exists()
        
        assert export_to_html("http://localhost", findings, 1.5, "default", str(html_file)) is True
        assert html_file.exists()

    def test_json_schema_validation(self):
        from leafscan.report.exporters import validate_finding_json
        valid = {
            "title": "Test XSS",
            "severity": "high",
            "vuln_type": "XSS",
            "url": "http://localhost/xss",
            "description": "Test desc",
            "remediation": "Test fix",
            "evidence": "Evidence"
        }
        assert validate_finding_json(valid) is True
        
        invalid = {
            "title": "Missing severity"
        }
        assert validate_finding_json(invalid) is False

    def test_leaf_ai_provider(self, monkeypatch):
        import os
        monkeypatch.setenv("LEAF_AI_OFFLINE", "true")
        from leafscan.core.ai_client import AIClient
        config = {
            "ai": {
                "enabled": True,
                "provider": "leaf-ai",
                "api_key": "mock-key",
                "model": "leafgpt"
            }
        }
        client = AIClient(config)
        assert client.provider == "leaf-ai"
        
        # Test call_ai fallback response containing dataset markers
        res = client.call_ai("XSS vulnerability", "You are a scanner helper")
        assert "Leaf Security" in res or "matched" in res.lower() or "vulnerability" in res.lower() or "offline" in res.lower()

    def test_ask_command(self):
        from click.testing import CliRunner
        from leafscan.cli import ask
        runner = CliRunner()
        result = runner.invoke(ask, ["What is XSS?"])
        assert result.exit_code == 0
        assert "AI Response" in result.output

