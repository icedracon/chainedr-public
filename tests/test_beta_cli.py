import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import beta_cli  # noqa: E402


def test_serialized_gate_ignores_baselined_findings(tmp_path, monkeypatch):
    current = tmp_path / "current.json"
    baseline = tmp_path / "baseline.json"
    current.write_text(
        json.dumps({
            "findings": [
                {"rule_id": "AA7702-001", "file_path": "Wallet.sol", "title": "old", "severity": "HIGH"},
                {"rule_id": "AA7702-002", "file_path": "Vault.sol", "title": "new", "severity": "LOW"},
            ]
        }),
        encoding="utf-8",
    )
    baseline.write_text(
        json.dumps({
            "findings": [
                {"rule_id": "AA7702-001", "file_path": "Wallet.sol", "title": "old", "severity": "HIGH"},
            ]
        }),
        encoding="utf-8",
    )

    args = SimpleNamespace(
        target=".",
        target_opt=None,
        ci_command=None,
        sarif="out.sarif",
        json_out=str(current),
        fail_on="high",
        baseline=str(baseline),
    )

    monkeypatch.setattr(beta_cli, "_ORIGINAL_CMD_SCAN", lambda args: 0)

    assert beta_cli.cmd_ci(args) == 0
    data = json.loads(current.read_text(encoding="utf-8"))
    assert [f["rule_id"] for f in data["findings"]] == ["AA7702-002"]


def test_serialized_gate_fails_on_new_high_finding():
    assert beta_cli._severity_gate_from_json(
        [{"severity": "HIGH"}],
        "high",
    ) == 1


def test_sarif_wrapper_rewrites_product_url(tmp_path, monkeypatch):
    out = tmp_path / "report.sarif"

    def fake_writer(path, findings):
        Path(path).write_text(
            json.dumps({
                "runs": [{
                    "tool": {
                        "driver": {
                            "informationUri": beta_cli._OLD_PROJECT_URL,
                        }
                    }
                }]
            }),
            encoding="utf-8",
        )

    monkeypatch.setattr(beta_cli, "_ORIGINAL_WRITE_SARIF", fake_writer)
    beta_cli._write_sarif(str(out), [])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["runs"][0]["tool"]["driver"]["informationUri"] == beta_cli.PROJECT_URL


def test_parser_wrapper_rewrites_help_footer(monkeypatch):
    class Parser:
        epilog = f"docs: {beta_cli._OLD_PROJECT_URL}"

    monkeypatch.setattr(beta_cli, "_ORIGINAL_BUILD_PARSER", lambda: Parser())
    parser = beta_cli.build_parser()
    assert beta_cli.PROJECT_URL in parser.epilog
    assert beta_cli._OLD_PROJECT_URL not in parser.epilog


def test_python_module_entrypoint_exposes_beta_cli_surface():
    src_dir = Path(__file__).resolve().parent.parent / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src_dir)

    result = subprocess.run(
        [sys.executable, "-m", "chainedr", "--help"],
        check=True,
        cwd=src_dir.parent,
        env=env,
        text=True,
        capture_output=True,
    )

    assert "ChainEDR Analyzer - static Pectra-era smart-account scanner" in result.stdout
    for command in ("scan", "ci", "prove", "live", "doctor"):
        assert command in result.stdout
    for legacy_command in ("bench", "baseline", "debug", "poc", "init"):
        assert f"    {legacy_command} " not in result.stdout
