import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import cli  # noqa: E402


def _normalized(text: str) -> str:
    return text.replace("\r\n", "\n")


def test_checked_in_workflow_matches_ci_init_template():
    repo_root = Path(__file__).resolve().parent.parent
    workflow = repo_root / ".github" / "workflows" / "chainedr.yml"

    assert _normalized(workflow.read_text(encoding="utf-8")) == _normalized(
        cli._GITHUB_ACTIONS_WORKFLOW_TEMPLATE
    )


def test_ci_init_generates_resilient_github_workflow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert cli._ci_init(SimpleNamespace()) == 0

    workflow = (tmp_path / ".github" / "workflows" / "chainedr.yml").read_text(
        encoding="utf-8"
    )
    assert "continue-on-error: true" in workflow
    assert "if: always()" in workflow
    assert "github/codeql-action/upload-sarif@v4" in workflow
    assert "actions/checkout@v6" in workflow
    assert "actions/setup-python@v6" in workflow
    assert "actions/upload-artifact@v7" in workflow
    assert "CHAINEDR_TARGET" in workflow
    assert "--profile auditor" in workflow
    assert "--out-dir chainedr-report" in workflow
    assert "chainedr-report/scan.json" in workflow
    assert "chainedr-report/chainedr.sarif" in workflow
    assert "chainedr-report/evidence_bundle.md" in workflow
    assert "chainedr-report/executive_summary.md" in workflow
    assert "chainedr-report/manifest.json" in workflow
    assert "path: chainedr-report/**" in workflow

    config = tmp_path / ".chainedr.toml"
    assert config.exists()
