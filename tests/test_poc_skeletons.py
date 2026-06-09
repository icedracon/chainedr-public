import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from poc_skeletons import generate_skeletons, render_foundry_skeleton  # noqa: E402


FINDING = {
    "rule_id": "AA7702-001",
    "severity": "CRITICAL",
    "title": "EIP-7702 reaches tx.origin modifier gate through Wallet.execute()",
    "file_path": "contracts/Wallet.sol",
    "location": "Wallet.execute:semantic",
    "metadata": {
        "semantic_context": {
            "signature_model": {"missing": ["chain_id"]},
            "userop_model": {"missing": []},
        },
        "proof_recipe": {
            "proof_status": "STATIC_CANDIDATE",
            "readiness": "oracle_confirmable",
            "objective": "show Wallet.execute accepts a delegated EOA",
            "adapters": [{"adapter_id": "eip7702_behavior_flip_probe"}],
        },
    },
}


def test_render_foundry_skeleton_contains_target_and_refutation():
    source = render_foundry_skeleton(FINDING)

    assert "contract ChainEDR_AA7702_001_Wallet_execute_PoC" in source
    assert "Call Wallet.execute" in source
    assert "show Wallet.execute accepts a delegated EOA" in source
    assert "mark REFUTED" in source
    assert "vm.etch(victimEoa" in source
    assert "Reviewer confidence:" in source


def test_generate_skeletons_writes_manifest(tmp_path):
    manifest = generate_skeletons([FINDING], tmp_path)

    assert manifest["generated"] == 1
    assert (tmp_path / "MANIFEST.json").exists()
    assert (tmp_path / "MANIFEST.md").exists()
    poc_path = Path(manifest["pocs"][0]["path"])
    assert manifest["pocs"][0]["reviewer_confidence"]["grade"]
    assert poc_path.exists()
    assert "ChainEDR Analyzer proof skeleton" in poc_path.read_text()
    assert "Proof / Confidence" in (tmp_path / "MANIFEST.md").read_text()


def test_cli_prove_poc_from_json_uses_analyzer_skeletons(tmp_path):
    scan_json = tmp_path / "scan.json"
    out_dir = tmp_path / "pocs"
    scan_json.write_text(json.dumps({"findings": [FINDING]}), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr.cli",
            "prove",
            "poc",
            "--from-json",
            str(scan_json),
            "--output-dir",
            str(out_dir),
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "PoC skeletons written: 1" in result.stdout
    assert (out_dir / "MANIFEST.md").exists()
