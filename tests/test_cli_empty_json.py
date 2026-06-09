import json
import subprocess
import sys
from pathlib import Path


def test_ci_accepts_report_only_fail_on_none(tmp_path):
    (tmp_path / "Vulnerable.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vulnerable {\n"
        "    function gated() external view { require(tx.origin == msg.sender); }\n"
        "}\n"
    )
    out = tmp_path / "scan.json"
    sarif = tmp_path / "scan.sarif"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr.cli",
            "ci",
            str(tmp_path),
            "--fail-on",
            "none",
            "--no-external",
            "--json",
            str(out),
            "--sarif",
            str(sarif),
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert out.exists()
    assert sarif.exists()
    data = json.loads(out.read_text())
    assert isinstance(data, dict)
    assert "findings" in data
    assert "summary" in data


def test_scan_accepts_lowercase_min_severity(tmp_path):
    (tmp_path / "Vulnerable.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vulnerable {\n"
        "    function gated() external view { require(tx.origin == msg.sender); }\n"
        "}\n"
    )
    out = tmp_path / "scan.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr.cli",
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
            "--no-external",
            "--min-severity",
            "medium",
            "--json",
            str(out),
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(out.read_text())
    assert data["summary"]["total"] >= 1
    assert all(f["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} for f in data["findings"])


def test_ci_extended_flag_enables_opt_in_detector(tmp_path):
    (tmp_path / "Batch.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Batch {\n"
        "    function execute(bytes32 mode, bytes calldata opData) external payable {}\n"
        "}\n"
    )
    default_out = tmp_path / "default.json"
    default_sarif = tmp_path / "default.sarif"
    extended_out = tmp_path / "extended.json"
    extended_sarif = tmp_path / "extended.sarif"

    base_cmd = [
        sys.executable,
        "-m",
        "chainedr.cli",
        "ci",
        str(tmp_path),
        "--fail-on",
        "none",
        "--no-external",
    ]

    default = subprocess.run(
        [*base_cmd, "--sarif", str(default_sarif), "--json", str(default_out)],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )
    extended = subprocess.run(
        [
            *base_cmd,
            "--sarif",
            str(extended_sarif),
            "--json",
            str(extended_out),
            "--extended",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )

    assert default.returncode == 0, default.stderr + default.stdout
    assert extended.returncode == 0, extended.stderr + extended.stdout
    default_findings = json.loads(default_out.read_text())["findings"]
    extended_findings = json.loads(extended_out.read_text())["findings"]
    assert "erc7821" not in {f.get("category") for f in default_findings}
    assert "erc7821" in {f.get("category") for f in extended_findings}


def test_console_entrypoint_routes_bytecode_help():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr.cli",
            "bytecode",
            "--help",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "--rpc-url" in result.stdout
    assert "--delegation-target" in result.stdout
    assert "--format" in result.stdout


def test_scan_writes_empty_json_for_clean_target(tmp_path):
    (tmp_path / "Clean.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Clean {}\n"
    )
    out = tmp_path / "scan.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr",
            "scan",
            str(tmp_path),
            "--no-external",
            "--json",
            str(out),
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert out.exists()
    data = json.loads(out.read_text())
    assert isinstance(data, dict)
    assert data["summary"]["total"] == 0
    assert data["findings"] == []


def test_ci_auditor_profile_writes_report_directory(tmp_path):
    (tmp_path / "Vulnerable.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vulnerable {\n"
        "    function gated() external view { require(tx.origin == msg.sender); }\n"
        "}\n",
        encoding="utf-8",
    )
    report_dir = tmp_path / "chainedr-report"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr",
            "ci",
            str(tmp_path),
            "--profile",
            "auditor",
            "--out-dir",
            str(report_dir),
            "--fail-on",
            "none",
            "--no-external",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    for name in (
        "scan.json",
        "chainedr.sarif",
        "evidence_bundle.md",
        "executive_summary.md",
        "manifest.json",
    ):
        assert (report_dir / name).exists()

    scan = json.loads((report_dir / "scan.json").read_text(encoding="utf-8"))
    manifest = json.loads((report_dir / "manifest.json").read_text(encoding="utf-8"))
    executive = (report_dir / "executive_summary.md").read_text(encoding="utf-8")
    evidence = (report_dir / "evidence_bundle.md").read_text(encoding="utf-8")

    assert scan["summary"]["total"] >= 1
    assert scan["summary"]["by_reviewer_tier"]
    assert manifest["profile"] == "auditor"
    assert manifest["summary"]["by_reviewer_tier"] == scan["summary"]["by_reviewer_tier"]
    assert manifest["artifacts"]["json"].endswith("scan.json")
    assert "ChainEDR Executive Summary" in executive
    assert "Reviewer tier mix" in executive
    assert "ChainEDR Evidence Bundle" in evidence
