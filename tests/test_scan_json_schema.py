import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "chainedr-scan-report.schema.json"


def _type_matches(value, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    return True


def _validate_schema(value, schema, path="$"):
    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        assert any(_type_matches(value, kind) for kind in expected_types), (
            f"{path}: expected {expected}, got {type(value).__name__}"
        )

    if "enum" in schema:
        assert value in schema["enum"], f"{path}: {value!r} not in enum {schema['enum']!r}"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema:
            assert value >= schema["minimum"], f"{path}: {value!r} below minimum"
        if "maximum" in schema:
            assert value <= schema["maximum"], f"{path}: {value!r} above maximum"

    if isinstance(value, dict):
        for key in schema.get("required", []):
            assert key in value, f"{path}: missing required key {key!r}"

        properties = schema.get("properties", {})
        for key, sub_schema in properties.items():
            if key in value:
                _validate_schema(value[key], sub_schema, f"{path}.{key}")

        additional = schema.get("additionalProperties", True)
        if additional is False:
            unexpected = set(value) - set(properties)
            assert not unexpected, f"{path}: unexpected keys {sorted(unexpected)!r}"
        elif isinstance(additional, dict):
            for key, child in value.items():
                if key not in properties:
                    _validate_schema(child, additional, f"{path}.{key}")

    if isinstance(value, list) and "items" in schema:
        for idx, item in enumerate(value):
            _validate_schema(item, schema["items"], f"{path}[{idx}]")


def _run_scan(target: Path, output: Path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "chainedr",
            "scan",
            str(target),
            "--no-external",
            "--json",
            str(output),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return json.loads(output.read_text(encoding="utf-8"))


def test_clean_scan_output_matches_json_schema(tmp_path):
    (tmp_path / "Clean.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Clean {}\n",
        encoding="utf-8",
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report = _run_scan(tmp_path, tmp_path / "clean.json")

    _validate_schema(report, schema)
    assert report["summary"]["total"] == 0
    assert report["findings"] == []


def test_finding_scan_output_matches_json_schema(tmp_path):
    (tmp_path / "DelegatedGate.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract DelegatedGate {\n"
        "    function gated() external view { require(tx.origin == msg.sender); }\n"
        "}\n",
        encoding="utf-8",
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report = _run_scan(tmp_path, tmp_path / "finding.json")

    _validate_schema(report, schema)
    assert report["summary"]["total"] >= 1
    assert len(report["findings"]) == report["summary"]["total"]
    assert all(finding["rule_id"] for finding in report["findings"])
    assert all(finding["analysis_depth"] for finding in report["findings"])
    assert all(finding["reviewer_confidence"]["grade"] for finding in report["findings"])
    assert report["summary"]["by_reviewer_confidence"]
