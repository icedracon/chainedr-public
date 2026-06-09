"""Production-beta patch layer for ChainEDR Analyzer CLI.

This module keeps the large CLI engine stable while fixing release-critical
behavior at the package boundary:

- CI baseline diff is applied before the final severity gate is evaluated;
- generated SARIF points to the ChainEDR repository;
- the help footer points to the ChainEDR repository.

The patch installer is idempotent. Importing :mod:`chainedr` installs the
patches before the existing ``chainedr.cli:main`` console entry point runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

try:
    from . import cli as _cli
except ImportError:  # direct source-tree imports used by regression tests
    import cli as _cli

PROJECT_URL = "https://github.com/icedracon/chainedr"
_OLD_PROJECT_URL = "https://github.com/icedracon/chainedr"

_ORIGINAL_BUILD_PARSER = _cli.build_parser
_ORIGINAL_WRITE_SARIF = _cli._write_sarif
_ORIGINAL_CMD_SCAN = _cli.cmd_scan
_INSTALLED = False


def _severity_gate_from_json(findings: Iterable[dict], fail_on: str) -> int:
    """Return CI status for serialized findings after baseline filtering."""
    if str(fail_on).lower() == "none":
        return 0
    gate = _cli._SEV_RANK.get(str(fail_on).upper(), 99)
    for finding in findings:
        severity = str(finding.get("severity", "")).upper()
        if _cli._SEV_RANK.get(severity, 99) <= gate:
            return 1
    return 0


def _load_json_findings(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return list(data.get("findings", []))


def cmd_ci(args):
    """Run CI scan, apply optional baseline diff, then evaluate the final gate.

    The original implementation evaluated ``--fail-on`` inside ``cmd_scan``
    before applying ``--baseline``. That made accepted historical findings fail
    a pipeline even when only new findings should be gated.
    """
    target = getattr(args, "target_opt", None) or getattr(args, "target", None)
    if getattr(args, "ci_command", None) == "init" or target == "init":
        return _cli._ci_init(args)

    args.target = target or "."
    if hasattr(_cli, "_apply_auditor_profile"):
        _cli._apply_auditor_profile(args)
    if not getattr(args, "sarif", None):
        args.sarif = "chainedr.sarif"
    if not getattr(args, "json_out", None):
        args.json_out = "chainedr.json"

    fail_on = getattr(args, "fail_on", None) or "high"
    args.fail_on = None
    result = _ORIGINAL_CMD_SCAN(args)
    if result:
        return result

    baseline_path = getattr(args, "baseline", None)
    if baseline_path and Path(baseline_path).exists():
        _cli._apply_baseline_diff(args.json_out, baseline_path)
        if hasattr(_cli, "_write_auditor_artifacts_from_json"):
            _cli._write_auditor_artifacts_from_json(args, source_root=Path(args.target).resolve())

    return _severity_gate_from_json(_load_json_findings(args.json_out), fail_on)


def _write_sarif(path: str, findings) -> None:
    """Write SARIF using the stable product repository URL."""
    _ORIGINAL_WRITE_SARIF(path, findings)
    sarif_path = Path(path)
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        driver["informationUri"] = PROJECT_URL
    sarif_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_parser():
    """Return the public parser with the stable product URL in the footer."""
    parser = _ORIGINAL_BUILD_PARSER()
    if parser.epilog:
        parser.epilog = parser.epilog.replace(_OLD_PROJECT_URL, PROJECT_URL)
    return parser


def install() -> None:
    """Install beta patches exactly once for the existing CLI module."""
    global _INSTALLED
    if _INSTALLED:
        return
    _cli.cmd_ci = cmd_ci
    _cli._write_sarif = _write_sarif
    _cli.build_parser = build_parser
    _INSTALLED = True


def main() -> None:
    """Install release-critical hooks and delegate to the stable CLI engine."""
    install()
    _cli.main()


if __name__ == "__main__":
    main()
