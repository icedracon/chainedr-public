"""Scan a directory of real-world EIP-7702 / AA accounts.

Pairs with `docs/REAL_WORLD_TRIAGE.md`. Drop production .sol files into
`real_7702_scan/` and run this script — it produces a one-line summary
per file plus a JSON record under `real_7702_scan/_scan_<file>.json`.

Why: the labelled benchmark and the held-out corpus are both written
by the same people who write the analyzer, so the F1 numbers there
have a circularity ceiling. Scanning files pulled live from upstream
production repos is the only honest precision check.

Sample fetch (run from repo root, requires curl):

    mkdir -p real_7702_scan
    curl -fsSLo real_7702_scan/LightAccount.sol \\
        https://raw.githubusercontent.com/alchemyplatform/light-account/develop/src/LightAccount.sol
    curl -fsSLo real_7702_scan/Kernel.sol \\
        https://raw.githubusercontent.com/zerodevapp/kernel/dev/src/Kernel.sol
    curl -fsSLo real_7702_scan/Nexus.sol \\
        https://raw.githubusercontent.com/bcnmy/nexus/dev/contracts/Nexus.sol
    curl -fsSLo real_7702_scan/Safe.sol \\
        https://raw.githubusercontent.com/safe-global/safe-smart-account/main/contracts/Safe.sol
    curl -fsSLo real_7702_scan/Solady_ERC4337.sol \\
        https://raw.githubusercontent.com/Vectorized/solady/main/src/accounts/ERC4337.sol
    curl -fsSLo real_7702_scan/Solady_ERC7821.sol \\
        https://raw.githubusercontent.com/Vectorized/solady/main/src/accounts/ERC7821.sol
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import types
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


def _bootstrap_chainedr() -> None:
    sys.path.insert(0, str(REPO))
    src_path = REPO / "src"
    mod = types.ModuleType("chainedr")
    mod.__path__ = [str(src_path)]
    sys.modules["chainedr"] = mod


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        default=str(REPO / "real_7702_scan"),
        help="Directory containing the production .sol files",
    )
    args = parser.parse_args()

    _bootstrap_chainedr()
    import argparse as _ap
    import chainedr.cli as cli  # type: ignore[import-not-found]

    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"missing: {corpus}", file=sys.stderr)
        return 2

    files = sorted(p for p in corpus.iterdir() if p.suffix == ".sol")
    if not files:
        print(f"no .sol files in {corpus}", file=sys.stderr)
        return 2

    print(f"{'file':25s} {'N':>3s}  rules")
    for sol in files:
        out_json = corpus / f"_scan_{sol.name}.json"
        ns = _ap.Namespace(
            target=str(sol),
            no_external=True,
            no_ast=False,
            deep=False,
            extended=False,
            mythril=False,
            external_timeout=30,
            ignore=[],
            min_severity="LOW",
            format="compact",
            sarif=None,
            json_out=str(out_json),
            fail_on=None,
            profile="default",
            output_dir=None,
            ai_triage=False,
            prove=False,
            prove_on_finding=[],
            prove_out=None,
        )
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            cli.cmd_scan(ns)
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err

        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        findings = data.get("findings", []) if isinstance(data, dict) else []
        rules: dict[str, int] = {}
        for f in findings:
            rid = f.get("rule_id") or f.get("check_id", "?")
            rules[rid] = rules.get(rid, 0) + 1
        rules_sorted = dict(sorted(rules.items()))
        print(f"{sol.name:25s} {len(findings):3d}  {rules_sorted}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
