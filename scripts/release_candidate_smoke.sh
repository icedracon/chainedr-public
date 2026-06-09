#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rm -rf dist build .beta-smoke
mkdir -p dist results .beta-smoke/pocs .beta-smoke/clean

cat > .beta-smoke/clean/Clean.sol <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CleanMath {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}
SOL

python -m pip install --upgrade pip build pytest web3 eth-account scikit-learn xgboost joblib
python -m build ./src --wheel --outdir dist
python -m pip install --force-reinstall dist/chainedr-*.whl
python -m pip check
python -m compileall -q src tests scripts

python - <<'PY'
import chainedr
from chainedr import beta_cli, beta_semantics, cli, eip7702_detector

assert cli.cmd_ci is beta_cli.cmd_ci, "beta CI wrapper was not installed"
assert cli._write_sarif is beta_cli._write_sarif, "SARIF URL wrapper was not installed"
assert cli.build_parser is beta_cli.build_parser, "CLI help wrapper was not installed"
assert getattr(
    eip7702_detector.EIP7702Finding.__post_init__,
    "_chainedr_beta_semantics",
    False,
), "EIP-7702 semantics normalizer was not installed"
PY

chainedr --help >/dev/null
python -m pytest tests/ -q

python scripts/benchmark_evaluator.py \
  --strict \
  -o results/eip7702_benchmark_eval.json

python scripts/evaluate_eip7702_sandbox.py \
  --strict \
  -o results/eip7702_validation_eval.json

chainedr scan .beta-smoke/clean \
  --no-external \
  --deep \
  --json .beta-smoke/clean.json \
  --sarif .beta-smoke/clean.sarif

chainedr scan benchmarks/eip7702_sandbox/vulnerable \
  --no-external \
  --deep \
  --json .beta-smoke/vulnerable.json \
  --sarif .beta-smoke/vulnerable.sarif

chainedr prove bundle \
  --from-json .beta-smoke/vulnerable.json \
  -o .beta-smoke/evidence_bundle.md \
  --source-root .

chainedr prove poc \
  --from-json .beta-smoke/vulnerable.json \
  --output-dir .beta-smoke/pocs \
  --include-uncertain

python - <<'PY'
import json
from pathlib import Path

PROJECT_URL = "https://github.com/icedracon/chainedr"

clean = json.loads(Path(".beta-smoke/clean.json").read_text(encoding="utf-8"))
clean_findings = clean if isinstance(clean, list) else clean.get("findings", [])
assert clean_findings == [], f"clean smoke fixture produced findings: {clean_findings}"

for sarif_path in [
    Path(".beta-smoke/clean.sarif"),
    Path(".beta-smoke/vulnerable.sarif"),
]:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    runs = sarif.get("runs", [])
    assert runs, f"missing SARIF runs: {sarif_path}"
    uri = runs[0].get("tool", {}).get("driver", {}).get("informationUri")
    assert uri == PROJECT_URL, f"unexpected SARIF informationUri in {sarif_path}: {uri}"
PY

test -s results/eip7702_benchmark_eval.json
test -s results/eip7702_validation_eval.json
test -s .beta-smoke/clean.json
test -s .beta-smoke/clean.sarif
test -s .beta-smoke/vulnerable.json
test -s .beta-smoke/vulnerable.sarif
test -s .beta-smoke/evidence_bundle.md
test -s .beta-smoke/pocs/MANIFEST.md

printf '\nChainEDR Analyzer private-beta smoke: PASS\n'
