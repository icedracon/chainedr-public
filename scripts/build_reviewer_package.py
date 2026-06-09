"""Build the concise reviewer-facing ChainEDR package."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evidence import run_reviewer_package  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "reviewer_package")
    parser.add_argument("--no-benchmark", action="store_true", help="Skip benchmark execution inside demo pack")
    args = parser.parse_args()

    result = run_reviewer_package(args.out, include_benchmark=not args.no_benchmark)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
