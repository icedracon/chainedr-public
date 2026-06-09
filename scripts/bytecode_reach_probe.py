#!/usr/bin/env python3
"""
Profile unverified EIP-7702 delegator bytecode from RPC.

Example:
  python scripts/bytecode_reach_probe.py \
    0x9db96924a0b0b9a83fe2368b29539561a9c696d8 \
    --json-out results/bytecode_profiles.json

This intentionally prints no RPC URL or API key.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from bytecode_oracle import profile_address  # noqa: E402


BUNDLEBEAR_TOP_UNVERIFIED = [
    "0x9db96924a0b0b9a83fe2368b29539561a9c696d8",
    "0x7c802f062c67058d0dd40b041204b960e8bde26a",
    "0xb1280932da6df283be6dddd99f2a147d41773988",
    "0x31a12e00769f8ade55a9b6172f372fad7c251ad7",
    "0x22ed1827f5be793111e63c05c3f468adcce21095",
    "0x27dbd0e71b85700e29994d6d3a51f2e32442aa61",
    "0x1e68c71fa1b7c3efd4a576b5551d2e8004f96ea7",
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Profile runtime bytecode for unverified EIP-7702 delegators")
    ap.add_argument("addresses", nargs="*", help="Contract addresses to profile")
    ap.add_argument("--bundlebear-top-unverified", action="store_true",
                    help="Profile the current hardcoded BundleBear top unverified snapshot")
    ap.add_argument("--rpc-url", default=None, help="RPC URL. Defaults to RPC_URL/.env.")
    ap.add_argument("--json-out", default="", help="Optional JSON output path")
    args = ap.parse_args()

    addresses = list(args.addresses)
    if args.bundlebear_top_unverified:
        addresses.extend(BUNDLEBEAR_TOP_UNVERIFIED)
    addresses = list(dict.fromkeys(a.lower() for a in addresses))
    if not addresses:
        ap.error("provide at least one address or --bundlebear-top-unverified")

    profiles = []
    failures = []
    for address in addresses:
        try:
            profiles.append(profile_address(address, args.rpc_url))
        except Exception as exc:  # keep batch moving
            failures.append({"address": address, "error": type(exc).__name__})

    payload = {
        "profiles": [p.to_dict() for p in profiles],
        "failures": failures,
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    print(text)

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    return 1 if failures and not profiles else 0


if __name__ == "__main__":
    raise SystemExit(main())
