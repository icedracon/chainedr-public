#!/usr/bin/env python3
"""
Run a minimal dynamic bytecode probe against local/fork Anvil.

The script fetches runtime bytecode from the source RPC, installs it on a
local/fork target RPC, points a victim EOA-like address at it via
0xef0100||implementation (or direct runtime mode), sends ETH to the victim, and
parses callTracer value flows.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from bytecode_oracle import (  # noqa: E402
    EIP7702DelegationProbe,
    RuntimeBytecodeProbe,
    fetch_runtime_bytecode,
)

try:
    from web3 import Web3
except Exception:  # pragma: no cover
    Web3 = None


def main() -> int:
    ap = argparse.ArgumentParser(description="Dynamically probe runtime bytecode on Anvil")
    ap.add_argument("address", help="Source contract address whose runtime bytecode is probed")
    ap.add_argument("--source-rpc-url", default=None, help="RPC used to fetch source bytecode")
    ap.add_argument("--target-rpc-url", default="http://127.0.0.1:8545",
                    help="Local/fork Anvil RPC used for probing")
    ap.add_argument("--mode", choices=["delegation", "runtime"], default="delegation",
                    help="Use exact 7702 delegation code or direct runtime install")
    ap.add_argument("--victim", default="0x7702000000000000000000000000000000000001",
                    help="Victim EOA-like address to receive runtime bytecode")
    ap.add_argument("--value-wei", type=int, default=10**18,
                    help="ETH amount to send to victim during receive probe")
    ap.add_argument("--json-out", default="", help="Optional JSON output path")
    args = ap.parse_args()

    if Web3 is None:
        raise SystemExit("web3 is required")

    runtime = fetch_runtime_bytecode(args.address, args.source_rpc_url)
    w3 = Web3(Web3.HTTPProvider(args.target_rpc_url))
    if not w3.is_connected():
        raise SystemExit("target Anvil RPC is not reachable")

    if args.mode == "delegation":
        result = EIP7702DelegationProbe(w3, args.victim).probe_receive_value(
            args.address,
            runtime,
            value_wei=args.value_wei,
        )
    else:
        result = RuntimeBytecodeProbe(w3, args.victim).probe_receive_value(
            args.address,
            runtime,
            value_wei=args.value_wei,
        )

    text = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    print(text)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    return 0 if result.tx_status == 1 else 2


if __name__ == "__main__":
    raise SystemExit(main())
