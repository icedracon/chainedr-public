"""
Harvest real exploit traces using FREE Etherscan + Infura APIs.
No archive node required.

Usage:
    python tests/harvest_etherscan.py \
        --etherscan-key YOUR_ETHERSCAN_KEY \
        --infura-key YOUR_INFURA_KEY

Or via env vars:
    ETHERSCAN_API_KEY=... INFURA_API_KEY=... python tests/harvest_etherscan.py
"""
from __future__ import annotations

import json
import os
import sys
import time
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evm_tracer.etherscan_adapter import EtherscanAdapter

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "traces"

# Real exploit transactions to harvest
REAL_ATTACKS = [
    {
        "slug": "real_euler_2023",
        "name": "Euler Finance",
        "tx": "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887ad48c4f0b76b672e66c7f820d",
        "contract": "0x27182842E098f60e3D576794A5bFFb0777E025d3",
        "category": "FLASH_LOAN",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "real_cream_2021",
        "name": "Cream Finance (Oct 2021)",
        "tx": "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
        "contract": "0x7589dB3A0B29B29B59F1cB4F7d90B094a39ecF3e",
        "category": "FLASH_LOAN",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "real_dao_2016",
        "name": "The DAO",
        "tx": "0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3571d8571607b19d",
        "contract": "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413",
        "category": "REENTRANCY",
        "expect": {"reentrancy": True},
    },
    {
        "slug": "real_bzx_2020",
        "name": "bZx (Feb 2020)",
        "tx": "0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838",
        "contract": "0x9441d7556e7820B5ca42082cfa99487D56AcA958",
        "category": "ORACLE",
        "expect": {},
    },
    {
        "slug": "real_harvest_2020",
        "name": "Harvest Finance",
        "tx": "0x35f8d2f572fceaac9288e5d462117850ef2694786992a8c3f6d02612277b0877",
        "contract": "0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE",
        "category": "ORACLE",
        "expect": {},
    },
    {
        "slug": "real_parity_kill_2017",
        "name": "Parity WalletLib kill",
        "tx": "0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686e0722c9",
        "contract": "0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4",
        "category": "SELFDESTRUCT",
        "expect": {"selfdestruct_present": True},
    },
    {
        "slug": "real_beanstalk_2022",
        "name": "Beanstalk Governance",
        "tx": "0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7",
        "contract": "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
        "category": "GOVERNANCE",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "real_ronin_2022",
        "name": "Ronin Bridge",
        "tx": "0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7",
        "contract": "0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2",
        "category": "ACCESS_CONTROL",
        "expect": {},
    },
]


def harvest(etherscan_key: str):
    adapter = EtherscanAdapter(api_key=etherscan_key)
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    saved = 0
    for entry in REAL_ATTACKS:
        out_path = FIXTURES_DIR / f"{entry['slug']}.json"
        if out_path.exists():
            print(f"  [{entry['slug']}] Already exists, skipping")
            saved += 1
            continue

        print(f"  [{entry['slug']}] {entry['name']}...", end=" ", flush=True)
        try:
            trace, tx_meta, logs = adapter.fetch_trace(entry["tx"])

            # Count nodes
            def count_nodes(t):
                n = 1
                for c in t.get("calls", []):
                    n += count_nodes(c)
                return n
            nc = count_nodes(trace)

            fixture = {
                "meta": {
                    "slug": entry["slug"],
                    "name": entry["name"],
                    "category": entry["category"],
                    "contract": entry["contract"].lower(),
                    "expect": entry["expect"],
                    "source": "etherscan",
                },
                "tx": tx_meta,
                "trace": trace,
                "logs": logs,
            }

            with open(out_path, "w") as f:
                json.dump(fixture, f, indent=2, default=str)

            size_kb = out_path.stat().st_size / 1024
            print(f"OK ({nc} nodes, {len(logs)} logs, {size_kb:.0f} KB)")
            saved += 1

        except Exception as e:
            print(f"FAILED: {e}")

    print(f"\nDone: {saved}/{len(REAL_ATTACKS)} fixtures in {FIXTURES_DIR}")
    print("Run: python -m pytest tests/test_golden_traces.py -v")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--etherscan-key", default=os.environ.get("ETHERSCAN_API_KEY"))
    args = parser.parse_args()

    if not args.etherscan_key:
        print("Provide --etherscan-key or set ETHERSCAN_API_KEY env var")
        sys.exit(1)

    harvest(args.etherscan_key)
