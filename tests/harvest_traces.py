"""
Trace fixture harvester — one-time script to fetch real exploit traces from archive node.

Usage:
    python tests/harvest_traces.py --rpc https://eth-mainnet.g.alchemy.com/v2/KEY

Fetches debug_traceTransaction (Geth callTracer) + tx receipt for each known attack.
Saves to tests/fixtures/traces/<name>.json — committed to repo for offline golden tests.

Run once when you have archive node access. Tests never need live RPC after this.
"""
from __future__ import annotations

import json
import os
import sys
import time
import argparse
from pathlib import Path
from typing import Any

try:
    from web3 import Web3
except ImportError:
    print("pip install web3 first")
    sys.exit(1)


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "traces"

# 20 real attacks covering all detection categories
# Each entry: (slug, tx_hash, victim_contract, category, expected_findings)
GOLDEN_ATTACKS = [
    # ── Flash loan attacks ──────────────────────────────────────────────────
    {
        "slug": "euler_2023",
        "name": "Euler Finance",
        "tx": "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887ad48c4f0b76b672e66c7f820d",
        "contract": "0x27182842E098f60e3D576794A5bFFb0777E025d3",
        "category": "FLASH_LOAN",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "cream_oct_2021",
        "name": "Cream Finance (Oct 2021)",
        "tx": "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
        "contract": "0x7589dB3A0B29B29B59F1cB4F7d90B094a39ecF3e",
        "category": "FLASH_LOAN",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "value_defi_2020",
        "name": "Value DeFi",
        "tx": "0x65f6a3d8ad160de58f9d73c47b1cd9b72b2f5b8e89a30f07d59e2db8a946a91d",
        "contract": "0x0d7E906BD9cAFa154b048cFa766Cc1E54E39AF9B",
        "category": "FLASH_LOAN",
        "expect": {"flash_loan": True},
    },
    # ── Reentrancy attacks ──────────────────────────────────────────────────
    {
        "slug": "the_dao_2016",
        "name": "The DAO",
        "tx": "0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3571d8571607b19d",
        "contract": "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413",
        "category": "REENTRANCY",
        "expect": {"reentrancy": True},
    },
    {
        "slug": "curve_vyper_2023",
        "name": "Curve Vyper reentrancy",
        "tx": "0xa84aa065ce61dbb1eb50ab6ae67fc31a9da50dd2571c5b6cdea04fda43d0e798",
        "contract": "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022",
        "category": "REENTRANCY",
        "expect": {"reentrancy": True},
    },
    {
        "slug": "fei_rari_2022",
        "name": "Fei/Rari Capital",
        "tx": "0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530",
        "contract": "0xe16DB319d9dA7Ce40b666DD2E365a4b8B3C18217",
        "category": "REENTRANCY",
        "expect": {"reentrancy": True},
    },
    # ── Oracle manipulation ─────────────────────────────────────────────────
    {
        "slug": "bzx_feb_2020",
        "name": "bZx (Feb 2020)",
        "tx": "0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838",
        "contract": "0x9441d7556e7820B5ca42082cfa99487D56AcA958",
        "category": "ORACLE",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "harvest_2020",
        "name": "Harvest Finance",
        "tx": "0x35f8d2f572fceaac9288e5d462117850ef2694786992a8c3f6d02612277b0877",
        "contract": "0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE",
        "category": "ORACLE",
        "expect": {},
    },
    {
        "slug": "warp_2020",
        "name": "Warp Finance",
        "tx": "0x8bb8dc5c7c830bac85fa48acad2505e9300a91c3ff239c9517d0cae33b595090",
        "contract": "0xC5C2453B76360bCf1d4e3E94bA06bF69C5Df4C5",
        "category": "ORACLE",
        "expect": {"flash_loan": True},
    },
    # ── Delegation / proxy ──────────────────────────────────────────────────
    {
        "slug": "poly_network_2021",
        "name": "Poly Network",
        "tx": "0xad7a2c70c958fcd3ab9a043e30a85b9d46a3f0c8f2e22ee4b46f0e32fbb4fe63",
        "contract": "0x250e76987d838a75310c34bf422ea9f1AC4Cc906",
        "category": "ACCESS_CONTROL",
        "expect": {"delegatecall_present": True},
    },
    # ── SELFDESTRUCT ─────────────────────────────────────────────────────────
    {
        "slug": "parity_walletlib_2017",
        "name": "Parity WalletLib kill",
        "tx": "0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686e0722c9",
        "contract": "0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4",
        "category": "SELFDESTRUCT",
        "expect": {"selfdestruct_present": True},
    },
    # ── Share price / donation ──────────────────────────────────────────────
    {
        "slug": "erc4626_generic_donation",
        "name": "ERC4626 vault donation",
        "tx": "0x2e7dc8b2fb7e25fd00ed9565f0643f5209b993ac7b73eb74808c0e4e5607b116",
        "contract": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",
        "category": "DONATION",
        "expect": {},
    },
    # ── Complex multi-pattern ───────────────────────────────────────────────
    {
        "slug": "nomad_bridge_2022",
        "name": "Nomad Bridge",
        "tx": "0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4ed5d1",
        "contract": "0x88A69B4E698A4B090DF6CF5Bd7B2D47325Ad30A3",
        "category": "ACCESS_CONTROL",
        "expect": {},
    },
    {
        "slug": "beanstalk_2022",
        "name": "Beanstalk Governance",
        "tx": "0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7",
        "contract": "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
        "category": "GOVERNANCE",
        "expect": {"flash_loan": True},
    },
    {
        "slug": "ronin_bridge_2022",
        "name": "Ronin Bridge (validator theft, simple multisig)",
        "tx": "0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7",
        "contract": "0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2",
        "category": "ACCESS_CONTROL",
        "expect": {},
    },
]


def harvest_one(w3: Web3, entry: dict) -> dict | None:
    """Fetch trace + receipt for one transaction. Returns fixture dict or None."""
    tx_hash = entry["tx"]
    print(f"  [{entry['slug']}] Fetching {tx_hash[:18]}...", end=" ", flush=True)

    try:
        # 1. Transaction
        tx = w3.eth.get_transaction(tx_hash)
        tx_data = {
            "hash": tx_hash,
            "from": tx["from"].lower(),
            "to": (tx.get("to") or "").lower(),
            "value": hex(tx["value"]),
            "blockNumber": tx["blockNumber"],
        }
    except Exception as e:
        print(f"SKIP (tx fetch failed: {e})")
        return None

    try:
        # 2. Receipt (for logs)
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        logs_raw = []
        for log in receipt.get("logs", []):
            logs_raw.append({
                "address": log["address"].lower() if log.get("address") else "",
                "topics": [t.hex() if isinstance(t, bytes) else str(t) for t in (log.get("topics") or [])],
                "data": log["data"].hex() if isinstance(log["data"], bytes) else str(log.get("data", "0x")),
                "logIndex": log.get("logIndex", 0),
            })
    except Exception as e:
        print(f"SKIP (receipt failed: {e})")
        return None

    try:
        # 3. Debug trace (Geth callTracer)
        trace = w3.provider.make_request(
            "debug_traceTransaction",
            [tx_hash, {"tracer": "callTracer", "tracerConfig": {"withLog": True}}],
        )
        trace_result = trace.get("result")
        if not trace_result:
            # Try Parity/Erigon trace_transaction
            trace2 = w3.provider.make_request("trace_transaction", [tx_hash])
            trace_result = trace2.get("result")
            if trace_result:
                tx_data["trace_format"] = "erigon"
            else:
                print("SKIP (no trace data)")
                return None
        else:
            tx_data["trace_format"] = "geth"
    except Exception as e:
        print(f"SKIP (trace failed: {e})")
        return None

    fixture = {
        "meta": {
            "slug": entry["slug"],
            "name": entry["name"],
            "category": entry["category"],
            "contract": entry["contract"].lower(),
            "expect": entry["expect"],
        },
        "tx": tx_data,
        "trace": trace_result,
        "logs": logs_raw,
    }

    size_kb = len(json.dumps(fixture)) / 1024
    print(f"OK ({size_kb:.0f} KB, {tx_data['trace_format']})")
    return fixture


def harvest_all(rpc_url: str, slugs: list[str] | None = None):
    """Fetch all golden attack traces and save as fixtures."""
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 120}))
    if not w3.is_connected():
        print(f"Cannot connect to {rpc_url}")
        sys.exit(1)

    chain_id = w3.eth.chain_id
    latest = w3.eth.block_number
    print(f"Connected: chain_id={chain_id}, latest={latest}")

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    targets = GOLDEN_ATTACKS
    if slugs:
        targets = [a for a in GOLDEN_ATTACKS if a["slug"] in slugs]

    saved = 0
    for entry in targets:
        out_path = FIXTURES_DIR / f"{entry['slug']}.json"
        if out_path.exists():
            print(f"  [{entry['slug']}] Already exists, skipping")
            saved += 1
            continue

        fixture = harvest_one(w3, entry)
        if not fixture:
            continue

        with open(out_path, "w") as f:
            json.dump(fixture, f, indent=2, default=str)
        saved += 1
        time.sleep(0.5)  # rate limit

    print(f"\nDone: {saved}/{len(targets)} fixtures saved to {FIXTURES_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Harvest trace fixtures for golden tests")
    parser.add_argument("--rpc", required=True, help="Archive node RPC URL")
    parser.add_argument("--slug", nargs="*", help="Only harvest specific slugs")
    args = parser.parse_args()
    harvest_all(args.rpc, args.slug)
