"""
Generate synthetic but structurally-accurate trace fixtures for golden tests.

These replicate the EXACT JSON structure Geth/Erigon returns, with realistic
call trees that trigger specific detector signals. No archive node needed.

Run: python tests/fixtures/generate_synthetic.py
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "traces"
OUT.mkdir(parents=True, exist_ok=True)

# Standard addresses
ATTACKER = "0x" + "a1" * 20
VICTIM   = "0x" + "b2" * 20
AAVE_V2  = "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"
BALANCER = "0xba12222222228d8ba445958a75a0704d566bf2c8"
UNISWAP  = "0x" + "d4" * 20
TOKEN_A  = "0x" + "e5" * 20
TOKEN_B  = "0x" + "f6" * 20
PROXY    = "0x" + "c3" * 20
IMPL     = "0x" + "77" * 20
NEW_ADDR = "0x" + "88" * 20
ECRECOVER = "0x0000000000000000000000000000000000000001"

ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

def addr_topic(addr):
    return "0x" + "0" * 24 + addr[2:]

def uint256_hex(v):
    return "0x" + v.to_bytes(32, "big").hex()


def save(slug, meta, trace, logs=None, tx_override=None):
    tx = {
        "hash": "0x" + "00" * 32,
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "blockNumber": 18000000,
        "trace_format": "geth",
    }
    if tx_override:
        tx.update(tx_override)
    fixture = {
        "meta": meta,
        "tx": tx,
        "trace": trace,
        "logs": logs or [],
    }
    p = OUT / f"{slug}.json"
    with open(p, "w") as f:
        json.dump(fixture, f, indent=2)
    print(f"  {slug}.json ({len(json.dumps(fixture))//1024} KB)")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Flash loan via Aave V2 — classic pattern
# ═══════════════════════════════════════════════════════════════════════════════
def gen_flash_loan_aave():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            # Victim calls Aave V2 flashLoan
            {
                "type": "CALL",
                "from": VICTIM,
                "to": AAVE_V2,
                "value": "0x0",
                "gas": "0x60000",
                "gasUsed": "0x40000",
                "input": "0xab9c4b5d",  # flashLoan selector
                "output": "0x1",
                "calls": [
                    # Aave calls back with executeOperation
                    {
                        "type": "CALL",
                        "from": AAVE_V2,
                        "to": VICTIM,
                        "value": "0x0",
                        "gas": "0x50000",
                        "gasUsed": "0x30000",
                        "input": "0x920f5c84" + "00" * 128,  # aave_v2_executeOperation
                        "output": "0x1",
                        "calls": [
                            # Inside callback: swap on Uniswap
                            {
                                "type": "CALL",
                                "from": VICTIM,
                                "to": UNISWAP,
                                "value": "0x0",
                                "gas": "0x30000",
                                "gasUsed": "0x10000",
                                "input": "0x38ed1739",
                                "output": "0x1",
                            },
                        ],
                    },
                    # Aave pulls repayment
                    {
                        "type": "CALL",
                        "from": AAVE_V2,
                        "to": TOKEN_A,
                        "value": "0x0",
                        "gas": "0x10000",
                        "gasUsed": "0x5000",
                        "input": "0x23b872dd",  # transferFrom
                        "output": "0x1",
                    },
                ],
            },
        ],
    }
    save("flash_loan_aave_v2", {
        "slug": "flash_loan_aave_v2",
        "name": "Flash Loan via Aave V2",
        "category": "FLASH_LOAN",
        "contract": VICTIM,
        "expect": {
            "flash_loan": True,
            "flash_loan_providers": ["aave_v2"],
            "reentrancy": True,  # callback IS a re-entrant call to victim
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Flash loan via Balancer — receiveFlashLoan callback
# ═══════════════════════════════════════════════════════════════════════════════
def gen_flash_loan_balancer():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            {
                "type": "CALL",
                "from": VICTIM,
                "to": BALANCER,
                "value": "0x0",
                "gas": "0x60000",
                "gasUsed": "0x40000",
                "input": "0x5c38449e",  # flashLoan
                "output": "0x1",
                "calls": [
                    {
                        "type": "CALL",
                        "from": BALANCER,
                        "to": VICTIM,
                        "value": "0x0",
                        "gas": "0x50000",
                        "gasUsed": "0x30000",
                        "input": "0xf04f2707" + "00" * 128,  # receiveFlashLoan
                        "output": "0x1",
                    },
                ],
            },
        ],
    }
    save("flash_loan_balancer", {
        "slug": "flash_loan_balancer",
        "name": "Flash Loan via Balancer",
        "category": "FLASH_LOAN",
        "contract": VICTIM,
        "expect": {
            "flash_loan": True,
            "flash_loan_providers": ["balancer"],
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Same-function reentrancy (DAO-style)
# ═══════════════════════════════════════════════════════════════════════════════
def gen_reentrancy_same():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0x3ccfd60b",  # withdraw()
        "output": "0x1",
        "calls": [
            {
                "type": "CALL",
                "from": VICTIM,
                "to": ATTACKER,
                "value": "0xde0b6b3a7640000",  # 1 ETH
                "gas": "0x50000",
                "gasUsed": "0x30000",
                "input": "0x",
                "output": "0x1",
                "calls": [
                    # Reentrant call — same selector
                    {
                        "type": "CALL",
                        "from": ATTACKER,
                        "to": VICTIM,
                        "value": "0x0",
                        "gas": "0x40000",
                        "gasUsed": "0x20000",
                        "input": "0x3ccfd60b",
                        "output": "0x1",
                        "calls": [
                            {
                                "type": "CALL",
                                "from": VICTIM,
                                "to": ATTACKER,
                                "value": "0xde0b6b3a7640000",
                                "gas": "0x30000",
                                "gasUsed": "0x10000",
                                "input": "0x",
                                "output": "0x1",
                            },
                        ],
                    },
                ],
            },
        ],
    }
    save("reentrancy_same_function", {
        "slug": "reentrancy_same_function",
        "name": "Same-function reentrancy (DAO-style)",
        "category": "REENTRANCY",
        "contract": VICTIM,
        "expect": {
            "reentrancy": True,
            "reentrancy_exploitable": True,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Cross-function reentrancy (Curve-style)
# ═══════════════════════════════════════════════════════════════════════════════
def gen_reentrancy_cross():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xe8e33700",  # addLiquidity
        "output": "0x1",
        "calls": [
            {
                "type": "CALL",
                "from": VICTIM,
                "to": ATTACKER,
                "value": "0xde0b6b3a7640000",
                "gas": "0x50000",
                "gasUsed": "0x30000",
                "input": "0x",
                "output": "0x1",
                "calls": [
                    # Reentrant call — DIFFERENT selector
                    {
                        "type": "CALL",
                        "from": ATTACKER,
                        "to": VICTIM,
                        "value": "0x0",
                        "gas": "0x40000",
                        "gasUsed": "0x20000",
                        "input": "0x2e1a7d4d",  # withdraw — different fn
                        "output": "0x1",
                    },
                ],
            },
        ],
    }
    save("reentrancy_cross_function", {
        "slug": "reentrancy_cross_function",
        "name": "Cross-function reentrancy",
        "category": "REENTRANCY",
        "contract": VICTIM,
        "expect": {
            "reentrancy": True,
            "reentrancy_exploitable": True,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Read-only reentrancy (STATICCALL)
# ═══════════════════════════════════════════════════════════════════════════════
def gen_reentrancy_readonly():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0x3ccfd60b",
        "output": "0x1",
        "calls": [
            {
                "type": "CALL",
                "from": VICTIM,
                "to": ATTACKER,
                "value": "0xde0b6b3a7640000",
                "gas": "0x50000",
                "gasUsed": "0x30000",
                "input": "0x",
                "output": "0x1",
                "calls": [
                    # Read-only reentrant — STATICCALL
                    {
                        "type": "STATICCALL",
                        "from": ATTACKER,
                        "to": VICTIM,
                        "value": "0x0",
                        "gas": "0x40000",
                        "gasUsed": "0x5000",
                        "input": "0x3ccfd60b",
                        "output": "0x1",
                    },
                ],
            },
        ],
    }
    save("reentrancy_read_only", {
        "slug": "reentrancy_read_only",
        "name": "Read-only reentrancy (STATICCALL)",
        "category": "REENTRANCY",
        "contract": VICTIM,
        "expect": {
            "reentrancy": True,
            "reentrancy_exploitable": False,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. DELEGATECALL proxy pattern
# ═══════════════════════════════════════════════════════════════════════════════
def gen_delegatecall_proxy():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": PROXY,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            {
                "type": "DELEGATECALL",
                "from": PROXY,
                "to": IMPL,
                "value": "0x0",
                "gas": "0x60000",
                "gasUsed": "0x40000",
                "input": "0xdeadbeef",
                "output": "0x1",
                "calls": [
                    {
                        "type": "CALL",
                        "from": PROXY,  # context is still proxy
                        "to": UNISWAP,
                        "value": "0x0",
                        "gas": "0x30000",
                        "gasUsed": "0x10000",
                        "input": "0x38ed1739",
                        "output": "0x1",
                    },
                ],
            },
        ],
    }
    save("delegatecall_proxy", {
        "slug": "delegatecall_proxy",
        "name": "DELEGATECALL through proxy",
        "category": "PROXY",
        "contract": PROXY,
        "expect": {
            "delegatecall_present": True,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. CREATE2 deploying fresh contract
# ═══════════════════════════════════════════════════════════════════════════════
def gen_create2():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            {
                "type": "CREATE2",
                "from": VICTIM,
                "to": "",
                "value": "0x0",
                "gas": "0x40000",
                "gasUsed": "0x20000",
                "input": "0x6080604052" + "00" * 50,  # init bytecode
                "output": "0x" + "00" * 12 + NEW_ADDR[2:],  # deployed address in last 20 bytes
            },
            {
                "type": "CALL",
                "from": VICTIM,
                "to": NEW_ADDR,
                "value": "0x0",
                "gas": "0x20000",
                "gasUsed": "0x10000",
                "input": "0xdeadbeef",
                "output": "0x1",
            },
        ],
    }
    save("create2_fresh_contract", {
        "slug": "create2_fresh_contract",
        "name": "CREATE2 deploying attack contract",
        "category": "CREATE2",
        "contract": VICTIM,
        "expect": {
            "fresh_contracts": [NEW_ADDR],
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. SELFDESTRUCT
# ═══════════════════════════════════════════════════════════════════════════════
def gen_selfdestruct():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            {
                "type": "SELFDESTRUCT",
                "from": VICTIM,
                "to": ATTACKER,
                "value": "0xde0b6b3a7640000",
                "gas": "0x10000",
                "gasUsed": "0x1000",
                "input": "0x",
                "output": "0x",
            },
        ],
    }
    save("selfdestruct", {
        "slug": "selfdestruct",
        "name": "SELFDESTRUCT draining ETH",
        "category": "SELFDESTRUCT",
        "contract": VICTIM,
        "expect": {
            "selfdestruct_present": True,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Reverted subcall — ETH not counted
# ═══════════════════════════════════════════════════════════════════════════════
def gen_reverted_subcall():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0xde0b6b3a7640000",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            # This subcall reverts — its ETH should NOT be counted
            {
                "type": "CALL",
                "from": VICTIM,
                "to": UNISWAP,
                "value": "0x1bc16d674ec80000",  # 2 ETH
                "gas": "0x30000",
                "gasUsed": "0x1000",
                "input": "0x38ed1739",
                "output": "0x",
                "error": "execution reverted",
                "revertReason": "insufficient liquidity",
            },
            # This succeeds
            {
                "type": "CALL",
                "from": VICTIM,
                "to": UNISWAP,
                "value": "0x6f05b59d3b20000",  # 0.5 ETH
                "gas": "0x30000",
                "gasUsed": "0x10000",
                "input": "0x38ed1739",
                "output": "0x1",
            },
        ],
    }
    save("reverted_subcall", {
        "slug": "reverted_subcall",
        "name": "Reverted subcall ETH handling",
        "category": "REVERT",
        "contract": VICTIM,
        "expect": {
            "eth_in_wei": 1_000_000_000_000_000_000,   # 1 ETH to victim
            "eth_out_wei": 500_000_000_000_000_000,     # 0.5 ETH out (reverted 2 ETH not counted)
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Callback hijack — protocol calls back to attacker
# ═══════════════════════════════════════════════════════════════════════════════
def gen_callback_hijack():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            # Victim calls some external protocol
            {
                "type": "CALL",
                "from": VICTIM,
                "to": UNISWAP,
                "value": "0x0",
                "gas": "0x50000",
                "gasUsed": "0x30000",
                "input": "0x38ed1739",
                "output": "0x1",
                "calls": [
                    # Protocol calls BACK to attacker (callback hijack)
                    {
                        "type": "CALL",
                        "from": UNISWAP,
                        "to": ATTACKER,
                        "value": "0x0",
                        "gas": "0x30000",
                        "gasUsed": "0x10000",
                        "input": "0x10d1e85c" + "00" * 96,  # uniswapV2Call
                        "output": "0x1",
                    },
                ],
            },
        ],
    }
    save("callback_hijack", {
        "slug": "callback_hijack",
        "name": "Callback hijack via Uniswap V2",
        "category": "CALLBACK",
        "contract": VICTIM,
        "expect": {
            "callback_hijacks_count": 1,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Direct token gift (ERC4626 donation attack)
# ═══════════════════════════════════════════════════════════════════════════════
def gen_token_gift():
    logs = [
        {
            "address": TOKEN_A,
            "topics": [
                ERC20_TRANSFER_TOPIC,
                addr_topic(ATTACKER),
                addr_topic(VICTIM),
            ],
            "data": uint256_hex(10**18),
            "logIndex": 0,
        },
        # NO Deposit event from VICTIM
    ]
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": TOKEN_A,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xa9059cbb" + "00" * 64,  # transfer
        "output": "0x1",
    }
    save("direct_token_gift", {
        "slug": "direct_token_gift",
        "name": "ERC4626 donation attack",
        "category": "DONATION",
        "contract": VICTIM,
        "expect": {
            "direct_token_gift": True,
        },
    }, trace, logs=logs)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Deep call tree (90+ depth) — stress test
# ═══════════════════════════════════════════════════════════════════════════════
def gen_deep_tree():
    def nest(depth, max_depth):
        node = {
            "type": "CALL",
            "from": f"0x{'%02x' % (depth % 256)}" + "00" * 19,
            "to": f"0x{'%02x' % ((depth+1) % 256)}" + "00" * 19,
            "value": "0x0",
            "gas": hex(100000 - depth * 100),
            "gasUsed": hex(50000 - depth * 50),
            "input": "0xdeadbeef",
            "output": "0x1",
        }
        if depth < max_depth:
            node["calls"] = [nest(depth + 1, max_depth)]
        return node

    trace = nest(0, 90)
    save("deep_call_tree_90", {
        "slug": "deep_call_tree_90",
        "name": "90-depth call tree (stress test)",
        "category": "STRESS",
        "contract": VICTIM,
        "expect": {
            "max_depth_gte": 90,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 13. Erigon flat-array format
# ═══════════════════════════════════════════════════════════════════════════════
def gen_erigon_flat():
    trace = [
        {
            "action": {"callType": "call", "from": ATTACKER, "to": VICTIM, "value": "0xde0b6b3a7640000",
                       "gas": "0x7a120", "input": "0xdeadbeef"},
            "result": {"gasUsed": "0x5dc00", "output": "0x1"},
            "subtraces": 1,
            "traceAddress": [],
            "type": "call",
        },
        {
            "action": {"callType": "call", "from": VICTIM, "to": UNISWAP, "value": "0x0",
                       "gas": "0x50000", "input": "0x38ed1739"},
            "result": {"gasUsed": "0x30000", "output": "0x1"},
            "subtraces": 0,
            "traceAddress": [0],
            "type": "call",
        },
    ]
    save("erigon_flat_array", {
        "slug": "erigon_flat_array",
        "name": "Erigon flat-array trace format",
        "category": "FORMAT",
        "contract": VICTIM,
        "expect": {
            "nodes_gte": 2,
        },
    }, trace, tx_override={"trace_format": "erigon"})


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Flash loan + reentrancy combo (Fei/Rari style)
# ═══════════════════════════════════════════════════════════════════════════════
def gen_flash_loan_reentrancy():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            # Flash loan from Aave V2
            {
                "type": "CALL",
                "from": VICTIM,
                "to": AAVE_V2,
                "value": "0x0",
                "gas": "0x60000",
                "gasUsed": "0x50000",
                "input": "0xab9c4b5d",
                "output": "0x1",
                "calls": [
                    # executeOperation callback
                    {
                        "type": "CALL",
                        "from": AAVE_V2,
                        "to": VICTIM,
                        "value": "0x0",
                        "gas": "0x50000",
                        "gasUsed": "0x40000",
                        "input": "0x920f5c84" + "00" * 128,
                        "output": "0x1",
                        "calls": [
                            # Inside callback: trigger reentrancy
                            {
                                "type": "CALL",
                                "from": VICTIM,
                                "to": ATTACKER,
                                "value": "0xde0b6b3a7640000",
                                "gas": "0x30000",
                                "gasUsed": "0x20000",
                                "input": "0x",
                                "output": "0x1",
                                "calls": [
                                    # Reentrant call
                                    {
                                        "type": "CALL",
                                        "from": ATTACKER,
                                        "to": VICTIM,
                                        "value": "0x0",
                                        "gas": "0x20000",
                                        "gasUsed": "0x10000",
                                        "input": "0x920f5c84",
                                        "output": "0x1",
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    }
    save("flash_loan_plus_reentrancy", {
        "slug": "flash_loan_plus_reentrancy",
        "name": "Flash loan + reentrancy combo",
        "category": "COMBO",
        "contract": VICTIM,
        "expect": {
            "flash_loan": True,
            "reentrancy": True,
            "reentrancy_exploitable": True,
            "is_critical": True,
        },
    }, trace)


# ═══════════════════════════════════════════════════════════════════════════════
# 15. Precompile calls (ecrecover)
# ═══════════════════════════════════════════════════════════════════════════════
def gen_precompile():
    trace = {
        "type": "CALL",
        "from": ATTACKER,
        "to": VICTIM,
        "value": "0x0",
        "gas": "0x7a120",
        "gasUsed": "0x5dc00",
        "input": "0xdeadbeef",
        "output": "0x1",
        "calls": [
            {
                "type": "STATICCALL",
                "from": VICTIM,
                "to": ECRECOVER,
                "value": "0x0",
                "gas": "0x10000",
                "gasUsed": "0xc00",
                "input": "0x" + "ab" * 128,
                "output": "0x" + "00" * 12 + "aa" * 20,
            },
            {
                "type": "STATICCALL",
                "from": VICTIM,
                "to": ECRECOVER,
                "value": "0x0",
                "gas": "0x10000",
                "gasUsed": "0xc00",
                "input": "0x" + "cd" * 128,
                "output": "0x" + "00" * 12 + "bb" * 20,
            },
        ],
    }
    save("precompile_ecrecover", {
        "slug": "precompile_ecrecover",
        "name": "ecrecover precompile calls",
        "category": "PRECOMPILE",
        "contract": VICTIM,
        "expect": {
            "ecrecover_calls": 2,
            "precompiles_excluded_from_unique": True,
        },
    }, trace)


if __name__ == "__main__":
    print("Generating synthetic golden fixtures:")
    gen_flash_loan_aave()
    gen_flash_loan_balancer()
    gen_reentrancy_same()
    gen_reentrancy_cross()
    gen_reentrancy_readonly()
    gen_delegatecall_proxy()
    gen_create2()
    gen_selfdestruct()
    gen_reverted_subcall()
    gen_callback_hijack()
    gen_token_gift()
    gen_deep_tree()
    gen_erigon_flat()
    gen_flash_loan_reentrancy()
    gen_precompile()
    print(f"\nDone: {len(list(OUT.glob('*.json')))} fixtures in {OUT}")
