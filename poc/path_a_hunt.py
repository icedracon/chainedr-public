#!/usr/bin/env python3
"""
Path A hunt: bytecode-prove unverified 7702 delegators.

For each target: fetch real mainnet runtime bytecode, static-profile it, then on a
LOCAL anvil install the bytecode + delegate a fresh TEST victim and run the
Phase-2 probes as a non-owner attacker:
  - unauthorized state write (a third party mutates persistent storage via a
    public selector — the Porwarder/unprotected-setter class)
  - value forwarding (does inbound ETH to the delegated account get swept out)

Fully sandboxed: a test victim on local anvil, no real account is touched.
Run (WSL, anvil on 127.0.0.1:8545):  python3 poc/path_a_hunt.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from web3 import Web3
from bytecode_oracle import (
    EIP7702DelegationProbe,
    extract_push4_selectors,
    fetch_runtime_bytecode,
    profile_bytecode,
)

# REAL live delegation-target implementations harvested from the type-4 stream
# (400 recent blocks), by delegation frequency. The earlier BundleBear top-5 were
# fabricated (code=0/nonce=0); these are genuine, actively-delegated contracts.
TARGETS = {
    "live_3572": "0xe6B97aA1490c93c28A14D86C13C9dc9c950643ed",
    "live_1511": "0x27DbD0e71b85700E29994d6D3a51F2e32442AA61",
    "live_366":  "0x18eC006842f647B40a81353b3497D5f589e416EA",
    "live_111":  "0xC43B6C6a43e5760A756a67756b2155C7fA735310",
    "live_56":   "0xD2e28229F6f2c235e57De2EbC727025A1D0530FB",
    "live_55a":  "0xCce0A2eBE17c5E532802896Fc8AfCaaB8aBD8ba0",
    "live_55b":  "0x0000Fb7702036ff9f76044a501ac1aA74cbab16b",
    "live_44":   "0x545940F521452b4138b360aD55E28667ea07a8bf",
    "live_41":   "0x56EF4D420533e3C4c7E79c64D1f958aA89D2C3a9",
    "live_37a":  "0xe6Cae83BdE06E4c305530e199D7217f42808555B",
    "live_37b":  "0x1f760b5Dfe50b7b4e33533571b3cD82eE58B2d89",
}
ANVIL = os.environ.get("ANVIL_URL", "http://127.0.0.1:8545")
KNOWN = {"c4d66de8": "initialize(address)"}


def main():
    anvil = Web3(Web3.HTTPProvider(ANVIL))
    assert anvil.is_connected(), f"anvil not reachable at {ANVIL}"
    attacker = anvil.eth.accounts[2]
    findings = []

    for idx, (name, addr) in enumerate(TARGETS.items()):
        print(f"\n===== {name} {addr} =====")
        try:
            runtime = fetch_runtime_bytecode(addr)
        except Exception as e:
            print(f"  fetch failed: {e}")
            continue
        if not runtime or runtime in ("0x", "0x0"):
            print("  no code at address (EOA / self-destructed)")
            continue
        prof = profile_bytecode(runtime, addr)
        selectors = (extract_push4_selectors(runtime, dispatcher_only=True)
                     or extract_push4_selectors(runtime))
        print(f"  code={prof.code_size}B  static_severity={prof.severity}  "
              f"selectors={len(selectors)}  flags={prof.risk_flags}")

        # fresh victim per target so storage starts clean
        victim = "0x7702" + f"{idx:036x}"
        probe = EIP7702DelegationProbe(anvil, Web3.to_checksum_address(victim))

        # 1) unauthorized state writes
        confirmed = probe.confirm_unauthorized_state_writes(
            addr, selectors, attacker, runtime_bytecode=runtime)
        for v in confirmed:
            sig = KNOWN.get(v.selector, v.selector)
            print(f"  [STATE-WRITE] non-owner wrote {v.changed_slots} via {v.selector} ({sig})")
            findings.append((name, addr, "unauthorized_state_write", v.to_dict()))

        # 2) value forwarding / sweep on inbound ETH
        vf = probe.probe_receive_value(addr, runtime_bytecode=runtime, value_wei=10**18)
        if vf.observed_outbound_value:
            print(f"  [VALUE-SWEEP] inbound ETH forwarded out: "
                  f"{[f.to_dict() for f in vf.value_flows]}")
            findings.append((name, addr, "inbound_value_forwarded", vf.to_dict()))

        if not confirmed and not vf.observed_outbound_value:
            print("  clean (no unauthorized state write, no value sweep)")

    print("\n========== SUMMARY ==========")
    if not findings:
        print("No confirmed findings across targets (expected on hardened accounts).")
    for name, addr, kind, _ in findings:
        print(f"  {name} {addr}: {kind}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
