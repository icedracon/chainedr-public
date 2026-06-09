#!/usr/bin/env python3
"""
Fork-mode dynamic confirmation of an EIP-7702 finding — thin driver over the
reusable `ForkOracle` engine (src/fork_oracle.py).

Static analysis says "this code.length==0 EOA check is risky under 7702"
(AA7702-002, UNCERTAIN). This forks mainnet, deploys a victim EOA gate, applies a
real 7702 delegation, and dynamically confirms the bypass.

Run (toolchain lives in WSL):
  wsl -d Ubuntu-22.04 -- bash -lc \
    "export PATH=\$HOME/.foundry/bin:\$PATH; RPC_URL=<url> \
     python3 <repo-root>/poc/fork_7702_oracle.py"
"""
import json, os, subprocess, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from fork_oracle import ForkOracle  # noqa: E402

# A real, deployed 7702-capable implementation (ZeroDev Kernel v3.3) to delegate to.
IMPL = "0xd6CEDDe84be40893d153Be9d467CD6aD37875b28"
EOA = "0x00000000000000000000000000000000DeAd7702"

VICTIM_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EOAGate {
    function isEOA(address a) external view returns (bool) { return a.code.length == 0; }
}
"""


def compile_victim():
    p = subprocess.run(["solc", "--combined-json", "abi,bin", "-"],
                       input=VICTIM_SRC.encode(), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode()[:600])
    c = next(v for k, v in json.loads(p.stdout)["contracts"].items() if k.endswith(":EOAGate"))
    abi = c["abi"]
    return (abi if isinstance(abi, list) else json.loads(abi)), c["bin"]


def main():
    with ForkOracle() as fo:
        print(f"[*] forked mainnet @ block {fo.block}")
        abi, bytecode = compile_victim()
        gate = fo.deploy(abi, bytecode)
        print(f"[*] deployed EOAGate at {gate.address}")

        v = fo.confirm_eoa_gate(
            gate_call=lambda a: gate.functions.isEOA(fo.w3.to_checksum_address(a)).call(),
            eoa=EOA, implementation=IMPL, finding="AA7702-002",
        )
        print(f"[*] before delegation: isEOA={v.before}")
        print(f"[*] after  delegation: isEOA={v.after}")
        print()
        print(json.dumps(v.to_dict(), indent=2))
        print()
        if v.confirmed:
            print("DIVERGENCE PROVEN: AA7702-002 dynamically confirmed on a mainnet fork "
                  "(a code.length==0 EOA gate is bypassed by a delegated account).")
            return 0
        print("no divergence (unexpected)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
