#!/usr/bin/env python3
"""
Differential Oracle — working end-to-end demo (run natively where anvil+solc live).

Proves the dynamic-analysis flow the static detector cannot do:
  1. boot a fresh anvil node
  2. compile a REFERENCE vault and a TARGET vault with solc
  3. deploy both, seed them identically
  4. replay the SAME calldata against both
  5. diff return values  ->  flag divergence

Two scenarios are run:
  A. TARGET == REFERENCE  -> expect NO divergence  (false-positive control)
  B. TARGET has a planted rounding/inflation bug -> expect divergence DETECTED

Usage (from Windows):
  python3 <repo-root>/poc/differential_oracle_demo.py
"""
import json
import re
import shutil
import socket
import subprocess
import sys
import time

from web3 import Web3

SOLC = "solc"
ANVIL = subprocess.run(["bash", "-lc", "command -v anvil || echo ~/.foundry/bin/anvil"],
                       capture_output=True, text=True).stdout.strip()

REFERENCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    constructor(uint256 a, uint256 s){ totalAssets=a; totalSupply=s; }
    // correct ERC4626 share math, rounds DOWN (floor)
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 1) / (totalAssets + 1);
    }
}
"""

# Planted bug: rounds UP (ceil) -> systematic share inflation, depositors get
# more shares than they should, diluting existing holders. Classic ERC4626 vuln.
TARGET_BUGGY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    constructor(uint256 a, uint256 s){ totalAssets=a; totalSupply=s; }
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 num = assets * (totalSupply + 1);
        uint256 den = totalAssets + 1;
        uint256 q = num / den;
        if (num % den != 0) q += 1;   // BUG: ceil instead of floor
        return q;
    }
}
"""


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def compile_one(src, name):
    p = subprocess.run([SOLC, "--combined-json", "abi,bin", "--optimize", "-"],
                       input=src.encode(), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode()[:800])
    out = json.loads(p.stdout)
    for k, v in out["contracts"].items():
        if k.rsplit(":", 1)[-1] == name:
            abi = v["abi"]
            return (abi if isinstance(abi, list) else json.loads(abi)), v["bin"]
    raise KeyError(name)


def _version_tuple(solc_output: str) -> tuple[int, int, int] | None:
    match = re.search(r"Version:\s*(\d+)\.(\d+)\.(\d+)", solc_output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def check_prereqs() -> bool:
    solc_path = shutil.which(SOLC)
    if not solc_path:
        print("Missing solc. Run this demo in WSL Ubuntu-22.04 or install solc 0.8.20+.")
        return False

    solc_run = subprocess.run([SOLC, "--version"], capture_output=True, text=True)
    solc_out = solc_run.stdout.strip()
    print("solc  =", solc_out.splitlines()[-1] if solc_out else solc_path)
    solc_version = _version_tuple(solc_out)
    if solc_version is None or solc_version < (0, 8, 20):
        print("This demo requires solc 0.8.20+. On this machine, run it from WSL Ubuntu-22.04.")
        return False

    print(f"anvil = {ANVIL}")
    if not ANVIL:
        print("Missing anvil. Run this demo in WSL Ubuntu-22.04 where Foundry is installed.")
        return False
    try:
        anvil_run = subprocess.run([ANVIL, "--version"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.SubprocessError):
        print("Could not start anvil. Run this demo in WSL Ubuntu-22.04 where Foundry is installed.")
        return False
    if anvil_run.returncode != 0:
        print("Could not start anvil. Run this demo in WSL Ubuntu-22.04 where Foundry is installed.")
        return False
    return True


class Anvil:
    def __enter__(self):
        self.port = free_port()
        self.p = subprocess.Popen([ANVIL, "--port", str(self.port), "--silent"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{self.port}"))
            if w3.is_connected():
                return w3
            time.sleep(0.1)
        raise RuntimeError("anvil did not start")

    def __exit__(self, *a):
        self.p.terminate()
        try: self.p.wait(timeout=5)
        except subprocess.TimeoutExpired: self.p.kill()


def deploy(w3, abi, b, args, sender):
    c = w3.eth.contract(abi=abi, bytecode=b)
    tx = c.constructor(*args).transact({"from": sender})
    r = w3.eth.wait_for_transaction_receipt(tx)
    return w3.eth.contract(address=r.contractAddress, abi=abi)


def differential(target_src, reference_src, label):
    # seed both vaults with the SAME non-1:1 ratio so rounding direction matters
    ctor = (1_000_000_000, 333_333_333)            # totalAssets, totalSupply
    test_inputs = [1, 7, 100, 9999, 10**6, 10**18 - 1, 10**18]
    t_abi, t_bin = compile_one(target_src, "Vault")
    r_abi, r_bin = compile_one(reference_src, "Vault")
    diffs = []
    with Anvil() as w3:
        s = w3.eth.accounts[0]
        t = deploy(w3, t_abi, t_bin, ctor, s)
        r = deploy(w3, r_abi, r_bin, ctor, s)
        for x in test_inputs:
            to = t.functions.convertToShares(x).call()
            ro = r.functions.convertToShares(x).call()
            if to != ro:
                diffs.append((x, to, ro))
    print(f"\n=== Scenario {label} ===")
    if diffs:
        print(f"  DIVERGENCE DETECTED on {len(diffs)}/{len(test_inputs)} inputs:")
        for x, to, ro in diffs:
            print(f"    convertToShares({x}): target={to}  reference={ro}  (+{to-ro})")
    else:
        print("  EQUIVALENT — no divergence (control passed, no false alarm)")
    return diffs


def main():
    if not check_prereqs():
        sys.exit(2)
    # A. control: reference vs itself -> must be clean
    a = differential(REFERENCE, REFERENCE, "A (control: identical impls)")
    # B. buggy target vs reference -> must flag
    b = differential(TARGET_BUGGY, REFERENCE, "B (planted ceil-rounding inflation bug)")
    ok = (len(a) == 0) and (len(b) > 0)
    print("\n" + ("PASS — oracle is sound (no FP on A) and effective (caught B)"
                  if ok else "FAIL — unexpected result"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
