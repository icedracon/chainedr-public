"""
ChainEDR Differential Oracle

Deploys a target contract and an OpenZeppelin reference implementation
side-by-side on Anvil, calls the same functions with the same inputs,
and flags output deviations.

Catches bugs that are invisible to all other tools:
  - Wrong rounding direction (should be Floor, is Ceil)
  - Systematic share inflation / deflation
  - Fee accounting errors
  - Non-monotone conversion functions

Currently supports: ERC4626
"""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from web3 import Web3


# ─────────────────────────────────────────────────────────────────────────────
# OZ ERC4626 reference — minimal, faithful rounding logic
# ─────────────────────────────────────────────────────────────────────────────

_OZ_ERC4626_REFERENCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Stripped-down OZ ERC4626 for differential testing.
// Asset is a constructor-supplied MockERC20.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

library Math {
    enum Rounding { Floor, Ceil }
    function mulDiv(uint256 x, uint256 y, uint256 d, Rounding r)
        internal pure returns (uint256)
    {
        uint256 result = mulDiv(x, y, d);
        if (r == Rounding.Ceil && mulmod(x, y, d) != 0) result += 1;
        return result;
    }
    function mulDiv(uint256 x, uint256 y, uint256 d)
        internal pure returns (uint256) { return x * y / d; }
}

contract OZVaultReference {
    using Math for uint256;
    IERC20 private immutable _asset;
    mapping(address => uint256) private _bal;
    uint256 private _supply;

    constructor(IERC20 asset_) { _asset = asset_; }

    function asset() external view returns (address) { return address(_asset); }
    function totalAssets() public view returns (uint256) {
        return _asset.balanceOf(address(this));
    }
    function totalSupply() external view returns (uint256) { return _supply; }
    function balanceOf(address a) external view returns (uint256) { return _bal[a]; }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return _convert(assets, Math.Rounding.Floor);
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return shares.mulDiv(totalAssets() + 1, _supply + 1, Math.Rounding.Floor);
    }
    function previewDeposit(uint256 assets) external view returns (uint256) {
        return _convert(assets, Math.Rounding.Floor);
    }
    function previewMint(uint256 shares) external view returns (uint256) {
        return shares.mulDiv(totalAssets() + 1, _supply + 1, Math.Rounding.Ceil);
    }
    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return _convert(assets, Math.Rounding.Ceil);
    }
    function previewRedeem(uint256 shares) external view returns (uint256) {
        return convertToAssets(shares);
    }
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        _asset.transferFrom(msg.sender, address(this), assets);
        _supply += shares; _bal[receiver] += shares;
    }
    function redeem(uint256 shares, address receiver, address owner_)
        external returns (uint256 assets)
    {
        assets = convertToAssets(shares);
        _supply -= shares; _bal[owner_] -= shares;
        _asset.transfer(receiver, assets);
    }
    function maxDeposit(address) external pure returns (uint256) { return type(uint256).max; }
    function maxWithdraw(address) external pure returns (uint256) { return type(uint256).max; }
    function maxRedeem(address) external pure returns (uint256) { return type(uint256).max; }
    function maxMint(address) external pure returns (uint256) { return type(uint256).max; }

    function _convert(uint256 assets, Math.Rounding r) private view returns (uint256) {
        return assets.mulDiv(_supply + 1, totalAssets() + 1, r);
    }
}
"""

_MOCK_ERC20_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MockERC20 {
    string public name = "Mock"; string public symbol = "MCK"; uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 v) external { balanceOf[to] += v; totalSupply += v; }
    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v; return true;
    }
    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v; balanceOf[to] += v; return true;
    }
    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v; balanceOf[f] -= v; balanceOf[to] += v; return true;
    }
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DiffFinding:
    function: str
    input_args: Dict[str, Any]
    target_output: Any
    reference_output: Any
    deviation_pct: float           # |target - reference| / reference * 100
    severity: str
    description: str


# ─────────────────────────────────────────────────────────────────────────────
# Compiler helper
# ─────────────────────────────────────────────────────────────────────────────

class _Compiler:
    WSL_DISTRO = "Ubuntu-22.04"
    WSL_VENV   = "/root/chainedr_venv/bin"

    def compile(self, source: str) -> Optional[Dict[str, Tuple[List[Dict], str]]]:
        """Returns {contract_name: (abi, bytecode)} for all contracts in source."""
        uid = uuid.uuid4().hex[:8]
        tmp = f"/tmp/_chainedr_diff_{uid}.sol"
        try:
            subprocess.run(
                ["wsl", "-d", self.WSL_DISTRO, "--", "bash", "-c",
                 f"cat > {tmp}"],
                input=source.encode("utf-8"), capture_output=True, timeout=10,
            )
            proc = subprocess.run(
                ["wsl", "-d", self.WSL_DISTRO, "--", "bash", "-c",
                 f"export PATH={self.WSL_VENV}:$PATH && "
                 f"solc --combined-json abi,bin {tmp} 2>/dev/null"],
                capture_output=True, text=True, timeout=30,
            )
            if not proc.stdout.strip():
                return None
            data = json.loads(proc.stdout)
            result = {}
            for key, val in data.get("contracts", {}).items():
                name = key.split(":")[-1]
                raw_abi = val.get("abi", "[]")
                abi = raw_abi if isinstance(raw_abi, list) else json.loads(raw_abi)
                bc = val.get("bin", "")
                if bc:
                    result[name] = (abi, bc)
            return result
        except Exception:
            return None
        finally:
            subprocess.run(
                ["wsl", "-d", self.WSL_DISTRO, "--", "rm", "-f", tmp],
                capture_output=True, timeout=5,
            )

    def deploy(self, w3: Web3, abi: List[Dict], bytecode: str,
               deployer: str, args: List[Any] = None) -> Optional[str]:
        try:
            c = w3.eth.contract(abi=abi, bytecode=bytecode)
            tx = c.constructor(*(args or [])).transact({
                "from": deployer, "gasPrice": 0, "gas": 5_000_000,
            })
            w3.provider.make_request("evm_mine", [])
            receipt = w3.eth.get_transaction_receipt(tx)
            return receipt.get("contractAddress")
        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Differential Oracle
# ─────────────────────────────────────────────────────────────────────────────

class DifferentialOracle:
    """
    Deploys the target contract and the OZ reference side-by-side.
    Calls matching functions with identical inputs and compares outputs.
    """

    # Functions to compare: (name_in_target, name_in_reference)
    _ERC4626_COMPARE = [
        ("convertToShares", "convertToShares"),
        ("convertToAssets", "convertToAssets"),
        ("previewDeposit",  "previewDeposit"),
        ("previewMint",     "previewMint"),
        ("previewWithdraw", "previewWithdraw"),
        ("previewRedeem",   "previewRedeem"),
        ("maxDeposit",      "maxDeposit"),
    ]

    _TEST_AMOUNTS = [
        0, 1, 100, 1_000, 1_000_000,
        10**6,     # 1 USDC
        10**18,    # 1 ETH / 1 token
        10**18 - 1,
        10**24,    # large
    ]

    def __init__(self, endpoint: str, deployer: str):
        self.endpoint = endpoint
        self.deployer = Web3.to_checksum_address(deployer)
        self.w3 = Web3(Web3.HTTPProvider(endpoint))
        self._compiler = _Compiler()

    def compare_erc4626(self, target_source: str,
                        target_abi: List[Dict],
                        target_address: str) -> List[DiffFinding]:
        """
        Compare target vault against OZ reference on all view functions.
        Returns list of findings where target deviates from reference.
        """
        findings: List[DiffFinding] = []
        snap = self.w3.provider.make_request("evm_snapshot", [])["result"]
        try:
            # 1. Deploy MockERC20 (shared asset for both vaults)
            mock_compiled = self._compiler.compile(_MOCK_ERC20_SOL)
            if not mock_compiled or "MockERC20" not in mock_compiled:
                return []
            mock_abi, mock_bc = mock_compiled["MockERC20"]
            mock_addr = self._compiler.deploy(
                self.w3, mock_abi, mock_bc, self.deployer)
            if not mock_addr:
                return []
            mock_addr = Web3.to_checksum_address(mock_addr)
            mock_token = self.w3.eth.contract(address=mock_addr, abi=mock_abi)

            # 2. Deploy OZ reference vault (same asset)
            ref_compiled = self._compiler.compile(_OZ_ERC4626_REFERENCE)
            if not ref_compiled or "OZVaultReference" not in ref_compiled:
                return []
            ref_abi, ref_bc = ref_compiled["OZVaultReference"]
            ref_addr = self._compiler.deploy(
                self.w3, ref_abi, ref_bc, self.deployer, [mock_addr])
            if not ref_addr:
                return []
            ref_addr = Web3.to_checksum_address(ref_addr)

            ref_contract = self.w3.eth.contract(
                address=ref_addr, abi=ref_abi,
            )

            target_fn_names = {e["name"] for e in target_abi
                               if e.get("type") == "function"}

            # 3. Re-deploy target vault from source with MockERC20 as asset.
            #    This ensures both vaults share the same asset token so we can
            #    seed them identically.  If re-deploy fails we fall back to an
            #    unseeded comparison (catches formula-structure bugs only).
            target_contract = None
            redeployed = False
            try:
                t_compiled = self._compiler.compile(target_source)
                if t_compiled:
                    target_fn_set = {e.get("name") for e in target_abi
                                     if e.get("type") == "function"}
                    for cname, (c_abi, c_bc) in t_compiled.items():
                        c_fn_set = {e.get("name") for e in c_abi
                                    if e.get("type") == "function"}
                        if target_fn_set.issubset(c_fn_set) and len(c_fn_set) > 2:
                            ctor = next((e for e in c_abi
                                         if e.get("type") == "constructor"), None)
                            ctor_args = []
                            if ctor:
                                for inp in ctor.get("inputs", []):
                                    t = inp.get("type", "")
                                    if t == "address":
                                        ctor_args.append(mock_addr)
                                    elif "uint" in t:
                                        ctor_args.append(0)
                                    elif t == "bool":
                                        ctor_args.append(False)
                                    else:
                                        ctor_args.append(b"")
                            new_addr = self._compiler.deploy(
                                self.w3, c_abi, c_bc, self.deployer, ctor_args)
                            if new_addr:
                                target_contract = self.w3.eth.contract(
                                    address=Web3.to_checksum_address(new_addr),
                                    abi=target_abi,
                                )
                                redeployed = True
                            break
            except Exception:
                pass

            if target_contract is None:
                target_contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(target_address),
                    abi=target_abi,
                )

            # 4. Seed BOTH vaults identically (only when target was re-deployed
            #    with MockERC20 — otherwise skip seeding entirely to avoid
            #    false positives from cold-vs-seeded comparison).
            if redeployed:
                try:
                    seed = 10**18 * 100
                    mock_token.functions.mint(self.deployer, seed * 2).transact(
                        {"from": self.deployer, "gasPrice": 0})
                    mock_token.functions.approve(ref_addr, seed).transact(
                        {"from": self.deployer, "gasPrice": 0})
                    ref_contract.functions.deposit(seed, self.deployer).transact(
                        {"from": self.deployer, "gasPrice": 0})
                    mock_token.functions.approve(
                        target_contract.address, seed).transact(
                        {"from": self.deployer, "gasPrice": 0})
                    target_contract.functions.deposit(seed, self.deployer).transact(
                        {"from": self.deployer, "gasPrice": 0})
                    self.w3.provider.make_request("evm_mine", [])
                except Exception:
                    pass

            # 4. Compare each matching function
            for target_fn, ref_fn in self._ERC4626_COMPARE:
                if target_fn not in target_fn_names:
                    continue
                target_func = getattr(target_contract.functions, target_fn)
                ref_func    = getattr(ref_contract.functions, ref_fn)

                # Determine if function takes an address or uint256
                target_entry = next(
                    (e for e in target_abi
                     if e.get("type") == "function" and e.get("name") == target_fn),
                    None
                )
                if not target_entry:
                    continue
                inputs = target_entry.get("inputs", [])
                if not inputs:
                    continue
                first_type = inputs[0].get("type", "uint256")

                if first_type == "address":
                    test_vals = [self.deployer]
                else:
                    test_vals = self._TEST_AMOUNTS

                for val in test_vals:
                    try:
                        t_out = target_func(val).call()
                        r_out = ref_func(val).call()
                    except Exception:
                        continue

                    if t_out == r_out:
                        continue

                    # Compute deviation
                    if isinstance(t_out, int) and isinstance(r_out, int) and r_out != 0:
                        dev_pct = abs(t_out - r_out) / r_out * 100
                    else:
                        dev_pct = 100.0  # non-numeric mismatch = 100%

                    sev = ("CRITICAL" if dev_pct > 5
                           else "HIGH" if dev_pct > 0.5
                           else "MEDIUM")

                    param_name = inputs[0].get("name", "x")
                    direction = "HIGHER" if (isinstance(t_out, int) and
                                             isinstance(r_out, int) and
                                             t_out > r_out) else "LOWER"
                    findings.append(DiffFinding(
                        function=target_fn,
                        input_args={param_name: val},
                        target_output=t_out,
                        reference_output=r_out,
                        deviation_pct=dev_pct,
                        severity=sev,
                        description=(
                            f"`{target_fn}({val})` returns {t_out} but OZ reference "
                            f"returns {r_out} — {direction} by {dev_pct:.2f}%. "
                            + ("Share inflation: users receive MORE shares than reference → "
                               "future redeemers get less. "
                               if direction == "HIGHER" and "Share" in target_fn
                               else "")
                            + ("Rounding error accumulates per operation. "
                               if dev_pct < 1 else "")
                        ),
                    ))

        finally:
            self.w3.provider.make_request("evm_revert", [snap])

        return findings
