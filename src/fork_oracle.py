"""
Fork oracle — dynamic confirmation of EIP-7702 findings on a mainnet fork.

This is ChainEDR's differentiator: every other Solidity scanner stops at "this
pattern looks risky." ChainEDR can take a static finding and *dynamically
confirm or refute it* against real on-chain state — by forking mainnet, applying
an EIP-7702 delegation exactly as a SET_CODE_TX would, and observing whether a
guarded behaviour actually changes.

Reusable engine:
    with ForkOracle(rpc_url) as fo:
        fo.set_delegation(eoa, impl)          # simulate a live 7702 delegation
        before, after = fo.differential(victim_call)

Requires `anvil` (Foundry) + web3. Returns structured results; raises only on
infrastructure errors so callers can degrade gracefully.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field

try:
    from web3 import Web3
except Exception:  # pragma: no cover
    Web3 = None  # type: ignore


# EIP-7702 delegation indicator: an EOA's code becomes 0xef0100 || implementation
DELEGATION_PREFIX = "ef0100"


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


@dataclass
class DynamicVerdict:
    finding: str
    confirmed: bool
    before: object
    after: object
    detail: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = {
            "finding": self.finding,
            "dynamically_confirmed": self.confirmed,
            "value_before_delegation": self.before,
            "value_after_delegation": self.after,
            "detail": self.detail,
        }
        if self.evidence:
            data["evidence"] = self.evidence
        return data


class ForkOracle:
    """Fork mainnet with anvil and run EIP-7702 delegation experiments."""

    def __init__(self, rpc_url: str | None = None, anvil: str | None = None,
                 fork_block: int | None = None):
        self.rpc_url = rpc_url or os.environ.get("RPC_URL")
        if not self.rpc_url:
            raise ValueError("rpc_url required (or set RPC_URL)")
        self.anvil = anvil or os.path.expanduser("~/.foundry/bin/anvil")
        if not os.path.exists(self.anvil):
            self.anvil = "anvil"
        self.fork_block = fork_block
        self.port = _free_port()
        self.proc: subprocess.Popen | None = None
        self.w3 = None

    def __enter__(self) -> "ForkOracle":
        if Web3 is None:
            raise RuntimeError("web3 not installed")
        cmd = [self.anvil, "--fork-url", self.rpc_url, "--port", str(self.port), "--silent"]
        if self.fork_block:
            cmd += ["--fork-block-number", str(self.fork_block)]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{self.port}"
        for _ in range(150):
            cand = Web3(Web3.HTTPProvider(url))
            if cand.is_connected():
                self.w3 = cand
                return self
            time.sleep(0.1)
        self.__exit__(None, None, None)
        raise RuntimeError("anvil fork did not start in time")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def block(self) -> int:
        return self.w3.eth.block_number

    def deploy(self, abi: list, bytecode: str, *args):
        sender = self.w3.eth.accounts[0]
        c = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        tx = c.constructor(*args).transact({"from": sender})
        rcpt = self.w3.eth.wait_for_transaction_receipt(tx)
        return self.w3.eth.contract(address=rcpt.contractAddress, abi=abi)

    def set_delegation(self, eoa: str, implementation: str) -> None:
        """Apply an EIP-7702 delegation to `eoa` pointing at `implementation`,
        exactly as a SET_CODE_TX would (code := 0xef0100 || impl)."""
        eoa = Web3.to_checksum_address(eoa)
        impl = implementation.lower().replace("0x", "")
        code = "0x" + DELEGATION_PREFIX + impl
        self.w3.provider.make_request("anvil_setCode", [eoa, code])

    def clear_delegation(self, eoa: str) -> None:
        self.w3.provider.make_request("anvil_setCode",
                                      [Web3.to_checksum_address(eoa), "0x"])

    def is_delegated(self, addr: str) -> bool:
        code = self.w3.eth.get_code(Web3.to_checksum_address(addr)).hex()
        return code.lower().lstrip("0x").startswith(DELEGATION_PREFIX)

    def confirm_eoa_gate(self, gate_call, eoa: str, implementation: str,
                         finding: str = "AA7702-002") -> DynamicVerdict:
        """Differential: evaluate an `isEOA`-style call on a fresh EOA, apply a
        7702 delegation, and re-evaluate. If the result flips True->False the
        EOA gate is dynamically confirmed bypassable.

        gate_call: callable(address) -> bool, using this oracle's w3.
        """
        checksum_eoa = Web3.to_checksum_address(eoa)
        before_code = self.w3.eth.get_code(checksum_eoa).hex()
        before = gate_call(eoa)
        self.set_delegation(eoa, implementation)
        after_code = self.w3.eth.get_code(checksum_eoa).hex()
        after = gate_call(eoa)
        confirmed = (before is True and after is False)
        detail = ("EOA gate returns True pre-delegation and False after a 7702 "
                  "delegation -> a delegated account bypasses the EOA-only check"
                  if confirmed else "no behavioural change observed")
        evidence = {
            "probe": "code_presence_behavior_flip",
            "eoa": checksum_eoa,
            "implementation": Web3.to_checksum_address(implementation),
            "code_before": before_code,
            "code_after": after_code,
            "delegation_prefix": DELEGATION_PREFIX,
            "is_delegated_after": after_code.lower().lstrip("0x").startswith(DELEGATION_PREFIX),
            "behavior_flip": f"{before}->{after}",
        }
        return DynamicVerdict(finding, confirmed, before, after, detail, evidence)
