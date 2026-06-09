"""
Bytecode reach oracle for unverified EIP-7702 delegators.

Source scanners cannot analyze the highest-volume 7702 delegates when the
contracts are unverified. This module gives ChainEDR a first bytecode-native
layer:

* fetch runtime bytecode from RPC,
* extract dispatcher PUSH4 selectors and embedded PUSH20 constants,
* fingerprint suspicious drainer/delegate behavior,
* parse call traces from a fork/local EVM probe.

It is deliberately conservative. A bytecode profile is a prioritization signal,
not a bounty-grade proof. Dynamic trace evidence is required before escalating.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    from web3 import Web3
except Exception:  # pragma: no cover
    Web3 = None  # type: ignore

try:
    from eth_utils import keccak as _eth_keccak
except Exception:  # pragma: no cover
    _eth_keccak = None  # type: ignore


CALL = 0xF1
CALLVALUE = 0x34
CALLER = 0x33
BALANCE = 0x31
SELFBALANCE = 0x47
DELEGATECALL = 0xF4
SELFDESTRUCT = 0xFF
DELEGATION_PREFIX = "ef0100"


# selector -> (human-readable signature, behavior tag).
# INVARIANT: every key MUST equal keccak(signature)[:4]. Enforced by
# tests/test_bytecode_oracle.py::test_known_selectors_hash_correctly so a
# mislabeled entry can never ship (a wrong selector->sig mapping fabricates a
# signal and, for a 4-byte constant, becomes a false positive on benign code).
#
# NOTE: there are intentionally NO "known_drainer" entries. The previous
# e9cb1f0d/4d3e1916 entries were mislabeled (their signatures hash to 0c89a0df /
# bca8c7b5) and unverifiable, so they were removed. Add drainer selectors only
# with a verified signature AND a cited source.
KNOWN_SELECTORS: dict[str, tuple[str, str]] = {
    "70a08231": ("balanceOf(address)", "erc20_balance_read"),
    "a9059cbb": ("transfer(address,uint256)", "erc20_transfer"),
    "23b872dd": ("transferFrom(address,address,uint256)", "erc20_transfer_from"),
    "095ea7b3": ("approve(address,uint256)", "erc20_approve"),
    "dd62ed3e": ("allowance(address,address)", "erc20_allowance_read"),
    "b88d4fde": ("safeTransferFrom(address,address,uint256,bytes)", "erc721_transfer"),
    "42842e0e": ("safeTransferFrom(address,address,uint256)", "erc721_transfer"),
    "6352211e": ("ownerOf(uint256)", "erc721_owner_read"),
    "081812fc": ("getApproved(uint256)", "erc721_approval_read"),
    "e985e9c5": ("isApprovedForAll(address,address)", "operator_approval_read"),
    "a22cb465": ("setApprovalForAll(address,bool)", "operator_approval"),
    "00fdd58e": ("balanceOf(address,uint256)", "erc1155_balance_read"),
    "f242432a": ("safeTransferFrom(address,address,uint256,uint256,bytes)", "erc1155_transfer"),
    "1626ba7e": ("isValidSignature(bytes32,bytes)", "erc1271_signature_check"),
    "20c13b0b": ("isValidSignature(bytes,bytes)", "erc1271_signature_check"),
    "3644e515": ("DOMAIN_SEPARATOR()", "domain_separator_read"),
    "7ecebe00": ("nonces(address)", "nonce_read"),
    "35567e1a": ("getNonce(address,uint192)", "nonce_read"),
    "3a871cdd": (
        "validateUserOp((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes),bytes32,uint256)",
        "userop_validation",
    ),
    "50ef260e": (
        "validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes32,bytes),bytes32,uint256)",
        "userop_validation",
    ),
    "2e1a7d4d": ("withdraw(uint256)", "wrapped_native_withdraw"),
    "c4d66de8": ("initialize(address)", "initializer"),
    "b61d27f6": ("execute(address,uint256,bytes)", "account_execute"),
    "51945447": ("execute(address,uint256,bytes,uint8)", "account_execute"),
    "47e1da2a": ("executeBatch(address[],uint256[],bytes[])", "account_execute_batch"),
    "34fcd5be": ("executeBatch((address,uint256,bytes)[])", "account_execute_batch"),
    "9517e29f": ("installModule(uint256,address,bytes)", "module_install"),
    "755563ad": ("setValidator(address,bytes)", "validator_setter"),
    "1327d3d8": ("setValidator(address)", "validator_setter"),
    "13af4035": ("setOwner(address)", "owner_setter"),
    "6c19e783": ("setSigner(address)", "signer_setter"),
    "0a0a05e6": ("setDestination(address)", "destination_setter"),
    "d784d426": ("setImplementation(address)", "implementation_setter"),
    "3659cfe6": ("upgradeTo(address)", "implementation_setter"),
    "f3fef3a3": ("withdraw(address,uint256)", "asset_withdraw"),
    "01681a62": ("sweep(address)", "asset_sweep"),
    "8da5cb5b": ("owner()", "owner_read"),
    "b0d691fe": ("entryPoint()", "entrypoint_read"),
    "392e53cd": ("isInitialized()", "initializer_read"),
}


EXECUTE_SELECTORS = frozenset({"b61d27f6", "51945447", "47e1da2a", "34fcd5be"})
ERC20_BALANCE_OF_SELECTOR = "70a08231"
ERC20_TRANSFER_SELECTOR = "a9059cbb"
ERC20_APPROVE_SELECTOR = "095ea7b3"
ERC20_ALLOWANCE_SELECTOR = "dd62ed3e"
ERC20_TRANSFER_FROM_SELECTOR = "23b872dd"
ERC721_OWNER_OF_SELECTOR = "6352211e"
ERC721_TRANSFER_FROM_SELECTOR = "23b872dd"
ERC721_SAFE_TRANSFER_FROM_SELECTOR = "42842e0e"
ERC721_SET_APPROVAL_FOR_ALL_SELECTOR = "a22cb465"
ERC1155_BALANCE_OF_SELECTOR = "00fdd58e"
ERC1155_SAFE_TRANSFER_FROM_SELECTOR = "f242432a"
INSTALL_MODULE_SELECTOR = "9517e29f"
SET_VALIDATOR_BYTES_SELECTOR = "755563ad"


def _load_env_rpc() -> str:
    if os.environ.get("RPC_URL"):
        return os.environ["RPC_URL"]
    for path in (Path(".env"), Path("../.env"), Path("../../.env")):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("RPC_URL="):
                return line.split("=", 1)[1].strip()
    return ""


def normalize_bytecode(bytecode: str | bytes) -> bytes:
    if isinstance(bytecode, bytes):
        return bytecode
    raw = bytecode.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return b""
    return bytes.fromhex(raw)


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _pad_word(hex_value: str) -> str:
    raw = _strip_0x(hex_value).lower()
    if len(raw) > 64:
        raise ValueError("ABI word too large")
    return raw.rjust(64, "0")


def _encode_uint(value: int) -> str:
    if value < 0:
        raise ValueError("uint cannot be negative")
    return hex(value)[2:].rjust(64, "0")


def _encode_bool(value: bool) -> str:
    return _encode_uint(1 if value else 0)


def _encode_address(address: str) -> str:
    raw = _strip_0x(address).lower()
    if len(raw) != 40:
        raise ValueError("address must be 20 bytes")
    return raw.rjust(64, "0")


def _encode_bytes(data: str | bytes) -> str:
    if isinstance(data, bytes):
        raw = data.hex()
    else:
        raw = _strip_0x(data).lower()
    pad = (64 - (len(raw) % 64)) % 64
    return _encode_uint(len(raw) // 2) + raw + ("0" * pad)


def _encode_address_array(addresses: list[str]) -> str:
    return _encode_uint(len(addresses)) + "".join(_encode_address(a) for a in addresses)


def _encode_uint_array(values: list[int]) -> str:
    return _encode_uint(len(values)) + "".join(_encode_uint(v) for v in values)


def _keccak(data: bytes) -> bytes:
    if Web3 is not None:
        return bytes(Web3.keccak(data))
    if _eth_keccak is not None:
        return bytes(_eth_keccak(data))
    raise RuntimeError("web3 or eth-utils is required for keccak")


def _encode_bytes_array(items: list[str | bytes]) -> str:
    # Dynamic array of dynamic bytes: length + per-element offsets + element tails.
    # Offsets are relative to the tuple area after the length word.
    offsets: list[int] = []
    tails: list[str] = []
    cursor = 32 * len(items)
    for item in items:
        tail = _encode_bytes(item)
        offsets.append(cursor)
        tails.append(tail)
        cursor += len(tail) // 2
    return (
        _encode_uint(len(items))
        + "".join(_encode_uint(o) for o in offsets)
        + "".join(tails)
    )


def _selector_word(selector: str) -> str:
    raw = _strip_0x(selector).lower()
    if len(raw) != 8:
        raise ValueError("selector must be 4 bytes")
    return raw


def iter_opcodes(bytecode: str | bytes) -> Iterable[tuple[int, int, bytes]]:
    """Yield (pc, opcode, immediate). PUSH immediates are skipped as code."""
    code = normalize_bytecode(bytecode)
    pc = 0
    while pc < len(code):
        op = code[pc]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            imm = code[pc + 1:pc + 1 + n]
            yield pc, op, imm
            pc += 1 + n
        else:
            yield pc, op, b""
            pc += 1


EQ = 0x14


def extract_push4_selectors(bytecode: str | bytes, dispatcher_only: bool = False) -> list[str]:
    """Extract PUSH4 4-byte constants.

    dispatcher_only=True keeps only PUSH4 immediately followed by EQ — the solc
    function-dispatcher pattern (`DUP1 PUSH4 <sel> EQ ... JUMPI`). This avoids
    treating arbitrary 4-byte numeric constants as function selectors (which can
    false-match a known selector). Default False preserves raw extraction.
    """
    ops = list(iter_opcodes(bytecode))
    selectors: list[str] = []
    seen: set[str] = set()
    for idx, (_, op, imm) in enumerate(ops):
        if op != 0x63 or len(imm) != 4:
            continue
        if dispatcher_only:
            nxt = ops[idx + 1][1] if idx + 1 < len(ops) else None
            if nxt != EQ:
                continue
        sel = imm.hex()
        if sel not in seen:
            seen.add(sel)
            selectors.append(sel)
    return selectors


def extract_push20_addresses(bytecode: str | bytes) -> list[str]:
    addresses: list[str] = []
    seen: set[str] = set()
    if Web3 is None:
        checksum = lambda x: "0x" + _strip_0x(x).lower()  # noqa: E731
    else:
        checksum = Web3.to_checksum_address
    for _, op, imm in iter_opcodes(bytecode):
        if op == 0x73 and len(imm) == 20:
            raw = imm.hex()
            # Skip non-addresses: zero, the 0xff..ff address bitmask (PUSH20
            # used for `AND` masking, not a real address), and any all-same-byte
            # constant — these are arithmetic constants, not embedded addresses.
            if int(raw, 16) == 0 or raw in seen:
                continue
            if len(set(imm)) == 1:  # all bytes equal (0xff..ff mask, 0x00.., etc.)
                continue
            seen.add(raw)
            addresses.append(checksum("0x" + raw))
    return addresses


@dataclass
class GuardSurface:
    selectors: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    likely_guarded: bool = False
    guard_strength: str = "none"
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "selectors": self.selectors,
            "hints": self.hints,
            "likely_guarded": self.likely_guarded,
            "guard_strength": self.guard_strength,
            "confidence": self.confidence,
        }


def classify_guard_surface(bytecode_or_selectors: str | bytes | Iterable[str]) -> GuardSurface:
    """Classify guard-like bytecode surfaces without claiming exploitability.

    This is a reachability triage aid for unverified delegators. Selectors and
    CALLER usage can tell us that authorization machinery probably exists, but
    they cannot prove that a path is safe. Dynamic probes still decide impact.
    """
    code = b""
    if isinstance(bytecode_or_selectors, (str, bytes)):
        code = normalize_bytecode(bytecode_or_selectors)
        selectors = extract_push4_selectors(code, dispatcher_only=True)
        if not selectors:
            selectors = extract_push4_selectors(code)
    else:
        selectors = []
        seen: set[str] = set()
        for raw in bytecode_or_selectors:
            sel = _strip_0x(str(raw)).lower()
            if len(sel) == 8 and sel not in seen:
                seen.add(sel)
                selectors.append(sel)

    tags = {
        KNOWN_SELECTORS[sel][1]
        for sel in selectors
        if sel in KNOWN_SELECTORS
    }
    has_caller = any(op == CALLER for _, op, _ in iter_opcodes(code)) if code else False

    hints: list[str] = []
    if any(tag in tags for tag in {"owner_read", "owner_setter", "signer_setter"}):
        hints.append("owner_or_signer_surface")
    if "entrypoint_read" in tags or "userop_validation" in tags:
        hints.append("entrypoint_or_userop_surface")
    if "erc1271_signature_check" in tags:
        hints.append("erc1271_signature_surface")
    if "domain_separator_read" in tags:
        hints.append("domain_separator_surface")
    if "nonce_read" in tags:
        hints.append("nonce_surface")
    if any(tag in tags for tag in {"initializer", "initializer_read"}):
        hints.append("initializer_surface")
    if any(tag in tags for tag in {"module_install", "validator_setter"}):
        hints.append("module_or_validator_mutation_surface")
    if has_caller:
        hints.append("caller_dependent")

    auth_hint_count = sum(
        hint in hints
        for hint in (
            "owner_or_signer_surface",
            "entrypoint_or_userop_surface",
            "erc1271_signature_surface",
            "domain_separator_surface",
            "nonce_surface",
            "caller_dependent",
        )
    )
    if (
        "caller_dependent" in hints
        and ("owner_or_signer_surface" in hints or "entrypoint_or_userop_surface" in hints)
    ) or auth_hint_count >= 4:
        strength = "strong"
        confidence = 0.75
    elif auth_hint_count >= 2:
        strength = "medium"
        confidence = 0.55
    elif auth_hint_count == 1:
        strength = "weak"
        confidence = 0.30
    else:
        strength = "none"
        confidence = 0.0

    return GuardSurface(
        selectors=selectors,
        hints=hints,
        likely_guarded=strength in {"medium", "strong"},
        guard_strength=strength,
        confidence=confidence,
    )


@dataclass
class BytecodeProfile:
    address: str
    code_size: int
    selectors: list[str] = field(default_factory=list)
    known_selectors: dict[str, str] = field(default_factory=dict)
    embedded_addresses: list[str] = field(default_factory=list)
    opcode_counts: dict[str, int] = field(default_factory=dict)
    risk_flags: list[str] = field(default_factory=list)
    guard_surface: dict = field(default_factory=dict)
    proof_surfaces: list[str] = field(default_factory=list)
    triage_score: int = 0
    triage_reasons: list[str] = field(default_factory=list)
    recommended_probes: list[str] = field(default_factory=list)
    risk_score: int = 0

    @property
    def severity(self) -> str:
        if self.risk_score >= 6:
            return "CRITICAL"
        if self.risk_score >= 4:
            return "HIGH"
        if self.risk_score >= 2:
            return "MEDIUM"
        if self.risk_score >= 1:
            return "LOW"
        return "INFO"

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "code_size": self.code_size,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "risk_flags": self.risk_flags,
            "selectors": self.selectors,
            "known_selectors": self.known_selectors,
            "embedded_addresses": self.embedded_addresses,
            "opcode_counts": self.opcode_counts,
            "guard_surface": self.guard_surface,
            "proof_surfaces": self.proof_surfaces,
            "triage_score": self.triage_score,
            "triage_reasons": self.triage_reasons,
            "recommended_probes": self.recommended_probes,
        }


def plan_bytecode_probes(
    selectors: list[str],
    known_selectors: dict[str, str],
    opcode_counts: dict[str, int],
    risk_flags: list[str],
    guard_surface: dict,
    embedded_addresses: list[str],
    risk_score: int,
) -> tuple[int, list[str], list[str], list[str]]:
    """Rank bytecode profiles by proofability, not just static suspicion.

    This planner is intentionally conservative: it recommends fork probes and
    explains priority, but it never turns a profile into a vulnerability claim.
    """
    tags = {
        KNOWN_SELECTORS[sel][1]
        for sel in selectors
        if sel in KNOWN_SELECTORS
    }
    exposed = set(selectors)
    guard_strength = str(guard_surface.get("guard_strength", "none"))
    likely_guarded = bool(guard_surface.get("likely_guarded"))
    triage_score = risk_score
    reasons: list[str] = []
    surfaces: list[str] = []
    probes: list[str] = []

    def add(reason: str, points: int, surface: str = "", probe: str = "") -> None:
        nonlocal triage_score
        triage_score += points
        if reason and reason not in reasons:
            reasons.append(reason)
        if surface and surface not in surfaces:
            surfaces.append(surface)
        if probe and probe not in probes:
            probes.append(probe)

    if "payable_value_path" in risk_flags and opcode_counts.get("CALL", 0):
        if guard_strength == "none":
            add(
                "payable external-call path with no detected guard surface",
                4,
                "unguarded_receive_value",
                "receive_value_delegation",
            )
        elif guard_strength == "weak":
            add(
                "payable external-call path with only weak guard hints",
                3,
                "weakly_guarded_receive_value",
                "receive_value_delegation",
            )
        else:
            add(
                "payable external-call path; guarded profile needs negative control",
                1,
                "guarded_receive_value",
                "receive_value_delegation_negative_control",
            )

    if "selfdestruct" in risk_flags:
        add(
            "SELFDESTRUCT reachable in runtime bytecode",
            4,
            "selfdestruct_surface",
            "selfdestruct_or_forced_value_probe",
        )

    if "delegatecall" in risk_flags:
        add(
            "DELEGATECALL reachable in delegated-account runtime",
            3,
            "delegatecall_storage_context",
            "delegatecall_storage_diff",
        )

    if exposed & EXECUTE_SELECTORS:
        add(
            "execute-style selector exposed on delegated account",
            3 if not likely_guarded else 1,
            "execute_asset_sweep_surface",
            "erc20_execute_sweep",
        )
        if not likely_guarded:
            add(
                "execute-style selector has weak/missing guard evidence",
                2,
                "execute_asset_sweep_surface",
                "erc721_execute_sweep",
            )

    mutator_tags = {
        "initializer",
        "owner_setter",
        "signer_setter",
        "implementation_setter",
        "module_install",
        "validator_setter",
        "operator_approval",
    }
    if tags & mutator_tags:
        add(
            "state-mutating account control selector exposed",
            3 if not likely_guarded else 1,
            "state_mutation_selector",
            "state_write_diff",
        )

    if {"erc20_transfer", "erc20_transfer_from", "erc20_approve"} & tags:
        add(
            "token movement or approval selector present",
            2,
            "token_movement_surface",
            "erc20_balance_or_allowance_diff",
        )

    if "erc1271_signature_check" in tags:
        add(
            "ERC-1271 signature validation surface present",
            1,
            "erc1271_signature_surface",
            "erc1271_magic_value_negative_control",
        )

    if "domain_separator_read" in tags or "nonce_read" in tags:
        add(
            "signature domain or nonce surface present",
            1,
            "signature_domain_surface",
            "domain_replay_negative_control",
        )

    if "userop_validation" in tags or "entrypoint_read" in tags:
        add(
            "ERC-4337/UserOp validation surface present",
            1,
            "userop_validation_surface",
            "userop_validation_negative_control",
        )

    if embedded_addresses:
        add(
            "embedded address constants present",
            1,
            "fixed_recipient_or_entrypoint_constant",
            "embedded_address_review",
        )

    if not probes and risk_score > 0:
        add(
            "static bytecode risk without a specific proof adapter yet",
            0,
            "manual_bytecode_review",
            "manual_trace_review",
        )

    return triage_score, reasons, surfaces, probes


def profile_bytecode(bytecode: str | bytes, address: str = "") -> BytecodeProfile:
    code = normalize_bytecode(bytecode)
    # Prefer dispatcher selectors (PUSH4+EQ); fall back to raw PUSH4 only if the
    # dispatcher pattern isn't present (unusual dispatch / hand-written stubs).
    selectors = extract_push4_selectors(code, dispatcher_only=True)
    if not selectors:
        selectors = extract_push4_selectors(code)
    embedded_addresses = extract_push20_addresses(code)
    opcode_counts_raw: dict[int, int] = {}
    for _, op, _ in iter_opcodes(code):
        opcode_counts_raw[op] = opcode_counts_raw.get(op, 0) + 1

    known = {
        sel: KNOWN_SELECTORS[sel][0]
        for sel in selectors
        if sel in KNOWN_SELECTORS
    }

    flags: list[str] = []
    score = 0

    if opcode_counts_raw.get(CALL, 0):
        flags.append("external_call")
        score += 1
    if opcode_counts_raw.get(CALLVALUE, 0):
        flags.append("payable_value_path")
        score += 1
    if opcode_counts_raw.get(SELFBALANCE, 0) or opcode_counts_raw.get(BALANCE, 0):
        flags.append("balance_dependent")
        score += 1
    if opcode_counts_raw.get(DELEGATECALL, 0):
        flags.append("delegatecall")
        score += 2
    if opcode_counts_raw.get(SELFDESTRUCT, 0):
        flags.append("selfdestruct")
        score += 2
    if "a9059cbb" in selectors and "70a08231" in selectors:
        flags.append("erc20_balance_sweep_surface")
        score += 3
    if "23b872dd" in selectors or "095ea7b3" in selectors:
        flags.append("token_allowance_surface")
        score += 1
    if any(KNOWN_SELECTORS[s][1].startswith("known_drainer") for s in selectors if s in KNOWN_SELECTORS):
        flags.append("known_drainer_selector")
        score += 4
    if embedded_addresses:
        flags.append("embedded_address_constants")
        score += 1

    guard_surface = classify_guard_surface(code)

    opcode_counts = {
        "CALL": opcode_counts_raw.get(CALL, 0),
        "CALLVALUE": opcode_counts_raw.get(CALLVALUE, 0),
        "BALANCE": opcode_counts_raw.get(BALANCE, 0),
        "SELFBALANCE": opcode_counts_raw.get(SELFBALANCE, 0),
        "DELEGATECALL": opcode_counts_raw.get(DELEGATECALL, 0),
        "SELFDESTRUCT": opcode_counts_raw.get(SELFDESTRUCT, 0),
    }
    triage_score, triage_reasons, proof_surfaces, recommended_probes = plan_bytecode_probes(
        selectors,
        known,
        opcode_counts,
        flags,
        guard_surface.to_dict(),
        embedded_addresses,
        score,
    )

    return BytecodeProfile(
        address=address,
        code_size=len(code),
        selectors=selectors,
        known_selectors=known,
        embedded_addresses=embedded_addresses,
        opcode_counts=opcode_counts,
        risk_flags=flags,
        guard_surface=guard_surface.to_dict(),
        proof_surfaces=proof_surfaces,
        triage_score=triage_score,
        triage_reasons=triage_reasons,
        recommended_probes=recommended_probes,
        risk_score=score,
    )


def fetch_runtime_bytecode(address: str, rpc_url: str | None = None) -> str:
    if Web3 is None:
        raise RuntimeError("web3 is required for bytecode fetching")
    rpc = rpc_url or _load_env_rpc()
    if not rpc:
        raise ValueError("RPC URL required. Set RPC_URL or pass rpc_url.")
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        raise RuntimeError("RPC connection failed")
    return w3.eth.get_code(Web3.to_checksum_address(address)).hex()


def profile_address(address: str, rpc_url: str | None = None) -> BytecodeProfile:
    return profile_bytecode(fetch_runtime_bytecode(address, rpc_url), address)


@dataclass(frozen=True)
class CalldataCandidate:
    selector: str
    signature: str
    calldata: str
    objective: str
    inner_call: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "selector": self.selector,
            "signature": self.signature,
            "calldata": self.calldata,
            "objective": self.objective,
            "inner_call": self.inner_call,
            "note": self.note,
        }


def erc20_transfer_calldata(recipient: str, amount: int) -> str:
    """Build `transfer(address,uint256)` calldata."""
    return "0x" + ERC20_TRANSFER_SELECTOR + _encode_address(recipient) + _encode_uint(amount)


def erc20_approve_calldata(spender: str, amount: int) -> str:
    """Build `approve(address,uint256)` calldata."""
    return "0x" + ERC20_APPROVE_SELECTOR + _encode_address(spender) + _encode_uint(amount)


def erc20_balance_of_calldata(account: str) -> str:
    return "0x" + ERC20_BALANCE_OF_SELECTOR + _encode_address(account)


def erc20_allowance_calldata(owner: str, spender: str) -> str:
    return "0x" + ERC20_ALLOWANCE_SELECTOR + _encode_address(owner) + _encode_address(spender)


def erc20_transfer_from_calldata(owner: str, recipient: str, amount: int) -> str:
    return (
        "0x"
        + ERC20_TRANSFER_FROM_SELECTOR
        + _encode_address(owner)
        + _encode_address(recipient)
        + _encode_uint(amount)
    )


def erc721_owner_of_calldata(token_id: int) -> str:
    return "0x" + ERC721_OWNER_OF_SELECTOR + _encode_uint(token_id)


def erc721_transfer_from_calldata(owner: str, recipient: str, token_id: int) -> str:
    return (
        "0x"
        + ERC721_TRANSFER_FROM_SELECTOR
        + _encode_address(owner)
        + _encode_address(recipient)
        + _encode_uint(token_id)
    )


def erc721_safe_transfer_from_calldata(owner: str, recipient: str, token_id: int) -> str:
    return (
        "0x"
        + ERC721_SAFE_TRANSFER_FROM_SELECTOR
        + _encode_address(owner)
        + _encode_address(recipient)
        + _encode_uint(token_id)
    )


def erc721_set_approval_for_all_calldata(operator: str, approved: bool = True) -> str:
    return "0x" + ERC721_SET_APPROVAL_FOR_ALL_SELECTOR + _encode_address(operator) + _encode_bool(approved)


def erc1155_balance_of_calldata(account: str, token_id: int) -> str:
    return "0x" + ERC1155_BALANCE_OF_SELECTOR + _encode_address(account) + _encode_uint(token_id)


def erc1155_safe_transfer_from_calldata(owner: str, recipient: str, token_id: int,
                                        amount: int, data: str | bytes = b"") -> str:
    head = (
        _encode_address(owner)
        + _encode_address(recipient)
        + _encode_uint(token_id)
        + _encode_uint(amount)
        + _encode_uint(160)
    )
    return "0x" + ERC1155_SAFE_TRANSFER_FROM_SELECTOR + head + _encode_bytes(data)


def install_module_calldata(module_type: int, module: str, init_data: str | bytes = b"") -> str:
    return (
        "0x"
        + INSTALL_MODULE_SELECTOR
        + _encode_uint(module_type)
        + _encode_address(module)
        + _encode_uint(96)
        + _encode_bytes(init_data)
    )


def set_validator_calldata(validator: str, init_data: str | bytes = b"") -> str:
    return (
        "0x"
        + SET_VALIDATOR_BYTES_SELECTOR
        + _encode_address(validator)
        + _encode_uint(64)
        + _encode_bytes(init_data)
    )


def execute_calldata(selector: str, target: str, value_wei: int,
                     inner_call: str | bytes) -> str:
    """Build calldata for common account `execute` shapes.

    Supported selectors:
      - execute(address,uint256,bytes)
      - execute(address,uint256,bytes,uint8)
      - executeBatch(address[],uint256[],bytes[]) with one call
      - executeBatch((address,uint256,bytes)[]) with one call
    """
    sel = _selector_word(selector)
    inner = "0x" + normalize_bytecode(inner_call).hex()

    if sel == "b61d27f6":
        head = _encode_address(target) + _encode_uint(value_wei) + _encode_uint(96)
        return "0x" + sel + head + _encode_bytes(inner)

    if sel == "51945447":
        # Last uint8/operation arg is 0 = CALL in the common execute mode enum.
        head = (
            _encode_address(target)
            + _encode_uint(value_wei)
            + _encode_uint(128)
            + _encode_uint(0)
        )
        return "0x" + sel + head + _encode_bytes(inner)

    if sel == "47e1da2a":
        targets = _encode_address_array([target])
        values = _encode_uint_array([value_wei])
        calls = _encode_bytes_array([inner])
        off_targets = 96
        off_values = off_targets + len(targets) // 2
        off_calls = off_values + len(values) // 2
        head = _encode_uint(off_targets) + _encode_uint(off_values) + _encode_uint(off_calls)
        return "0x" + sel + head + targets + values + calls

    if sel == "34fcd5be":
        # ABI for `tuple(address,uint256,bytes)[]`: outer offset, length,
        # per-element offset, then the single tuple body and bytes tail.
        tuple_body = _encode_address(target) + _encode_uint(value_wei) + _encode_uint(96)
        return (
            "0x"
            + sel
            + _encode_uint(32)
            + _encode_uint(1)
            + _encode_uint(32)
            + tuple_body
            + _encode_bytes(inner)
        )

    raise ValueError(f"unsupported execute selector: {selector}")


def build_erc20_sweep_execute_candidates(selectors: list[str], token: str,
                                         recipient: str, amount: int) -> list[CalldataCandidate]:
    """Generate execute-class calldata that attempts to move victim-held ERC20s.

    This is V2's first calldata-fuzzing primitive: for each supported execute
    selector exposed by the implementation, call `token.transfer(recipient, amount)`
    through the delegated victim account. Dynamic balance diff decides whether it
    is a bug; this builder is only a candidate generator.
    """
    exposed = {_selector_word(s) for s in selectors}
    inner = erc20_transfer_calldata(recipient, amount)
    out: list[CalldataCandidate] = []
    for sel in sorted(exposed & EXECUTE_SELECTORS):
        sig = KNOWN_SELECTORS.get(sel, ("unknown", ""))[0]
        out.append(CalldataCandidate(
            selector=sel,
            signature=sig,
            calldata=execute_calldata(sel, token, 0, inner),
            objective="erc20_sweep_via_execute",
            inner_call=inner,
            note="attacker calls delegated EOA; delegated EOA calls token.transfer",
        ))
    return out


def build_erc20_approval_execute_candidates(selectors: list[str], token: str,
                                            spender: str, amount: int) -> list[CalldataCandidate]:
    exposed = {_selector_word(s) for s in selectors}
    inner = erc20_approve_calldata(spender, amount)
    out: list[CalldataCandidate] = []
    for sel in sorted(exposed & EXECUTE_SELECTORS):
        sig = KNOWN_SELECTORS.get(sel, ("unknown", ""))[0]
        out.append(CalldataCandidate(
            selector=sel,
            signature=sig,
            calldata=execute_calldata(sel, token, 0, inner),
            objective="erc20_approval_via_execute",
            inner_call=inner,
            note="attacker calls delegated EOA; delegated EOA approves attacker/spender",
        ))
    return out


def build_erc721_sweep_execute_candidates(selectors: list[str], nft: str, owner: str,
                                          recipient: str, token_id: int) -> list[CalldataCandidate]:
    exposed = {_selector_word(s) for s in selectors}
    inner_calls = [
        ("erc721_sweep_safe_transfer_via_execute",
         erc721_safe_transfer_from_calldata(owner, recipient, token_id)),
        ("erc721_sweep_transfer_from_via_execute",
         erc721_transfer_from_calldata(owner, recipient, token_id)),
    ]
    out: list[CalldataCandidate] = []
    for sel in sorted(exposed & EXECUTE_SELECTORS):
        sig = KNOWN_SELECTORS.get(sel, ("unknown", ""))[0]
        for objective, inner in inner_calls:
            out.append(CalldataCandidate(
                selector=sel,
                signature=sig,
                calldata=execute_calldata(sel, nft, 0, inner),
                objective=objective,
                inner_call=inner,
                note="attacker calls delegated EOA; delegated EOA transfers ERC721",
            ))
    return out


def build_erc1155_sweep_execute_candidates(selectors: list[str], token: str, owner: str,
                                           recipient: str, token_id: int,
                                           amount: int) -> list[CalldataCandidate]:
    exposed = {_selector_word(s) for s in selectors}
    inner = erc1155_safe_transfer_from_calldata(owner, recipient, token_id, amount)
    out: list[CalldataCandidate] = []
    for sel in sorted(exposed & EXECUTE_SELECTORS):
        sig = KNOWN_SELECTORS.get(sel, ("unknown", ""))[0]
        out.append(CalldataCandidate(
            selector=sel,
            signature=sig,
            calldata=execute_calldata(sel, token, 0, inner),
            objective="erc1155_sweep_via_execute",
            inner_call=inner,
            note="attacker calls delegated EOA; delegated EOA transfers ERC1155",
        ))
    return out


def build_control_calldata_candidates(selectors: list[str], controller: str,
                                      init_data: str | bytes = b"",
                                      module_type: int = 1) -> list[CalldataCandidate]:
    """Generate direct module/validator install-style calls.

    These are not asset-theft proofs by themselves. The dynamic probe must show
    an attacker-caused storage change before evidence can claim anything.
    """
    exposed = {_selector_word(s) for s in selectors}
    out: list[CalldataCandidate] = []
    if INSTALL_MODULE_SELECTOR in exposed:
        out.append(CalldataCandidate(
            selector=INSTALL_MODULE_SELECTOR,
            signature=KNOWN_SELECTORS[INSTALL_MODULE_SELECTOR][0],
            calldata=install_module_calldata(module_type, controller, init_data),
            objective="module_install_state_change",
            inner_call=_strip_0x(init_data),
            note="attacker calls delegated EOA to install a module-like controller",
        ))
    if SET_VALIDATOR_BYTES_SELECTOR in exposed:
        out.append(CalldataCandidate(
            selector=SET_VALIDATOR_BYTES_SELECTOR,
            signature=KNOWN_SELECTORS[SET_VALIDATOR_BYTES_SELECTOR][0],
            calldata=set_validator_calldata(controller, init_data),
            objective="validator_set_state_change",
            inner_call=_strip_0x(init_data) if isinstance(init_data, str) else init_data.hex(),
            note="attacker calls delegated EOA to set a validator-like controller",
        ))
    return out


@dataclass
class ValueFlow:
    sender: str
    recipient: str
    value_wei: int
    call_type: str

    def to_dict(self) -> dict:
        return {
            "from": self.sender,
            "to": self.recipient,
            "value_wei": self.value_wei,
            "call_type": self.call_type,
        }


# Frame types that actually MOVE ETH. DELEGATECALL/STATICCALL/CALLCODE carry a
# `value` field in callTracer output but transfer no funds (the callee runs in the
# caller's context / is read-only), so counting them as value flows is a false
# positive — e.g. an ERC-1967 proxy delegatecalling its implementation looked like
# a "value sweep" on Coinbase's EIP7702Proxy until this was fixed.
_VALUE_MOVING_CALLS = {"CALL", "CREATE", "CREATE2", "SELFDESTRUCT"}


def extract_value_flows_from_call_trace(trace: dict) -> list[ValueFlow]:
    """Parse a callTracer-style result into nonzero ETH value flows (real transfers
    only — delegatecall/staticcall frames are skipped)."""
    flows: list[ValueFlow] = []

    def walk(node: dict) -> None:
        raw_value = node.get("value", "0x0")
        value = int(raw_value, 16) if isinstance(raw_value, str) else int(raw_value or 0)
        call_type = node.get("type", "CALL")
        if value > 0 and call_type.upper() in _VALUE_MOVING_CALLS:
            flows.append(ValueFlow(
                sender=node.get("from", ""),
                recipient=node.get("to", ""),
                value_wei=value,
                call_type=call_type,
            ))
        for child in node.get("calls", []) or []:
            walk(child)

    if "result" in trace and isinstance(trace["result"], dict):
        trace = trace["result"]
    walk(trace)
    return flows


@dataclass
class RuntimeProbeResult:
    target: str
    victim: str
    probe: str
    tx_status: int
    value_flows: list[ValueFlow] = field(default_factory=list)
    error: str = ""

    @property
    def observed_outbound_value(self) -> bool:
        victim_lower = self.victim.lower()
        return any(
            f.sender.lower() == victim_lower and f.value_wei > 0
            for f in self.value_flows
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "victim": self.victim,
            "probe": self.probe,
            "tx_status": self.tx_status,
            "observed_outbound_value": self.observed_outbound_value,
            "value_flows": [f.to_dict() for f in self.value_flows],
            "error": self.error,
        }


class RuntimeBytecodeProbe:
    """Install runtime bytecode on a local/fork EVM victim and probe behavior."""

    def __init__(self, w3, victim: str = "0x7702000000000000000000000000000000000001"):
        self.w3 = w3
        self.victim = Web3.to_checksum_address(victim) if Web3 is not None else victim

    def install_runtime(self, runtime_bytecode: str | bytes) -> None:
        code = normalize_bytecode(runtime_bytecode).hex()
        self.w3.provider.make_request("anvil_setCode", [self.victim, "0x" + code])

    def probe_receive_value(self, target: str, runtime_bytecode: str | bytes,
                            value_wei: int = 10**18) -> RuntimeProbeResult:
        self.install_runtime(runtime_bytecode)
        sender = self.w3.eth.accounts[0]
        try:
            tx_hash = self.w3.eth.send_transaction({
                "from": sender,
                "to": self.victim,
                "value": value_wei,
                "gas": 2_000_000,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            trace = self.w3.provider.make_request(
                "debug_traceTransaction",
                [tx_hash.hex(), {"tracer": "callTracer"}],
            )
            return RuntimeProbeResult(
                target=target,
                victim=self.victim,
                probe="receive_value",
                tx_status=int(receipt.status),
                value_flows=extract_value_flows_from_call_trace(trace),
            )
        except Exception as exc:
            return RuntimeProbeResult(
                target=target,
                victim=self.victim,
                probe="receive_value",
                tx_status=0,
                error=type(exc).__name__,
            )


@dataclass
class StateWriteVerdict:
    """Result of probing whether a NON-owner can mutate a delegated account's
    storage through a public selector (the unprotected-initializer/setter class,
    e.g. Porwarder.initialize)."""
    target: str
    victim: str
    selector: str
    caller: str
    tx_status: int
    changed_slots: list[int] = field(default_factory=list)
    error: str = ""

    @property
    def confirmed(self) -> bool:
        # Unauthorized state control: a fresh third party (not the account/owner)
        # made a successful call that mutated persistent storage.
        return self.tx_status == 1 and len(self.changed_slots) > 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "victim": self.victim,
            "selector": self.selector,
            "caller": self.caller,
            "tx_status": self.tx_status,
            "changed_slots": self.changed_slots,
            "unauthorized_state_write_confirmed": self.confirmed,
            "error": self.error,
        }


@dataclass
class TokenSweepVerdict:
    target: str
    victim: str
    token: str
    recipient: str
    selector: str
    caller: str
    tx_status: int
    victim_before: int
    victim_after: int
    recipient_before: int
    recipient_after: int
    calldata: str
    error: str = ""

    @property
    def confirmed(self) -> bool:
        return (
            self.tx_status == 1
            and self.victim_after < self.victim_before
            and self.recipient_after > self.recipient_before
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "victim": self.victim,
            "token": self.token,
            "recipient": self.recipient,
            "selector": self.selector,
            "caller": self.caller,
            "tx_status": self.tx_status,
            "victim_before": self.victim_before,
            "victim_after": self.victim_after,
            "recipient_before": self.recipient_before,
            "recipient_after": self.recipient_after,
            "calldata": self.calldata,
            "erc20_sweep_confirmed": self.confirmed,
            "error": self.error,
        }


@dataclass
class TokenFundingVerdict:
    token: str
    holder: str
    requested_amount: int
    before: int
    after: int
    storage_slot: int | None = None
    storage_key: str = ""
    error: str = ""

    @property
    def confirmed(self) -> bool:
        return self.after >= self.requested_amount

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "holder": self.holder,
            "requested_amount": self.requested_amount,
            "before": self.before,
            "after": self.after,
            "storage_slot": self.storage_slot,
            "storage_key": self.storage_key,
            "funding_confirmed": self.confirmed,
            "error": self.error,
        }


@dataclass
class TokenApprovalVerdict:
    target: str
    victim: str
    token: str
    spender: str
    recipient: str
    selector: str
    caller: str
    tx_status: int
    allowance_before: int
    allowance_after: int
    victim_before: int = 0
    victim_after: int = 0
    recipient_before: int = 0
    recipient_after: int = 0
    calldata: str = ""
    transfer_from_status: int = 0
    error: str = ""

    @property
    def allowance_confirmed(self) -> bool:
        return self.tx_status == 1 and self.allowance_after > self.allowance_before

    @property
    def exploited(self) -> bool:
        return (
            self.allowance_confirmed
            and self.transfer_from_status == 1
            and self.victim_after < self.victim_before
            and self.recipient_after > self.recipient_before
        )

    @property
    def confirmed(self) -> bool:
        return self.allowance_confirmed or self.exploited

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "victim": self.victim,
            "token": self.token,
            "spender": self.spender,
            "recipient": self.recipient,
            "selector": self.selector,
            "caller": self.caller,
            "tx_status": self.tx_status,
            "allowance_before": self.allowance_before,
            "allowance_after": self.allowance_after,
            "victim_before": self.victim_before,
            "victim_after": self.victim_after,
            "recipient_before": self.recipient_before,
            "recipient_after": self.recipient_after,
            "transfer_from_status": self.transfer_from_status,
            "calldata": self.calldata,
            "erc20_approval_confirmed": self.allowance_confirmed,
            "erc20_approval_exploited": self.exploited,
            "error": self.error,
        }


@dataclass
class NFTFundingVerdict:
    token: str
    holder: str
    token_id: int
    amount: int = 1
    asset_type: str = "erc721"
    before: str | int = ""
    after: str | int = ""
    storage_slot: int | None = None
    storage_key: str = ""
    error: str = ""

    @property
    def confirmed(self) -> bool:
        if self.asset_type == "erc721":
            return str(self.after).lower() == self.holder.lower()
        return int(self.after or 0) >= self.amount

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "holder": self.holder,
            "token_id": self.token_id,
            "amount": self.amount,
            "asset_type": self.asset_type,
            "before": self.before,
            "after": self.after,
            "storage_slot": self.storage_slot,
            "storage_key": self.storage_key,
            "funding_confirmed": self.confirmed,
            "error": self.error,
        }


@dataclass
class NFTSweepVerdict:
    target: str
    victim: str
    token: str
    recipient: str
    token_id: int
    selector: str
    caller: str
    tx_status: int
    asset_type: str
    victim_before: str | int
    victim_after: str | int
    recipient_before: int = 0
    recipient_after: int = 0
    calldata: str = ""
    error: str = ""

    @property
    def confirmed(self) -> bool:
        if self.asset_type == "erc721":
            return (
                self.tx_status == 1
                and str(self.victim_before).lower() == self.victim.lower()
                and str(self.victim_after).lower() == self.recipient.lower()
            )
        return (
            self.tx_status == 1
            and int(self.victim_after) < int(self.victim_before)
            and self.recipient_after > self.recipient_before
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "victim": self.victim,
            "token": self.token,
            "recipient": self.recipient,
            "token_id": self.token_id,
            "selector": self.selector,
            "caller": self.caller,
            "tx_status": self.tx_status,
            "asset_type": self.asset_type,
            "victim_before": self.victim_before,
            "victim_after": self.victim_after,
            "recipient_before": self.recipient_before,
            "recipient_after": self.recipient_after,
            "calldata": self.calldata,
            "nft_sweep_confirmed": self.confirmed,
            "error": self.error,
        }


class EIP7702DelegationProbe:
    """Point a local/fork EVM victim at a deployed implementation via 7702 code."""

    def __init__(self, w3, victim: str = "0x7702000000000000000000000000000000000001"):
        self.w3 = w3
        self.victim = Web3.to_checksum_address(victim) if Web3 is not None else victim

    def _checksum(self, address: str) -> str:
        return Web3.to_checksum_address(address) if Web3 is not None else address

    def _default_attacker(self) -> str:
        accounts = list(getattr(self.w3.eth, "accounts", []) or [])
        if len(accounts) > 1:
            return accounts[1]
        if accounts:
            return accounts[0]
        raise RuntimeError("no local accounts available for attacker probe")

    def _storage_snapshot(self, num_slots: int) -> list[str]:
        return [self.w3.eth.get_storage_at(self.victim, i).hex() for i in range(num_slots)]

    def _reset_storage_slots(self, num_slots: int) -> None:
        zero = "0x" + ("00" * 32)
        for slot in range(num_slots):
            key = "0x" + slot.to_bytes(32, "big").hex()
            try:
                self.w3.provider.make_request("anvil_setStorageAt", [self.victim, key, zero])
            except Exception:
                return

    def _erc20_balance(self, token: str, account: str) -> int:
        raw = self.w3.eth.call({
            "to": self._checksum(token),
            "data": erc20_balance_of_calldata(account),
        })
        if isinstance(raw, str):
            return int(_strip_0x(raw) or "0", 16)
        return int.from_bytes(raw, "big")

    def _call_uint(self, to: str, calldata: str) -> int:
        raw = self.w3.eth.call({"to": self._checksum(to), "data": calldata})
        if isinstance(raw, str):
            return int(_strip_0x(raw) or "0", 16)
        return int.from_bytes(raw, "big")

    def _erc20_allowance(self, token: str, owner: str, spender: str) -> int:
        return self._call_uint(token, erc20_allowance_calldata(owner, spender))

    def _erc721_owner_of(self, token: str, token_id: int) -> str:
        raw = self.w3.eth.call({
            "to": self._checksum(token),
            "data": erc721_owner_of_calldata(token_id),
        })
        if isinstance(raw, str):
            word = _strip_0x(raw).rjust(64, "0")
        else:
            word = raw.hex().rjust(64, "0")
        addr = "0x" + word[-40:]
        return self._checksum(addr)

    def _erc1155_balance(self, token: str, account: str, token_id: int) -> int:
        return self._call_uint(token, erc1155_balance_of_calldata(account, token_id))

    def erc20_balance_storage_key(self, holder: str, slot: int) -> str:
        """Return the Solidity mapping key for `mapping(address => uint) balances`.

        This is a fork-test helper, not a finding signal. The caller must verify
        it by reading `balanceOf(holder)` after patching storage.
        """
        encoded = bytes.fromhex(_encode_address(holder) + _encode_uint(slot))
        return "0x" + _keccak(encoded).hex()

    def erc721_owner_storage_key(self, token_id: int, slot: int) -> str:
        encoded = bytes.fromhex(_encode_uint(token_id) + _encode_uint(slot))
        return "0x" + _keccak(encoded).hex()

    def erc1155_balance_storage_key(self, holder: str, token_id: int, slot: int) -> str:
        outer = _keccak(bytes.fromhex(_encode_uint(token_id) + _encode_uint(slot))).hex()
        encoded = bytes.fromhex(_encode_address(holder) + _strip_0x(outer))
        return "0x" + _keccak(encoded).hex()

    def fund_erc20_balance_slot(self, token: str, holder: str, amount: int,
                                candidate_slots: Iterable[int] = range(12)
                                ) -> TokenFundingVerdict:
        """Patch common ERC20 balance mapping slots on an Anvil fork.

        The method brute-forces candidate mapping slots and accepts the patch
        only if `balanceOf(holder)` reports at least `amount`. This keeps the
        proof honest for normal ERC20/proxy storage while returning an explicit
        failed verdict for custom/rebasing layouts.
        """
        if amount < 0:
            raise ValueError("amount cannot be negative")
        holder = self._checksum(holder)
        token = self._checksum(token)
        try:
            before = self._erc20_balance(token, holder)
            if before >= amount:
                return TokenFundingVerdict(
                    token=token,
                    holder=holder,
                    requested_amount=amount,
                    before=before,
                    after=before,
                )
            value = "0x" + _encode_uint(amount)
            for slot in candidate_slots:
                key = self.erc20_balance_storage_key(holder, slot)
                self.w3.provider.make_request(
                    "anvil_setStorageAt",
                    [token, key, value],
                )
                after = self._erc20_balance(token, holder)
                if after >= amount:
                    return TokenFundingVerdict(
                        token=token,
                        holder=holder,
                        requested_amount=amount,
                        before=before,
                        after=after,
                        storage_slot=slot,
                        storage_key=key,
                    )
            final_balance = self._erc20_balance(token, holder)
            return TokenFundingVerdict(
                token=token,
                holder=holder,
                requested_amount=amount,
                before=before,
                after=final_balance,
                error="balance_slot_not_found",
            )
        except Exception as exc:
            return TokenFundingVerdict(
                token=token,
                holder=holder,
                requested_amount=amount,
                before=0,
                after=0,
                error=type(exc).__name__,
            )

    def fund_erc721_owner_slot(self, token: str, holder: str, token_id: int,
                               candidate_slots: Iterable[int] = range(12)
                               ) -> NFTFundingVerdict:
        holder = self._checksum(holder)
        token = self._checksum(token)
        try:
            try:
                before = self._erc721_owner_of(token, token_id)
            except Exception:
                before = ""
            if str(before).lower() == holder.lower():
                return NFTFundingVerdict(
                    token=token, holder=holder, token_id=token_id,
                    asset_type="erc721", before=before, after=before,
                )
            value = "0x" + _encode_address(holder)
            for slot in candidate_slots:
                key = self.erc721_owner_storage_key(token_id, slot)
                self.w3.provider.make_request("anvil_setStorageAt", [token, key, value])
                after = self._erc721_owner_of(token, token_id)
                if after.lower() == holder.lower():
                    return NFTFundingVerdict(
                        token=token, holder=holder, token_id=token_id,
                        asset_type="erc721", before=before, after=after,
                        storage_slot=slot, storage_key=key,
                    )
            final_owner = self._erc721_owner_of(token, token_id)
            return NFTFundingVerdict(
                token=token, holder=holder, token_id=token_id,
                asset_type="erc721", before=before, after=final_owner,
                error="owner_slot_not_found",
            )
        except Exception as exc:
            return NFTFundingVerdict(
                token=token, holder=holder, token_id=token_id,
                asset_type="erc721", error=type(exc).__name__,
            )

    def fund_erc1155_balance_slot(self, token: str, holder: str, token_id: int,
                                  amount: int, candidate_slots: Iterable[int] = range(12)
                                  ) -> NFTFundingVerdict:
        holder = self._checksum(holder)
        token = self._checksum(token)
        try:
            before = self._erc1155_balance(token, holder, token_id)
            if before >= amount:
                return NFTFundingVerdict(
                    token=token, holder=holder, token_id=token_id, amount=amount,
                    asset_type="erc1155", before=before, after=before,
                )
            value = "0x" + _encode_uint(amount)
            for slot in candidate_slots:
                key = self.erc1155_balance_storage_key(holder, token_id, slot)
                self.w3.provider.make_request("anvil_setStorageAt", [token, key, value])
                after = self._erc1155_balance(token, holder, token_id)
                if after >= amount:
                    return NFTFundingVerdict(
                        token=token, holder=holder, token_id=token_id, amount=amount,
                        asset_type="erc1155", before=before, after=after,
                        storage_slot=slot, storage_key=key,
                    )
            final_balance = self._erc1155_balance(token, holder, token_id)
            return NFTFundingVerdict(
                token=token, holder=holder, token_id=token_id, amount=amount,
                asset_type="erc1155", before=before, after=final_balance,
                error="balance_slot_not_found",
            )
        except Exception as exc:
            return NFTFundingVerdict(
                token=token, holder=holder, token_id=token_id, amount=amount,
                asset_type="erc1155", error=type(exc).__name__,
            )

    def probe_state_write(self, implementation: str, selector: str, attacker: str,
                          runtime_bytecode: str | bytes | None = None,
                          arg_word: str | None = None,
                          num_slots: int = 12) -> StateWriteVerdict:
        """Differential probe: delegate the victim to `implementation`, then have a
        non-owner `attacker` call `selector` (calldata = selector + a 32-byte word,
        defaulting to the left-padded attacker address — covers `f(address)` setters
        like initialize). Diff storage slots 0..num_slots. A successful call by an
        unrelated party that mutates storage = unauthorized state control confirmed.

        This auto-reproduces the Porwarder bug: initialize(address) called by a
        third party flips slot 0 to the attacker.
        """
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        sel = selector.lower().replace("0x", "")
        if arg_word is None:
            arg_word = attacker.lower().replace("0x", "").rjust(64, "0")
        calldata = "0x" + sel + arg_word
        self._reset_storage_slots(num_slots)
        before = self._storage_snapshot(num_slots)
        try:
            tx_hash = self.w3.eth.send_transaction({
                "from": Web3.to_checksum_address(attacker) if Web3 is not None else attacker,
                "to": self.victim,
                "data": calldata,
                "gas": 2_000_000,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            after = self._storage_snapshot(num_slots)
            changed = [i for i in range(num_slots) if before[i] != after[i]]
            return StateWriteVerdict(
                target=implementation, victim=self.victim, selector=sel,
                caller=attacker, tx_status=int(receipt.status), changed_slots=changed,
            )
        except Exception as exc:
            return StateWriteVerdict(
                target=implementation, victim=self.victim, selector=sel,
                caller=attacker, tx_status=0, error=type(exc).__name__,
            )

    def probe_state_write_with_calldata(self, implementation: str, calldata: str,
                                        caller: str,
                                        runtime_bytecode: str | bytes | None = None,
                                        num_slots: int = 12) -> StateWriteVerdict:
        """Generic storage-diff probe for synthesized multi-arg calldata."""
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        sel = _strip_0x(calldata)[:8].lower()
        self._reset_storage_slots(num_slots)
        before = self._storage_snapshot(num_slots)
        try:
            tx_hash = self.w3.eth.send_transaction({
                "from": self._checksum(caller),
                "to": self.victim,
                "data": calldata,
                "gas": 3_000_000,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            after = self._storage_snapshot(num_slots)
            changed = [i for i in range(num_slots) if before[i] != after[i]]
            return StateWriteVerdict(
                target=implementation, victim=self.victim, selector=sel,
                caller=caller, tx_status=int(receipt.status), changed_slots=changed,
            )
        except Exception as exc:
            return StateWriteVerdict(
                target=implementation, victim=self.victim, selector=sel,
                caller=caller, tx_status=0, error=type(exc).__name__,
            )

    def confirm_unauthorized_state_writes(self, implementation: str, selectors: list[str],
                                          attacker: str,
                                          runtime_bytecode: str | bytes | None = None,
                                          num_slots: int = 12) -> list[StateWriteVerdict]:
        """Run probe_state_write over candidate selectors; install bytecode once.
        Returns only the CONFIRMED unauthorized state writes."""
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        out: list[StateWriteVerdict] = []
        for sel in selectors:
            v = self.probe_state_write(implementation, sel, attacker, num_slots=num_slots)
            if v.confirmed:
                out.append(v)
        return out

    def set_delegation(self, implementation: str) -> None:
        impl = implementation.lower().replace("0x", "")
        if len(impl) != 40:
            raise ValueError("implementation must be a 20-byte address")
        self.w3.provider.make_request(
            "anvil_setCode",
            [self.victim, "0x" + DELEGATION_PREFIX + impl],
        )

    def install_implementation(self, implementation: str,
                               runtime_bytecode: str | bytes) -> None:
        code = normalize_bytecode(runtime_bytecode).hex()
        self.w3.provider.make_request(
            "anvil_setCode",
            [Web3.to_checksum_address(implementation), "0x" + code],
        )

    def probe_receive_value(self, implementation: str,
                            runtime_bytecode: str | bytes | None = None,
                            value_wei: int = 10**18) -> RuntimeProbeResult:
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        sender = self.w3.eth.accounts[0]
        try:
            tx_hash = self.w3.eth.send_transaction({
                "from": sender,
                "to": self.victim,
                "value": value_wei,
                "gas": 2_000_000,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            trace = self.w3.provider.make_request(
                "debug_traceTransaction",
                [tx_hash.hex(), {"tracer": "callTracer"}],
            )
            return RuntimeProbeResult(
                target=implementation,
                victim=self.victim,
                probe="receive_value_delegation",
                tx_status=int(receipt.status),
                value_flows=extract_value_flows_from_call_trace(trace),
            )
        except Exception as exc:
            return RuntimeProbeResult(
                target=implementation,
                victim=self.victim,
                probe="receive_value_delegation",
                tx_status=0,
                error=type(exc).__name__,
            )

    def probe_erc20_sweep_with_calldata(self, implementation: str, token: str,
                                        recipient: str, calldata: str,
                                        caller: str | None = None,
                                        runtime_bytecode: str | bytes | None = None,
                                        gas: int = 3_000_000) -> TokenSweepVerdict:
        """Call a delegated victim with prepared calldata and diff ERC20 balances.

        The caller is a non-owner attacker. The calldata should typically be an
        execute-class call generated by build_erc20_sweep_execute_candidates().
        A confirmed result means the victim's token balance fell and the
        recipient's balance rose after the attacker call.
        """
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        attacker = caller or self._default_attacker()
        sel = _strip_0x(calldata)[:8].lower()
        try:
            before_victim = self._erc20_balance(token, self.victim)
            before_recipient = self._erc20_balance(token, recipient)
            tx_hash = self.w3.eth.send_transaction({
                "from": self._checksum(attacker),
                "to": self.victim,
                "data": calldata,
                "gas": gas,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            after_victim = self._erc20_balance(token, self.victim)
            after_recipient = self._erc20_balance(token, recipient)
            return TokenSweepVerdict(
                target=implementation,
                victim=self.victim,
                token=token,
                recipient=recipient,
                selector=sel,
                caller=attacker,
                tx_status=int(receipt.status),
                victim_before=before_victim,
                victim_after=after_victim,
                recipient_before=before_recipient,
                recipient_after=after_recipient,
                calldata=calldata,
            )
        except Exception as exc:
            return TokenSweepVerdict(
                target=implementation,
                victim=self.victim,
                token=token,
                recipient=recipient,
                selector=sel,
                caller=attacker,
                tx_status=0,
                victim_before=0,
                victim_after=0,
                recipient_before=0,
                recipient_after=0,
                calldata=calldata,
                error=type(exc).__name__,
            )

    def probe_erc20_approval_with_calldata(self, implementation: str, token: str,
                                           spender: str, recipient: str,
                                           calldata: str, amount: int,
                                           caller: str | None = None,
                                           runtime_bytecode: str | bytes | None = None,
                                           gas: int = 3_000_000) -> TokenApprovalVerdict:
        """Prove a non-owner can make the delegated EOA approve a spender.

        If the victim has enough token balance, also attempts `transferFrom` from
        the approved spender to prove the approval is exploitable.
        """
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        attacker = caller or self._default_attacker()
        spender = self._checksum(spender)
        recipient = self._checksum(recipient)
        sel = _strip_0x(calldata)[:8].lower()
        try:
            allowance_before = self._erc20_allowance(token, self.victim, spender)
            victim_before = self._erc20_balance(token, self.victim)
            recipient_before = self._erc20_balance(token, recipient)
            tx_hash = self.w3.eth.send_transaction({
                "from": self._checksum(attacker),
                "to": self.victim,
                "data": calldata,
                "gas": gas,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            allowance_after = self._erc20_allowance(token, self.victim, spender)
            transfer_status = 0
            victim_after = self._erc20_balance(token, self.victim)
            recipient_after = self._erc20_balance(token, recipient)
            spend_amount = min(amount, victim_after, allowance_after)
            if int(receipt.status) == 1 and spend_amount > 0 and allowance_after > allowance_before:
                transfer_hash = self.w3.eth.send_transaction({
                    "from": spender,
                    "to": self._checksum(token),
                    "data": erc20_transfer_from_calldata(self.victim, recipient, spend_amount),
                    "gas": gas,
                })
                transfer_receipt = self.w3.eth.wait_for_transaction_receipt(transfer_hash)
                transfer_status = int(transfer_receipt.status)
                victim_after = self._erc20_balance(token, self.victim)
                recipient_after = self._erc20_balance(token, recipient)
            return TokenApprovalVerdict(
                target=implementation,
                victim=self.victim,
                token=token,
                spender=spender,
                recipient=recipient,
                selector=sel,
                caller=attacker,
                tx_status=int(receipt.status),
                allowance_before=allowance_before,
                allowance_after=allowance_after,
                victim_before=victim_before,
                victim_after=victim_after,
                recipient_before=recipient_before,
                recipient_after=recipient_after,
                transfer_from_status=transfer_status,
                calldata=calldata,
            )
        except Exception as exc:
            return TokenApprovalVerdict(
                target=implementation,
                victim=self.victim,
                token=token,
                spender=spender,
                recipient=recipient,
                selector=sel,
                caller=attacker,
                tx_status=0,
                allowance_before=0,
                allowance_after=0,
                calldata=calldata,
                error=type(exc).__name__,
            )

    def probe_erc721_sweep_with_calldata(self, implementation: str, nft: str,
                                         recipient: str, token_id: int,
                                         calldata: str, caller: str | None = None,
                                         runtime_bytecode: str | bytes | None = None,
                                         gas: int = 3_000_000) -> NFTSweepVerdict:
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        attacker = caller or self._default_attacker()
        recipient = self._checksum(recipient)
        sel = _strip_0x(calldata)[:8].lower()
        try:
            before_owner = self._erc721_owner_of(nft, token_id)
            tx_hash = self.w3.eth.send_transaction({
                "from": self._checksum(attacker),
                "to": self.victim,
                "data": calldata,
                "gas": gas,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            after_owner = self._erc721_owner_of(nft, token_id)
            return NFTSweepVerdict(
                target=implementation,
                victim=self.victim,
                token=nft,
                recipient=recipient,
                token_id=token_id,
                selector=sel,
                caller=attacker,
                tx_status=int(receipt.status),
                asset_type="erc721",
                victim_before=before_owner,
                victim_after=after_owner,
                calldata=calldata,
            )
        except Exception as exc:
            return NFTSweepVerdict(
                target=implementation,
                victim=self.victim,
                token=nft,
                recipient=recipient,
                token_id=token_id,
                selector=sel,
                caller=attacker,
                tx_status=0,
                asset_type="erc721",
                victim_before="",
                victim_after="",
                calldata=calldata,
                error=type(exc).__name__,
            )

    def probe_erc1155_sweep_with_calldata(self, implementation: str, token: str,
                                          recipient: str, token_id: int, amount: int,
                                          calldata: str, caller: str | None = None,
                                          runtime_bytecode: str | bytes | None = None,
                                          gas: int = 3_000_000) -> NFTSweepVerdict:
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        self.set_delegation(implementation)
        attacker = caller or self._default_attacker()
        recipient = self._checksum(recipient)
        sel = _strip_0x(calldata)[:8].lower()
        try:
            before_victim = self._erc1155_balance(token, self.victim, token_id)
            before_recipient = self._erc1155_balance(token, recipient, token_id)
            tx_hash = self.w3.eth.send_transaction({
                "from": self._checksum(attacker),
                "to": self.victim,
                "data": calldata,
                "gas": gas,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            after_victim = self._erc1155_balance(token, self.victim, token_id)
            after_recipient = self._erc1155_balance(token, recipient, token_id)
            return NFTSweepVerdict(
                target=implementation,
                victim=self.victim,
                token=token,
                recipient=recipient,
                token_id=token_id,
                selector=sel,
                caller=attacker,
                tx_status=int(receipt.status),
                asset_type="erc1155",
                victim_before=before_victim,
                victim_after=after_victim,
                recipient_before=before_recipient,
                recipient_after=after_recipient,
                calldata=calldata,
            )
        except Exception as exc:
            return NFTSweepVerdict(
                target=implementation,
                victim=self.victim,
                token=token,
                recipient=recipient,
                token_id=token_id,
                selector=sel,
                caller=attacker,
                tx_status=0,
                asset_type="erc1155",
                victim_before=0,
                victim_after=0,
                calldata=calldata,
                error=type(exc).__name__,
            )

    def probe_erc20_sweep_candidates(self, implementation: str, selectors: list[str],
                                     token: str, recipient: str, amount: int,
                                     caller: str | None = None,
                                     runtime_bytecode: str | bytes | None = None
                                     ) -> list[TokenSweepVerdict]:
        """Generate and execute ERC20 sweep candidates for exposed execute selectors."""
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        verdicts: list[TokenSweepVerdict] = []
        for candidate in build_erc20_sweep_execute_candidates(
            selectors, token, recipient, amount,
        ):
            verdicts.append(self.probe_erc20_sweep_with_calldata(
                implementation,
                token,
                recipient,
                candidate.calldata,
                caller=caller,
            ))
        return verdicts

    def probe_erc20_approval_candidates(self, implementation: str, selectors: list[str],
                                        token: str, spender: str, recipient: str,
                                        amount: int, caller: str | None = None,
                                        runtime_bytecode: str | bytes | None = None
                                        ) -> list[TokenApprovalVerdict]:
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        verdicts: list[TokenApprovalVerdict] = []
        for candidate in build_erc20_approval_execute_candidates(
            selectors, token, spender, amount,
        ):
            verdicts.append(self.probe_erc20_approval_with_calldata(
                implementation,
                token,
                spender,
                recipient,
                candidate.calldata,
                amount,
                caller=caller,
            ))
        return verdicts

    def probe_erc721_sweep_candidates(self, implementation: str, selectors: list[str],
                                      nft: str, recipient: str, token_id: int,
                                      caller: str | None = None,
                                      runtime_bytecode: str | bytes | None = None
                                      ) -> list[NFTSweepVerdict]:
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        verdicts: list[NFTSweepVerdict] = []
        for candidate in build_erc721_sweep_execute_candidates(
            selectors, nft, self.victim, recipient, token_id,
        ):
            verdicts.append(self.probe_erc721_sweep_with_calldata(
                implementation,
                nft,
                recipient,
                token_id,
                candidate.calldata,
                caller=caller,
            ))
        return verdicts

    def probe_erc1155_sweep_candidates(self, implementation: str, selectors: list[str],
                                       token: str, recipient: str, token_id: int,
                                       amount: int, caller: str | None = None,
                                       runtime_bytecode: str | bytes | None = None
                                       ) -> list[NFTSweepVerdict]:
        if runtime_bytecode is not None:
            self.install_implementation(implementation, runtime_bytecode)
        verdicts: list[NFTSweepVerdict] = []
        for candidate in build_erc1155_sweep_execute_candidates(
            selectors, token, self.victim, recipient, token_id, amount,
        ):
            verdicts.append(self.probe_erc1155_sweep_with_calldata(
                implementation,
                token,
                recipient,
                token_id,
                amount,
                candidate.calldata,
                caller=caller,
            ))
        return verdicts


def profiles_to_json(profiles: list[BytecodeProfile]) -> str:
    return json.dumps([p.to_dict() for p in profiles], indent=2, sort_keys=True)


# ────────────────────────────────────────────────────────────────────
# Bytecode-level AA7702 detector — no decompiler dependency
# ────────────────────────────────────────────────────────────────────

ORIGIN_OP = 0x32
CALLER_OP = 0x33
EQ_OP = 0x14
EXTCODESIZE_OP = 0x3B
EXTCODECOPY_OP = 0x3C
EXTCODEHASH_OP = 0x3F
DELEGATECALL_OP = 0xF4
SELFDESTRUCT_OP = 0xFF
ISZERO_OP = 0x15
JUMP_OP = 0x56
JUMPI_OP = 0x57
JUMPDEST_OP = 0x5B
RETURN_OP = 0xF3
REVERT_OP = 0xFD
STOP_OP = 0x00
INVALID_OP = 0xFE


@dataclass
class BytecodeFinding:
    """An AA7702-* finding recovered purely from runtime bytecode.

    Carries enough provenance (PC, opcode, owning selector) for a reviewer
    to ground-truth the signal against a disassembled trace. ``selector``
    is ``""`` when the hit lies in shared dispatcher / fallback code.
    """

    rule_id: str
    title: str
    severity: str
    pc: int
    opcode: int
    selector: str
    description: str
    confidence: float
    cwe: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "check_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "pc": self.pc,
            "opcode_hex": f"0x{self.opcode:02X}",
            "selector": self.selector,
            "description": self.description,
            "confidence": round(self.confidence, 2),
            "cwe": self.cwe,
            "category": "eip7702_bytecode",
            "analysis_depth": "bytecode",
            "location": (
                f"selector:0x{self.selector}:PC{self.pc}"
                if self.selector
                else f"dispatcher:PC{self.pc}"
            ),
        }


def _build_dispatcher_map(
    ops: list[tuple[int, int, bytes]],
) -> dict[str, int]:
    """Recover a ``{selector_hex: dest_pc}`` map from the solc dispatcher.

    Pattern: ``PUSH4 <sel> EQ PUSH(1|2) <dest> JUMPI`` — the standard solc
    Solidity dispatcher prologue. Each match yields one entry. Unusual
    dispatchers (Yul assembly, function table approaches) are ignored;
    selectors not in the map are tagged ``""`` later.
    """
    mapping: dict[str, int] = {}
    for idx, (pc, op, imm) in enumerate(ops):
        if op != 0x63 or len(imm) != 4:
            continue
        if idx + 3 >= len(ops):
            continue
        _, eq_op, _ = ops[idx + 1]
        if eq_op != EQ_OP:
            continue
        _, push_op, push_imm = ops[idx + 2]
        if push_op not in (0x60, 0x61, 0x62):  # PUSH1..PUSH3
            continue
        try:
            dest = int.from_bytes(push_imm, "big")
        except Exception:
            continue
        _, jumpi_op, _ = ops[idx + 3]
        if jumpi_op != JUMPI_OP:
            continue
        sel = imm.hex()
        mapping.setdefault(sel, dest)
    return mapping


def _selector_for_pc(
    pc: int,
    sorted_jumpdests: list[int],
    pc_to_selector: dict[int, str],
) -> str:
    """Return the selector whose function body contains ``pc`` (approximate).

    The owning JUMPDEST is the largest entry ``<= pc`` in the
    ``sorted_jumpdests`` list that also appears in ``pc_to_selector``.
    Returns ``""`` when no enclosing selector body could be matched.

    NOTE: solc dispatchers jump to *trampoline* JUMPDESTs that immediately
    re-jump to the real function body. This heuristic correctly tags the
    trampoline but reports the trampoline's selector for every PC in the
    body that follows it — which means a delegatecall in a later function
    can be reported under an earlier function's selector. PC and opcode
    are always exact; selector is a best-effort hint a reviewer can
    refine by disassembling around the reported PC.
    """
    owner = ""
    for dest in sorted_jumpdests:
        if dest > pc:
            break
        sel = pc_to_selector.get(dest, "")
        if sel:
            owner = sel
    return owner


def detect_bytecode_aa7702(
    bytecode: str | bytes,
    *,
    is_delegation_target_hint: bool = False,
) -> list[BytecodeFinding]:
    """Run bytecode-level AA7702 detection on ``bytecode``.

    ``bytecode`` is the runtime code returned by ``eth_getCode`` (with or
    without the ``0x`` prefix). The detector is deliberately conservative:
    it surfaces *candidate* signals, each annotated with PC + opcode +
    owning selector. A finding here means "this bytecode does the thing"
    — confirming exploitability still requires source / trace evidence,
    which is the same proof discipline used by the source detector.

    Heuristics:

    * **AA7702-001**: ``ORIGIN`` followed by ``CALLER`` (in either order)
      within a 6-opcode window, with at least one ``EQ`` opcode in the
      same window. That is the bytecode shape of ``tx.origin ==
      msg.sender``.
    * **AA7702-002**: ``EXTCODESIZE`` / ``EXTCODEHASH`` followed by
      ``ISZERO`` within a 4-opcode window — the bytecode shape of
      ``addr.code.length == 0`` / ``addr.code.length == 0``-equivalent
      compares.
    * **AA7702-006**: every ``DELEGATECALL`` opcode in the runtime code.
      Source-level suppression of pinned-storage layouts cannot be
      reproduced at the bytecode level without storage-slot static
      reasoning, so the bytecode detector reports raw and flags
      ``is_delegation_target_hint`` as an upgrade.
    * **AA7702-015**: every ``SELFDESTRUCT`` opcode — a delegation
      target containing it is high-risk on the delegated EOA's storage.
    * **AA7702-target**: bytecode that starts with the ``0xef0100``
      delegation-designator prefix is itself a delegated EOA shape, not
      a contract; report once at PC 0.
    """
    code = normalize_bytecode(bytecode)
    findings: list[BytecodeFinding] = []
    if not code:
        return findings

    hex_str = code.hex()
    if hex_str.startswith(DELEGATION_PREFIX):
        findings.append(BytecodeFinding(
            rule_id="AA7702-target",
            title="Runtime code is an EIP-7702 delegation designator",
            severity="INFO",
            pc=0,
            opcode=int(hex_str[0:2], 16),
            selector="",
            description=(
                "The runtime bytecode begins with the 0xef0100 prefix "
                "that EIP-7702 reserves for the delegation designator. "
                "Any subsequent execution on this address runs the code "
                "of the implementation it points at, not this code."
            ),
            confidence=0.99,
            cwe="CWE-668",
        ))
        # No further opcode-level analysis is meaningful on the
        # designator itself; the implementation it points at is the
        # real target.
        return findings

    ops = list(iter_opcodes(code))
    dispatcher = _build_dispatcher_map(ops)
    jumpdests = sorted(pc for pc, op, _ in ops if op == JUMPDEST_OP)
    pc_to_selector: dict[int, str] = {
        dest: sel for sel, dest in dispatcher.items()
    }

    op_pcs = [pc for pc, _op, _ in ops]
    op_codes = [op for _pc, op, _ in ops]

    # AA7702-001 — ORIGIN + CALLER + EQ within a 6-opcode window
    n = len(op_codes)
    seen_001: set[tuple[str, int]] = set()
    for i in range(n):
        if op_codes[i] not in (ORIGIN_OP, CALLER_OP):
            continue
        window_end = min(n, i + 6)
        window_ops = op_codes[i:window_end]
        has_origin = ORIGIN_OP in window_ops
        has_caller = CALLER_OP in window_ops
        has_eq = EQ_OP in window_ops
        if has_origin and has_caller and has_eq:
            pc = op_pcs[i]
            sel = _selector_for_pc(pc, jumpdests, pc_to_selector)
            key = ("AA7702-001", sel or f"pc{pc}")
            if key in seen_001:
                continue
            seen_001.add(key)
            findings.append(BytecodeFinding(
                rule_id="AA7702-001",
                title=(
                    "EIP-7702: tx.origin == msg.sender check in runtime "
                    f"bytecode at PC {pc}"
                ),
                severity="CRITICAL",
                pc=pc,
                opcode=op_codes[i],
                selector=sel,
                description=(
                    "Bytecode opcodes ORIGIN + CALLER + EQ within a 6-"
                    "opcode window. After EIP-7702 the EOA boundary that "
                    "this check encodes is broken — a delegated EOA "
                    "passes while executing arbitrary code. The hit is "
                    f"inside {('selector 0x' + sel) if sel else 'shared dispatcher / fallback code'}."
                ),
                confidence=0.88,
                cwe="CWE-284",
            ))

    # AA7702-002 — EXTCODESIZE / EXTCODEHASH followed by ISZERO
    seen_002: set[tuple[str, int]] = set()
    for i, op in enumerate(op_codes):
        if op not in (EXTCODESIZE_OP, EXTCODEHASH_OP):
            continue
        window_end = min(n, i + 4)
        if ISZERO_OP not in op_codes[i + 1: window_end]:
            continue
        pc = op_pcs[i]
        sel = _selector_for_pc(pc, jumpdests, pc_to_selector)
        key = ("AA7702-002", sel or f"pc{pc}")
        if key in seen_002:
            continue
        seen_002.add(key)
        findings.append(BytecodeFinding(
            rule_id="AA7702-002",
            title=(
                f"EIP-7702: code.length / extcodehash check at PC {pc}"
            ),
            severity="HIGH",
            pc=pc,
            opcode=op,
            selector=sel,
            description=(
                "EXTCODESIZE / EXTCODEHASH followed by ISZERO — bytecode "
                "shape of an isContract-style EOA test. Under EIP-7702 "
                "a delegated EOA has nonzero code so the check "
                "misclassifies. Inside "
                f"{('selector 0x' + sel) if sel else 'shared code'}."
            ),
            confidence=0.78,
            cwe="CWE-697",
        ))

    # AA7702-006 — every DELEGATECALL opcode
    seen_006: set[tuple[str, int]] = set()
    for i, op in enumerate(op_codes):
        if op != DELEGATECALL_OP:
            continue
        pc = op_pcs[i]
        sel = _selector_for_pc(pc, jumpdests, pc_to_selector)
        key = ("AA7702-006", sel or f"pc{pc}")
        if key in seen_006:
            continue
        seen_006.add(key)
        sev = "HIGH" if is_delegation_target_hint else "MEDIUM"
        findings.append(BytecodeFinding(
            rule_id="AA7702-006",
            title=f"EIP-7702: DELEGATECALL opcode at PC {pc}",
            severity=sev,
            pc=pc,
            opcode=op,
            selector=sel,
            description=(
                "DELEGATECALL in runtime bytecode. If this contract is "
                "ever used as an EIP-7702 delegation target, the inner "
                "delegatecall creates a second context switch against "
                "the delegated EOA's storage. Inside "
                f"{('selector 0x' + sel) if sel else 'shared code'}."
            ),
            confidence=0.70 if is_delegation_target_hint else 0.50,
            cwe="CWE-693",
        ))

    # AA7702-015 — SELFDESTRUCT
    for i, op in enumerate(op_codes):
        if op != SELFDESTRUCT_OP:
            continue
        pc = op_pcs[i]
        sel = _selector_for_pc(pc, jumpdests, pc_to_selector)
        findings.append(BytecodeFinding(
            rule_id="AA7702-015",
            title=f"EIP-7702: SELFDESTRUCT opcode at PC {pc}",
            severity="HIGH",
            pc=pc,
            opcode=op,
            selector=sel,
            description=(
                "SELFDESTRUCT in runtime bytecode. If this contract is "
                "used as an EIP-7702 delegation target the selfdestruct "
                "executes against the delegated EOA — clearing its "
                "storage. Inside "
                f"{('selector 0x' + sel) if sel else 'shared code'}."
            ),
            confidence=0.85,
            cwe="CWE-668",
        ))

    return findings


def bytecode_findings_to_json(findings: list[BytecodeFinding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True)
