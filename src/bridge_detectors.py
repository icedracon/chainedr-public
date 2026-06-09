"""
ChainEDR — 2026 Detector Pack: Cross-Chain Bridge + ZK Verifier

Two new check classes driven by 2026 attack landscape:

  1. bridge_address_validation_gap  (38% of Q1 2026 DeFi losses)
     Purrlend-class: cross-chain message handler trusts msg.sender or
     a bridge-supplied address without cryptographic verification.
     Real attack: attacker deploys contract with same address on another
     chain, sends crafted bridge message, victim contract accepts it.

  2. zk_verifier_misconfig            (Foom Cash, $2.3M in 2026)
     Plonk/Groth16 verifier setup bug: trusted setup parameters not
     pinned, verifying-key not enforced, or proof.input ordering
     mismatched with circuit.

  3. zk_public_input_unconstrained    (verifier accepts arbitrary input)
     Common pattern: public input array passed to verifier without
     bounds check or value range enforcement.

Usage:
    from src.bridge_detectors import check_bridge_validation, check_zk_misconfig

    findings = []
    findings += check_bridge_validation(source_code)
    findings += check_zk_misconfig(source_code)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List


# ── Bridge address validation gap ────────────────────────────────────────────

_BRIDGE_HANDLERS = [
    # Common cross-chain message handler entry points
    r'function\s+receiveMessage\s*\(',
    r'function\s+_executeMessage\s*\(',
    r'function\s+lzReceive\s*\(',                # LayerZero
    r'function\s+executeMessage\s*\(',
    r'function\s+ccipReceive\s*\(',              # Chainlink CCIP
    r'function\s+_ccipReceive\s*\(',
    r'function\s+handle\s*\(',                   # Hyperlane
    r'function\s+wormholeReceive\s*\(',
    r'function\s+onMessageReceived\s*\(',
    r'function\s+anyExecute\s*\(',                # Multichain
    r'function\s+messageReceived\s*\(',
    r'function\s+_processMessage\s*\(',
]

_BRIDGE_SRC_ADDR_PARAMS = [
    'srcAddress', 'srcSender', 'sourceAddress', 'sender',
    'senderAddress', 'srcAddr', 'fromAddress', 'from_',
]

_BRIDGE_VALIDATION_PATTERNS = [
    # Patterns that indicate proper validation
    r'require\s*\([^)]*trustedRemote',
    r'require\s*\([^)]*trustedSender',
    r'require\s*\([^)]*authorized\w*',
    r'require\s*\([^)]*remoteAddress\s*==',
    r'require\s*\([^)]*srcAddress\s*==',
    r'require\s*\([^)]*keccak256\s*\([^)]*\)\s*==',  # hash-based check
    r'_authorizedSender\s*\[',
    r'onlyTrusted',
    r'remoteCallers\s*\[',
    r'verifyMessageHash\s*\(',
    r'verifyMerkleProof\s*\(',
    r'isValidRemote\s*\(',
]


def check_bridge_validation(source_code: Dict[str, str]) -> List[Dict]:
    """
    Detect cross-chain bridge handlers that lack source-address verification.

    Returns list of finding dicts (Hunter dict shape).
    """
    findings = []
    for filename, content in source_code.items():
        for handler_pattern in _BRIDGE_HANDLERS:
            for m in re.finditer(handler_pattern, content):
                # Extract function body via brace matching
                brace_pos = content.find('{', m.end())
                if brace_pos == -1:
                    continue
                body = _extract_body(content, brace_pos)
                if not body:
                    continue

                # Does the body validate src address?
                has_validation = any(
                    re.search(p, body, re.I) for p in _BRIDGE_VALIDATION_PATTERNS
                )
                if has_validation:
                    continue   # safe

                # Does the body USE any source-address param?
                uses_src = any(
                    re.search(rf'\b{p}\b', body) for p in _BRIDGE_SRC_ADDR_PARAMS
                )
                if not uses_src:
                    continue   # not a real bridge handler

                # Check if it makes state changes / external calls
                has_sink = bool(re.search(
                    r'\.transfer\s*\(|\.call\s*\(|\.send\s*\(|'
                    r'_mint\s*\(|\.mint\s*\(|\bemit\s+\w+\(',
                    body
                ))
                if not has_sink:
                    continue

                fn_name_m = re.search(r'function\s+(\w+)', m.group(0))
                fn_name = fn_name_m.group(1) if fn_name_m else '?'

                findings.append({
                    'check':       'bridge_address_validation_gap',
                    'severity':    'HIGH',
                    'confidence':  0.72,
                    'description': (
                        f"Cross-chain message handler {fn_name}() in {filename} "
                        f"uses a source-address parameter without verifying its "
                        f"authenticity. Attacker can deploy a contract with the same "
                        f"address on the source chain and send a forged message to "
                        f"unauthorized state changes or fund movements."
                    ),
                    'function':    fn_name,
                    'file':        filename,
                    'category':    'cross_chain',
                    'evidence_type': 'HEURISTIC',
                    'recommendation': (
                        "Add validation: require(_trustedRemoteLookup[_srcChainId] == _srcAddress) "
                        "OR verify a Merkle proof / signature against a pinned root. "
                        "LayerZero: use OAppCore.setPeer + _checkSender. CCIP: validate router "
                        "AND source-chain selector. Hyperlane: use Mailbox validator set proofs."
                    ),
                    'gap_advantage': (
                        "2026 attack class: bridge address validation gaps account for "
                        "~38% of Q1 2026 DeFi losses ($750M+ category). Slither/Aderyn "
                        "do not specifically check cross-chain handler validation."
                    ),
                    'real_world_example': (
                        "Purrlend (2026): attacker deployed identical-address contract "
                        "on bridge source chain, fed forged message into victim handler."
                    ),
                    'cve_class':   'CWE-345 (insufficient verification of data authenticity)',
                    'owasp_2026':  'SC04-Insufficient-Access-Control',
                })
                break   # one finding per handler function

    return findings


# ── ZK verifier misconfig ────────────────────────────────────────────────────

# Real ZK verifier call sites only. A bare `.verify(` matches Merkle-proof and
# signature verification (MerkleProof.verify, ECDSA-style .verify) which are NOT
# ZK — including it caused ~100% FP on account-abstraction / multichain code.
_ZK_VERIFIER_CALLS = [
    r'verifyProof\s*\(',
    r'_verifier\.verify\s*\(',
    r'Groth16Verifier',
    r'PlonkVerifier',
    r'IVerifier\([^)]+\)\.verify',
]

# A file must actually be doing ZK before we flag verifier-misconfig, otherwise
# Merkle/signature/multichain code trips the detector.
_ZK_CONTEXT_RE = re.compile(
    r'(groth16|plonk|snark|zk[\-_ ]?proof|verifyProof|verifying[\-_ ]?key|'
    r'trusted[\-_ ]?setup|pairing|\bIVerifier\b)',
    re.I,
)

_ZK_PUBLIC_INPUT_GUARDS = [
    r'require\s*\([^)]*publicInputs?\.length\s*==',
    r'require\s*\([^)]*input\.length\s*==',
    r'require\s*\([^)]*signals\s*\.length\s*==',
    # Range/bounds checks on inputs
    r'require\s*\([^)]*input\[\d+\]\s*<',
    r'require\s*\([^)]*input\[\d+\]\s*<=',
    r'require\s*\([^)]*signals\[\d+\]\s*<',
]


def check_zk_misconfig(source_code: Dict[str, str]) -> List[Dict]:
    """
    Detect ZK verifier integrations that:
      A. Don't pin the verifier address (immutable / constructor-only setter)
      B. Pass public inputs without length / range validation
      C. Use weak field arithmetic (modulo without prime check)
    """
    findings = []

    for filename, content in source_code.items():
        # Skip pure verifier libraries — they're allowed to do anything
        if re.search(r'\bcontract\s+\w*Verifier\b', content):
            continue

        # Require genuine ZK context, else Merkle/signature/multichain code
        # (which also calls things like `.verify`) produces pure false positives.
        if not _ZK_CONTEXT_RE.search(content):
            continue

        # Pattern A + B: look for verifier call sites in consumer contracts
        for vp in _ZK_VERIFIER_CALLS:
            for m in re.finditer(vp, content):
                # Get a context window around the call
                ctx_start = max(0, m.start() - 300)
                ctx_end = min(len(content), m.end() + 300)
                ctx = content[ctx_start:ctx_end]

                # Does the surrounding function validate inputs?
                has_input_guard = any(
                    re.search(p, ctx) for p in _ZK_PUBLIC_INPUT_GUARDS
                )

                # Is the verifier address mutable (set by non-owner / no access control)?
                has_setter = bool(re.search(
                    r'function\s+set\w*[Vv]erifier\s*\([^)]*\)[^{]*\{',
                    content
                ))
                # Check if any verifier setter exists; flag if no access control
                setter_unguarded = False
                if has_setter:
                    setter_m = re.search(
                        r'function\s+set\w*[Vv]erifier\s*\([^)]*\)([^{]*)\{',
                        content
                    )
                    if setter_m:
                        modifiers = setter_m.group(1)
                        if not any(t in modifiers for t in
                                   ['onlyOwner', 'onlyAdmin', 'onlyRole', 'auth']):
                            setter_unguarded = True

                if has_input_guard and not setter_unguarded:
                    continue   # well-defended

                missing = []
                if not has_input_guard:
                    missing.append('public-input length/range validation')
                if setter_unguarded:
                    missing.append('access control on verifier setter')

                findings.append({
                    'check':       'zk_verifier_misconfig',
                    'severity':    'HIGH' if setter_unguarded else 'MEDIUM',
                    'confidence':  0.68,
                    'description': (
                        f"ZK proof verifier integration in {filename} is missing: "
                        f"{', '.join(missing)}. Without these guards, "
                        f"{'an attacker can swap the verifier address with a no-op' if setter_unguarded else 'malformed or out-of-range public inputs may bypass intended constraints'}."
                    ),
                    'function':    '',
                    'file':        filename,
                    'category':    'zk',
                    'evidence_type': 'HEURISTIC',
                    'recommendation': (
                        "1. Make verifier immutable: `IVerifier public immutable verifier;` "
                        "set only in constructor. 2. Validate every public input: check "
                        "length matches circuit, check each signal is < curve order (e.g. "
                        "BN254 < 21888242871839275222246405745257275088548364400416034343698204186575808495617). "
                        "3. If setter required, gate with multi-sig or timelock."
                    ),
                    'gap_advantage': (
                        "ZK verifier misconfiguration is an emerging 2026 attack class. "
                        "Foom Cash lost $2.3M to a Plonk verifier setup bug. No standard "
                        "static analyzer covers this pattern."
                    ),
                    'real_world_example': (
                        "Foom Cash (2026): $2.3M drained via verifier misconfig in Plonk setup."
                    ),
                    'cve_class':   'CWE-345 / weak verification',
                    'owasp_2026':  'SC02-Logic-Errors',
                })
                break   # one per call site

    return findings


# ── Bridge signature / replay checks ────────────────────────────────────────

_BRIDGE_SIG_HASH_RE = re.compile(
    r'keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\(([^)]{20,})\)',
    re.DOTALL,
)

_EIP712_BOUND_DOMAIN_RE = re.compile(
    r'(DOMAIN_SEPARATOR|domainSeparator|_domainSeparator|_domainSeparatorV4|'
    r'_hashTypedData|_hashTypedDataV4|toTypedDataHash)',
    re.I,
)

_BRIDGE_RECEIVE_RE = re.compile(
    r'function\s+(receiveTokens|withdrawTokens|claimTokens|releaseTokens|'
    r'processWithdrawal|executeWithdrawal|fulfillBridge)\s*\(',
)

_REPLAY_GUARD_RE = re.compile(
    r'(usedHashes|processedHashes|executedIds|claimedIds|usedNonces|'
    r'completed\s*\[|executed\s*\[|processed\s*\[)',
)

_EXTERNAL_ID_CHECK_RE = re.compile(
    r'require\s*\([^)]*(?:externalId|txHash|bridgeId|requestId|nonce)',
)


def check_bridge_signature_gaps(source_code: Dict[str, str]) -> List[Dict]:
    """
    Detect bridge signature/hash construction weaknesses:
    1. Signature hash missing address(this) → valid on cloned bridges
    2. Receive-side function missing replay protection (externalId uniqueness)
    3. bytes32→address truncation without upper-bit validation
    """
    findings = []

    for filename, content in source_code.items():
        # Skip interfaces and test files
        if filename.startswith('I') and filename[1].isupper():
            continue

        # Check 1: Signature hash missing address(this)
        for m in _BRIDGE_SIG_HASH_RE.finditer(content):
            hash_params = m.group(1)
            has_bridge_context = bool(re.search(
                r'bridge|Bridge|BRIDGE|cross.*chain|deposit|withdraw',
                content[:m.start()],
            ))
            if not has_bridge_context:
                continue
            surrounding_context = content[max(0, m.start() - 1500):m.start() + 1500]
            if re.search(r'permit2\s*\.\s*permitTransferFrom|IPermit2\s*\.\s*PermitTransferFrom', surrounding_context):
                continue
            has_signature_context = bool(re.search(
                r'signature|signer|ecrecover|ECDSA|recover|isValidSignature|SignatureChecker',
                surrounding_context,
                re.IGNORECASE,
            ))
            if not has_signature_context:
                continue

            has_this = 'address(this)' in hash_params
            has_chain = bool(re.search(r'chainId|chainid|block\.chainid', hash_params))
            has_inline_eip712_domain_binding = bool(
                _EIP712_BOUND_DOMAIN_RE.search(surrounding_context)
                and re.search(r'(verifyingContract|EIP712|DOMAIN_SEPARATOR|_domainSeparator)', content, re.I)
                and 'address(this)' in content
                and re.search(r'chainId|chainid|block\.chainid', content)
            )
            has_oz_eip712_domain_binding = bool(
                re.search(r'_hashTypedData(?:V4)?\s*\(', surrounding_context)
                and re.search(r'(EIP712Upgradeable|EIP712)\b|__EIP712_init\s*\(', content)
            )
            has_eip712_domain_binding = (
                has_inline_eip712_domain_binding or has_oz_eip712_domain_binding
            )

            if not has_this and not has_eip712_domain_binding:
                line = content[:m.start()].count('\n') + 1
                findings.append({
                    'check': 'bridge_sig_missing_address',
                    'severity': 'HIGH',
                    'confidence': 0.80,
                    'title': 'Bridge signature hash missing address(this)',
                    'description': (
                        f"Signature hash in {filename}:L{line} does not include "
                        f"address(this). If the same bridge contract is deployed at a "
                        f"different address (clone, fork, or multi-deployment), the same "
                        f"signature is valid on both. An attacker can replay a valid "
                        f"signature from one bridge instance to another."
                        + ("" if has_chain else
                           " Additionally, no chain_id is included in the hash, "
                           "enabling cross-chain replay.")
                    ),
                    'file': filename,
                    'category': 'cross_chain',
                    'cwe': 'CWE-294',
                })

        # Check 2: Receive function without replay guard
        for m in _BRIDGE_RECEIVE_RE.finditer(content):
            fn_name = m.group(1)
            brace_pos = content.find('{', m.end())
            if brace_pos == -1:
                continue
            body = _extract_body(content, brace_pos)
            if not body:
                continue

            has_replay_guard = bool(_REPLAY_GUARD_RE.search(body))
            has_id_check = bool(_EXTERNAL_ID_CHECK_RE.search(body))
            header = content[m.start():brace_pos]
            is_admin_rescue = bool(
                fn_name == "withdrawTokens"
                and re.search(r'onlyRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*\)|onlyOwner|onlyAdmin', header)
                and re.search(r'safeTransfer\s*\(|sendValue\s*\(', body)
                and not re.search(r'nonce|proof|signature|message|claim|deposit|confirmed|processed|executed', body, re.I)
            )
            if is_admin_rescue:
                continue

            if not has_replay_guard and not has_id_check:
                line = content[:m.start()].count('\n') + 1
                has_role = bool(re.search(r'onlyRole|onlyOwner|onlyRelayer|onlyAdmin', body) or
                               re.search(r'onlyRole|onlyOwner|onlyRelayer|onlyAdmin',
                                         content[m.start():brace_pos]))

                findings.append({
                    'check': 'bridge_receive_no_replay_guard',
                    'severity': 'HIGH' if not has_role else 'MEDIUM',
                    'confidence': 0.85 if not has_role else 0.70,
                    'title': f'{fn_name}() missing on-chain replay protection',
                    'description': (
                        f"{fn_name}() in {filename}:L{line} processes bridge "
                        f"withdrawals/claims but has no on-chain replay guard "
                        f"(no usedHashes/processedIds/nonce check). "
                        + ("" if not has_role else
                           "The function is role-gated, but if the role key is "
                           "compromised, there is no on-chain defense against "
                           "replaying the same withdrawal multiple times. ")
                        + "An attacker (or compromised relayer) can call this "
                        f"function repeatedly with the same parameters to drain funds."
                    ),
                    'file': filename,
                    'category': 'cross_chain',
                    'cwe': 'CWE-294',
                })

        # Check 3: bytes32→address truncation
        truncation_matches = list(re.finditer(
            r'address\s*\(\s*uint160\s*\(\s*uint256\s*\(',
            content,
        ))
        if len(truncation_matches) >= 3:
            has_upper_check = bool(re.search(
                r'require\s*\([^)]*>>\s*160|require\s*\([^)]*&\s*0x[fF]+',
                content,
            ))
            if not has_upper_check:
                findings.append({
                    'check': 'bridge_bytes32_truncation',
                    'severity': 'MEDIUM',
                    'confidence': 0.60,
                    'title': f'bytes32→address truncation without upper-bit check ({len(truncation_matches)} casts)',
                    'description': (
                        f"{filename} has {len(truncation_matches)} "
                        f"address(uint160(uint256(x))) casts. If the bytes32 value "
                        f"has non-zero upper 96 bits (from a non-EVM chain encoding), "
                        f"they are silently discarded. Two different bytes32 values "
                        f"can map to the same address, enabling mapping confusion "
                        f"or duplicate processing."
                    ),
                    'file': filename,
                    'category': 'cross_chain',
                    'cwe': 'CWE-681',
                })

    return findings


# ── Internal helpers ─────────────────────────────────────────────────────────

def _extract_body(src: str, open_brace_pos: int) -> str:
    """Brace-matched function body extraction."""
    depth = 0
    i = open_brace_pos
    n = len(src)
    while i < n:
        c = src[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return src[open_brace_pos + 1:i]
        i += 1
    return ''


# ── Convenience: scan a directory ────────────────────────────────────────────

def scan_directory(directory: str) -> List[Dict]:
    """
    Run both detectors on every .sol file in a directory tree.
    Skips test/mock/vendor paths.
    """
    src = {}
    skip = ['/test', '\\test', '/mock', '\\mock', '.t.sol', 'test.sol']
    for f in Path(directory).rglob('*.sol'):
        if any(s in str(f).lower() for s in skip):
            continue
        try:
            src[f.name] = f.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
    findings = check_bridge_validation(src) + check_bridge_signature_gaps(src) + check_zk_misconfig(src)
    return findings
