"""
EIP-7702 / ERC-7562 validation-sandbox detector.

This detector targets pre-execution account-abstraction risks: code that may
pass local tests but violate ERC-7562 bundler validation constraints once an
EIP-7702 delegated account participates in a UserOperation flow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

try:
    from .detector_plugin import (
        Detector,
        DetectorCategory,
        Finding,
        ScanOptions,
        ScanResult,
        Severity,
        register_detector,
    )
    from .eip7702_sandbox import PreBehaviorTrace, SandboxPolicy
except ImportError:
    from detector_plugin import (
        Detector,
        DetectorCategory,
        Finding,
        ScanOptions,
        ScanResult,
        Severity,
        register_detector,
    )
    from eip7702_sandbox import PreBehaviorTrace, SandboxPolicy


_POLICY = SandboxPolicy()


@dataclass(frozen=True)
class _ValidationRule:
    rule_id: str
    erc7562_rule: str
    severity: Severity
    title: str
    boundary: str
    bypass_class: str
    assumption: str
    delegated_behavior: str
    fix: str
    confidence: float


_RULES = {
    "AA7562-001": _ValidationRule(
        rule_id="AA7562-001",
        erc7562_rule="OP-011/OP-012",
        severity=Severity.HIGH,
        title="Validation function reads forbidden environment data",
        boundary="validation_boundary",
        bypass_class="validation_environment_dependency",
        assumption="Validation outcome is deterministic across bundler simulation and inclusion.",
        delegated_behavior=(
            "A delegated account validation path can branch on origin, block data, gas, "
            "or destructive opcodes that ERC-7562 validation rules restrict."
        ),
        fix="Remove environment-dependent reads from validation; bind needed context in signed data.",
        confidence=0.78,
    ),
    "AA7562-002": _ValidationRule(
        rule_id="AA7562-002",
        erc7562_rule="OP-061",
        severity=Severity.HIGH,
        title="Validation function performs value transfer",
        boundary="gas_boundary",
        bypass_class="validation_value_call",
        assumption="Validation only proves authorization and cannot move value or trigger paid calls.",
        delegated_behavior=(
            "A delegated account validation path can spend value or trigger stateful receiver code "
            "before the UserOperation is included."
        ),
        fix="Move value transfers to execution; keep validateUserOp/validatePaymasterUserOp side-effect safe.",
        confidence=0.80,
    ),
    "AA7562-003": _ValidationRule(
        rule_id="AA7562-003",
        erc7562_rule="COD-010",
        severity=Severity.HIGH,
        title="Validation depends on mutable external code identity",
        boundary="code_boundary",
        bypass_class="simulation_execution_code_drift",
        assumption="Code observed during first validation is identical during second validation and inclusion.",
        delegated_behavior=(
            "A delegated account can validate against one target codehash and execute after that code changes."
        ),
        fix="Pin implementation codehashes and reject operations when the observed codehash changes.",
        confidence=0.72,
    ),
    "AA7562-004": _ValidationRule(
        rule_id="AA7562-004",
        erc7562_rule="AUTH-010",
        severity=Severity.CRITICAL,
        title="UserOperation accepts multiple EIP-7702 authorization tuples",
        boundary="replay_boundary",
        bypass_class="multiple_7702_authorization_tuples",
        assumption="A UserOperation carries at most one EIP-7702 authorization tuple.",
        delegated_behavior=(
            "Multiple authorization tuples can create ambiguous delegated authority during mempool validation."
        ),
        fix="Require exactly one EIP-7702 authorization tuple per UserOperation.",
        confidence=0.84,
    ),
    "AA7562-005": _ValidationRule(
        rule_id="AA7562-005",
        erc7562_rule="AUTH-020/AUTH-030",
        severity=Severity.HIGH,
        title="Delegated EIP-7702 account used outside UserOperation sender role",
        boundary="identity_boundary",
        bypass_class="delegated_sender_role_escape",
        assumption="An EIP-7702 delegated account is only used as the UserOperation sender.",
        delegated_behavior=(
            "Delegated authority can be treated as a paymaster, factory, aggregator, or arbitrary entity."
        ),
        fix="Reject delegated EIP-7702 accounts unless they are the UserOperation sender.",
        confidence=0.74,
    ),
    "AA7562-006": _ValidationRule(
        rule_id="AA7562-006",
        erc7562_rule="AUTH-040",
        severity=Severity.MEDIUM,
        title="Batch accepts same-sender EIP-7702 authorizations without delegate consistency check",
        boundary="replay_boundary",
        bypass_class="same_sender_delegate_mismatch",
        assumption="Mempool entries from the same sender share the same EIP-7702 delegate address.",
        delegated_behavior=(
            "A batch can contain same-sender UserOperations that authorize different delegate addresses."
        ),
        fix="Track sender to delegate address and reject mismatches before accepting a batch.",
        confidence=0.68,
    ),
    "AA7562-007": _ValidationRule(
        rule_id="AA7562-007",
        erc7562_rule="ERC-4337 userOpHash binding",
        severity=Severity.HIGH,
        title="Signature validation does not bind to userOpHash",
        boundary="validation_boundary",
        bypass_class="signature_domain_binding_bypass",
        assumption="Account validation binds signatures to the full UserOperation, EntryPoint, and chain context.",
        delegated_behavior=(
            "A delegated account can accept a signature over partial data and replay it across operations or domains."
        ),
        fix="Recover or verify signatures over the EntryPoint-supplied userOpHash.",
        confidence=0.76,
    ),
    "AA7562-008": _ValidationRule(
        rule_id="AA7562-008",
        erc7562_rule="ERC-4337 EntryPoint isolation",
        severity=Severity.HIGH,
        title="Validation function is not gated to EntryPoint",
        boundary="identity_boundary",
        bypass_class="entrypoint_caller_bypass",
        assumption="Only the canonical EntryPoint can call account or paymaster validation hooks.",
        delegated_behavior=(
            "A delegated EOA or arbitrary caller can invoke validation logic outside the bundler sandbox."
        ),
        fix="Add `onlyEntryPoint` or `require(msg.sender == address(entryPoint()))` to validation hooks.",
        confidence=0.70,
    ),
    "AA7562-009": _ValidationRule(
        rule_id="AA7562-009",
        erc7562_rule="EIP-7702 PER_EMPTY_ACCOUNT_COST",
        severity=Severity.MEDIUM,
        title="EIP-7702 authorization gas cost not included in preVerificationGas",
        boundary="gas_boundary",
        bypass_class="preverification_gas_underaccounting",
        assumption="Bundler pre-verification gas includes the additional EIP-7702 empty-account authorization cost.",
        delegated_behavior=(
            "A UserOperation with EIP-7702 authorization can be underpriced if PER_EMPTY_ACCOUNT_COST is omitted."
        ),
        fix="Add PER_EMPTY_ACCOUNT_COST (25000 gas) per EIP-7702 authorization to preVerificationGas accounting.",
        confidence=0.73,
    ),
}


@register_detector
class EIP7702ValidationDetector(Detector):
    name = "eip7702_validation"
    capabilities = [DetectorCategory.EIP7702.value]

    _VALIDATION_FN_RE = re.compile(
        r"function\s+(validateUserOp|validatePaymasterUserOp|validateSignature|"
        r"validateAccount|validateAuthorization)\s*\(",
    )
    _BUNDLER_FN_RE = re.compile(
        r"function\s+(\w*(?:handleOps|validateBatch|acceptUserOp|simulateValidation)\w*)\s*\(",
        re.IGNORECASE,
    )
    _USEROP_RE = re.compile(r"\bUserOperation\b|\bPackedUserOperation\b|\buserOp\b")
    _EIP7702_RE = re.compile(r"7702|authorization|authorizationList|authTuple|delegate", re.IGNORECASE)
    _AUTH_LENGTH_RE = re.compile(
        r"(?:authorizationList|authorizations|authorizationTuples|authTuples)\s*\.length",
        re.IGNORECASE,
    )
    _SENDER_RE = re.compile(r"\.sender\b|sender\s*==|sender\]")
    _NON_SENDER_ENTITY_RE = re.compile(
        r"paymaster|factory|aggregator|signatureAggregator|entity",
        re.IGNORECASE,
    )
    _DELEGATE_CONSISTENCY_RE = re.compile(
        r"delegate(?:Address)?\s*==|sameDelegate|delegateMismatch|senderToDelegate|delegateOfSender",
        re.IGNORECASE,
    )

    _BLOCKED_ENV_PATTERNS = (
        ("ORIGIN", re.compile(r"\btx\.origin\b")),
        ("GASPRICE", re.compile(r"\btx\.gasprice\b")),
        ("BLOCKHASH", re.compile(r"\bblockhash\s*\(")),
        ("COINBASE", re.compile(r"\bblock\.coinbase\b")),
        ("TIMESTAMP", re.compile(r"\bblock\.timestamp\b|\bnow\b")),
        ("NUMBER", re.compile(r"\bblock\.number\b")),
        ("PREVRANDAO", re.compile(r"\bblock\.(?:prevrandao|difficulty)\b")),
        ("GASLIMIT", re.compile(r"\bblock\.gaslimit\b")),
        ("BASEFEE", re.compile(r"\bblock\.basefee\b")),
        ("BLOBHASH", re.compile(r"\bblobhash\s*\(")),
        ("BLOBBASEFEE", re.compile(r"\bblock\.blobbasefee\b")),
        ("SELFDESTRUCT", re.compile(r"\bselfdestruct\s*\(")),
        ("CREATE", re.compile(r"\bnew\s+[A-Z_]\w*\s*\(")),
        ("GAS", re.compile(r"\bgasleft\s*\(")),
    )
    _VALUE_CALL_RE = re.compile(
        r"\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(",
        re.DOTALL,
    )
    _CODE_IDENTITY_RE = re.compile(
        r"\.codehash\b|extcodehash|\.code\.length\b|extcodesize|EXTCODE",
        re.IGNORECASE,
    )
    _CODEHASH_PIN_RE = re.compile(
        r"expectedCodeHash|trustedCodeHash|pinnedCodeHash|knownCodeHash|codehash\s*==",
        re.IGNORECASE,
    )
    _SIGNATURE_CHECK_RE = re.compile(
        r"ECDSA\.recover|ecrecover\s*\(|isValidSignature\s*\(|SignatureChecker|_isValidSignature",
        re.IGNORECASE,
    )
    _USEROP_HASH_RE = re.compile(r"\buserOpHash\b")
    _ENTRYPOINT_GATE_RE = re.compile(
        r"onlyEntryPoint|_requireFromEntryPoint|require\s*\(\s*msg\.sender\s*==\s*(?:address\s*\()?(?:entryPoint|ENTRY_POINT|_entryPoint)",
        re.IGNORECASE,
    )
    _PRE_VERIFICATION_GAS_RE = re.compile(r"\bpreVerificationGas\b")
    _EIP7702_GAS_COST_RE = re.compile(
        r"PER_EMPTY_ACCOUNT_COST|EMPTY_ACCOUNT_COST|25000|25_000",
        re.IGNORECASE,
    )
    _EXTERNAL_VALIDATION_CALL_RE = re.compile(
        r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()|"
        r"\.(?:transfer|send|isValidSignature)\s*\(",
        re.IGNORECASE | re.DOTALL,
    )
    _VALIDATION_MODULE_RE = re.compile(
        r"\bIValidationModule\b|is\s+[^{};]*\bIValidationModule\b",
        re.IGNORECASE,
    )

    def discover(self, ctx) -> bool:
        return ctx.has_solidity

    def scan(self, ctx, opts: ScanOptions) -> ScanResult:
        result = ScanResult(detector_name=self.name)
        findings: List[Finding] = []

        for sol_file in ctx.solidity_files:
            source = _strip_comments(ctx.read_file(sol_file))
            result.files_scanned += 1
            result.lines_scanned += len(source.splitlines())
            findings.extend(self._analyze(source, sol_file, ctx))

        result.findings = findings
        return result

    def _analyze(self, source: str, path: Path, ctx) -> List[Finding]:
        findings: List[Finding] = []
        lines = source.splitlines()
        fname = str(path.relative_to(ctx.root)) if path.is_relative_to(ctx.root) else path.name
        is_validation_module = bool(self._VALIDATION_MODULE_RE.search(source))

        for match in self._VALIDATION_FN_RE.finditer(source):
            fn_name = match.group(1)
            fn_start = source[:match.start()].count("\n")
            fn_body = _extract_fn_body(lines, fn_start)

            findings.extend(self._check_blocked_environment(fn_body, fname, fn_start, fn_name))
            findings.extend(self._check_value_call(fn_body, fname, fn_start, fn_name))
            findings.extend(self._check_code_drift(fn_body, fname, fn_start, fn_name))
            findings.extend(self._check_auth_sender_role(fn_body, fname, fn_start, fn_name))
            findings.extend(self._check_userop_hash_binding(fn_body, fname, fn_start, fn_name))
            findings.extend(
                self._check_entrypoint_gate(
                    fn_body,
                    fname,
                    fn_start,
                    fn_name,
                    is_validation_module=is_validation_module,
                )
            )

        for match in self._BUNDLER_FN_RE.finditer(source):
            fn_name = match.group(1)
            fn_start = source[:match.start()].count("\n")
            fn_body = _extract_fn_body(lines, fn_start)

            findings.extend(self._check_multiple_auth_tuples(fn_body, fname, fn_start, fn_name))
            findings.extend(self._check_delegate_consistency(fn_body, fname, fn_start, fn_name))
            findings.extend(self._check_preverification_gas(fn_body, fname, fn_start, fn_name))

        self._attach_validation_metadata(findings, build_validation_model(source))
        return findings

    def _attach_validation_metadata(self, findings: List[Finding], validation_model: dict) -> None:
        semantic_context = _validation_semantic_context(validation_model)
        for finding in findings:
            metadata = dict(finding.metadata or {})
            metadata["validation_model"] = validation_model
            metadata["semantic_context"] = semantic_context
            metadata["proof_recipe"] = _validation_proof_recipe(
                finding.rule_id,
                validation_model,
            )
            finding.metadata = metadata

    def _check_blocked_environment(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        found = []
        for opcode, pattern in self._BLOCKED_ENV_PATTERNS:
            if pattern.search(fn_body):
                if opcode == "GAS" and _gas_immediately_feeds_call(fn_body, pattern):
                    continue
                found.append(opcode)

        if not found:
            return []

        detail = ", ".join(sorted(set(found)))
        return [
            _finding(
                "AA7562-001",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-001'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` reads ERC-7562 blocked validation data/opcodes: {detail}. "
                    "Bundlers may reject or disagree on this UserOperation during validation."
                ),
                evidence=[fn_name, detail],
            )
        ]

    def _check_value_call(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        if not self._VALUE_CALL_RE.search(fn_body):
            return []
        if "depositTo" in fn_body and "entrypoint" in fn_body.lower():
            return []

        return [
            _finding(
                "AA7562-002",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-002'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` performs a value-bearing call or transfer. ERC-7562 "
                    "forbids CALL with value during validation except narrow EntryPoint cases."
                ),
                evidence=[fn_name, "CALL with value"],
            )
        ]

    def _check_code_drift(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        if not self._CODE_IDENTITY_RE.search(fn_body):
            return []
        if self._CODEHASH_PIN_RE.search(fn_body):
            return []

        return [
            _finding(
                "AA7562-003",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-003'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` checks external code identity without pinning an expected "
                    "codehash. ERC-7562 COD-010 invalidates operations if code changes between validations."
                ),
                evidence=[fn_name, "code identity check without pinned hash"],
            )
        ]

    def _check_multiple_auth_tuples(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        if not (self._USEROP_RE.search(fn_body) and self._EIP7702_RE.search(fn_body)):
            return []
        if not self._AUTH_LENGTH_RE.search(fn_body):
            return []
        if re.search(r"(?:authorizationList|authorizations|authorizationTuples|authTuples)\s*\.length\s*==\s*1", fn_body, re.IGNORECASE):
            return []
        if re.search(r"(?:authorizationList|authorizations|authorizationTuples|authTuples)\s*\.length\s*<=\s*1", fn_body, re.IGNORECASE):
            return []

        return [
            _finding(
                "AA7562-004",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-004'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` handles EIP-7702 authorization arrays without enforcing "
                    "ERC-7562 AUTH-010's single-authorization limit."
                ),
                evidence=[fn_name, "authorization length without == 1"],
            )
        ]

    def _check_auth_sender_role(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        if not self._EIP7702_RE.search(fn_body):
            return []
        if not self._NON_SENDER_ENTITY_RE.search(fn_body):
            return []
        if self._SENDER_RE.search(fn_body) and "sender" in fn_body.lower():
            return []

        return [
            _finding(
                "AA7562-005",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-005'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` appears to validate delegated EIP-7702 authorization for "
                    "a paymaster/factory/aggregator/entity role instead of only the UserOperation sender."
                ),
                evidence=[fn_name, "delegated non-sender entity"],
            )
        ]

    def _check_delegate_consistency(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        if not (self._USEROP_RE.search(fn_body) and self._EIP7702_RE.search(fn_body)):
            return []
        if "for" not in fn_body and "while" not in fn_body:
            return []
        if self._DELEGATE_CONSISTENCY_RE.search(fn_body):
            return []

        return [
            _finding(
                "AA7562-006",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-006'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` processes batched EIP-7702 UserOperations but does not "
                    "check that same-sender operations use the same delegate address."
                ),
                evidence=[fn_name, "batch EIP-7702 UserOperations without same-delegate check"],
            )
        ]

    def _check_userop_hash_binding(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        statements = _body_statements(fn_body)
        if not self._SIGNATURE_CHECK_RE.search(statements):
            return []
        if self._USEROP_HASH_RE.search(statements):
            return []

        return [
            _finding(
                "AA7562-007",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-007'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` performs signature validation without using the "
                    "EntryPoint-supplied userOpHash. The signature may not be bound "
                    "to the full UserOperation, chain, and EntryPoint domain."
                ),
                evidence=[fn_name, "signature check without userOpHash"],
            )
        ]

    def _check_entrypoint_gate(
        self,
        fn_body: str,
        fname: str,
        fn_start: int,
        fn_name: str,
        *,
        is_validation_module: bool = False,
    ) -> Iterable[Finding]:
        if "external" not in fn_body and "public" not in fn_body:
            return []
        if self._ENTRYPOINT_GATE_RE.search(fn_body):
            return []
        if is_validation_module and fn_name in {"validateUserOp", "validateSignature"}:
            return []

        return [
            _finding(
                "AA7562-008",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-008'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` is externally callable and has no clear EntryPoint "
                    "caller gate. Direct callers can exercise validation logic outside "
                    "the intended ERC-4337/7562 sandbox."
                ),
                evidence=[fn_name, "missing EntryPoint caller gate"],
            )
        ]

    def _check_preverification_gas(
        self, fn_body: str, fname: str, fn_start: int, fn_name: str
    ) -> Iterable[Finding]:
        if not self._PRE_VERIFICATION_GAS_RE.search(fn_body):
            return []
        if not self._EIP7702_RE.search(fn_body):
            return []
        if self._EIP7702_GAS_COST_RE.search(fn_body):
            return []

        return [
            _finding(
                "AA7562-009",
                fname,
                fn_start + 1,
                f"{_RULES['AA7562-009'].title} in `{fn_name}`",
                (
                    f"`{fn_name}` accounts for preVerificationGas while handling "
                    "EIP-7702 authorization, but does not include the 25,000 gas "
                    "PER_EMPTY_ACCOUNT_COST per authorization."
                ),
                evidence=[fn_name, "preVerificationGas without PER_EMPTY_ACCOUNT_COST"],
            )
        ]


def build_validation_model(source: str) -> dict:
    clean = _strip_comments(source)
    lines = clean.splitlines()
    detector = EIP7702ValidationDetector()
    state_var_names = _state_variable_names(clean)
    validation_functions = []
    bundler_functions = []

    for match in detector._VALIDATION_FN_RE.finditer(clean):
        fn_name = match.group(1)
        fn_start = clean[:match.start()].count("\n")
        fn_body = _extract_fn_body(lines, fn_start)
        statements = _body_statements(fn_body)
        blocked_ops = [
            opcode for opcode, pattern in detector._BLOCKED_ENV_PATTERNS
            if pattern.search(statements)
        ]
        validation_functions.append({
            "name": fn_name,
            "line": fn_start + 1,
            "entrypoint_gated": bool(detector._ENTRYPOINT_GATE_RE.search(fn_body)),
            "uses_userop_hash": bool(detector._USEROP_HASH_RE.search(statements)),
            "uses_nonce": bool(re.search(r"\b(?:userOp\.)?nonce\b", statements, re.I)),
            "verifies_signature": bool(detector._SIGNATURE_CHECK_RE.search(statements)),
            "blocked_environment_ops": sorted(set(blocked_ops)),
            "value_call": bool(detector._VALUE_CALL_RE.search(statements)),
            "code_identity_read": bool(detector._CODE_IDENTITY_RE.search(statements)),
            "codehash_pinned": bool(detector._CODEHASH_PIN_RE.search(statements)),
            "external_calls": _external_validation_calls(statements, detector),
            "mutable_state_writes": _mutable_state_writes(statements, state_var_names),
            "declared_view_or_pure": bool(re.search(r"\b(view|pure)\b", fn_body)),
        })

    for match in detector._BUNDLER_FN_RE.finditer(clean):
        fn_name = match.group(1)
        fn_start = clean[:match.start()].count("\n")
        fn_body = _extract_fn_body(lines, fn_start)
        statements = _body_statements(fn_body)
        handles_eip7702 = bool(detector._USEROP_RE.search(statements) and detector._EIP7702_RE.search(statements))
        auth_length = bool(detector._AUTH_LENGTH_RE.search(statements))
        bundler_functions.append({
            "name": fn_name,
            "line": fn_start + 1,
            "handles_eip7702_authorization": handles_eip7702,
            "checks_single_authorization": bool(
                auth_length and re.search(
                    r"(?:authorizationList|authorizations|authorizationTuples|authTuples)"
                    r"\s*\.length\s*(?:==|<=)\s*1",
                    statements,
                    re.I,
                )
            ),
            "checks_delegate_consistency": bool(detector._DELEGATE_CONSISTENCY_RE.search(statements)),
            "uses_preverification_gas": bool(detector._PRE_VERIFICATION_GAS_RE.search(statements)),
            "includes_7702_gas_cost": bool(detector._EIP7702_GAS_COST_RE.search(statements)),
        })

    missing = _validation_missing_bindings(validation_functions)
    return {
        "analysis": "erc7562_validation_model",
        "validation_functions": validation_functions,
        "bundler_functions": bundler_functions,
        "has_validate_userop": any(fn["name"] == "validateUserOp" for fn in validation_functions),
        "ungated_validation_functions": [
            fn["name"] for fn in validation_functions if not fn["entrypoint_gated"]
        ],
        "blocked_environment_ops": sorted({
            opcode
            for fn in validation_functions
            for opcode in fn["blocked_environment_ops"]
        }),
        "value_call_functions": [
            fn["name"] for fn in validation_functions if fn["value_call"]
        ],
        "external_call_functions": [
            fn["name"] for fn in validation_functions if fn["external_calls"]
        ],
        "mutable_state_write_functions": [
            fn["name"] for fn in validation_functions if fn["mutable_state_writes"]
        ],
        "missing_userop_bindings": missing,
    }


def _external_validation_calls(statements: str, detector: EIP7702ValidationDetector) -> list[str]:
    calls = []
    for match in detector._EXTERNAL_VALIDATION_CALL_RE.finditer(statements):
        calls.append(match.group(0).split("(", 1)[0].strip())
    return sorted(set(calls))


def _state_variable_names(source: str) -> set[str]:
    names: set[str] = set()
    depth = 0
    statement_start = 0
    for idx, char in enumerate(source):
        if char == "{":
            depth += 1
            statement_start = idx + 1
            continue
        if char == "}":
            depth = max(0, depth - 1)
            statement_start = idx + 1
            continue
        if char != ";" or depth != 1:
            continue
        statement = source[statement_start:idx + 1].strip()
        statement_start = idx + 1
        match = re.match(
            r"(?:mapping\s*\([^;]+\)|address|uint\d*|int\d*|bool|bytes\d*|string)"
            r"\s+(?:(?:public|private|internal|constant|immutable)\s+)*([A-Za-z_]\w*)\s*(?:=|;)",
            statement,
            re.S,
        )
        if match and "constant" not in statement and "immutable" not in statement:
            names.add(match.group(1))
    return names


def _mutable_state_writes(statements: str, state_var_names: set[str]) -> list[str]:
    writes = []
    if re.search(r"\bsstore\s*\(", statements, re.I):
        writes.append("sstore")
    for name in state_var_names:
        if re.search(rf"(?:^|[^\w.]){re.escape(name)}\s*(?:=|\+=|-=|\+\+|--|\[)", statements, re.I | re.M):
            writes.append(name)
    return sorted(set(writes))


def _validation_missing_bindings(validation_functions: list[dict]) -> list[str]:
    validate_userop = [
        fn for fn in validation_functions if fn["name"] == "validateUserOp"
    ]
    if not validate_userop:
        return []
    missing = []
    if not any(fn["uses_userop_hash"] for fn in validate_userop):
        missing.append("userOpHash")
    if not any(fn["uses_nonce"] for fn in validate_userop):
        missing.append("nonce")
    if not any(fn["entrypoint_gated"] for fn in validate_userop):
        missing.append("entryPoint")
    if not any(fn["verifies_signature"] for fn in validate_userop):
        missing.append("signature_verification")
    return missing


def _validation_semantic_context(validation_model: dict) -> dict:
    missing = list(validation_model.get("missing_userop_bindings") or [])
    return {
        "analysis": validation_model.get("analysis", "erc7562_validation_model"),
        "has_validate_userop": bool(validation_model.get("has_validate_userop")),
        "validation_model": validation_model,
        "userop_model": {
            "has_validate_userop": bool(validation_model.get("has_validate_userop")),
            "binds_userop_hash": "userOpHash" not in missing,
            "binds_nonce": "nonce" not in missing,
            "binds_entrypoint": "entryPoint" not in missing,
            "verifies_signature": "signature_verification" not in missing,
            "missing": missing,
            "blocked_environment_ops": validation_model.get("blocked_environment_ops", []),
            "value_call_functions": validation_model.get("value_call_functions", []),
            "external_call_functions": validation_model.get("external_call_functions", []),
            "mutable_state_write_functions": validation_model.get("mutable_state_write_functions", []),
        },
    }


def _validation_proof_recipe(rule_id: str, validation_model: dict) -> dict:
    rule = _RULES.get(rule_id)
    objective = (
        rule.assumption if rule is not None
        else "confirm or refute the validation finding with a UserOperation harness"
    )
    return {
        "check_id": rule_id,
        "status": "needs_dynamic_confirmation",
        "proof_status": "STATIC_CANDIDATE",
        "readiness": "userop_harness_candidate",
        "kind": "userop_validation_review",
        "objective": objective,
        "auto_poc_status": "manual_userop_fixture_needed",
        "semantic": _validation_semantic_context(validation_model),
        "proof_ladder": [
            "static_validation_signal",
            "validation_semantic_model",
            "userop_mutation_harness",
            "confirmed_or_refuted_evidence",
        ],
    }


def _finding(
    rule_id: str,
    file_path: str,
    line: int,
    title: str,
    description: str,
    *,
    evidence: list[str],
) -> Finding:
    rule = _RULES[rule_id]
    policy_rule = _POLICY.to_dict().get(rule.boundary, "")
    trace = PreBehaviorTrace(
        assumptions_detected=(rule.assumption,),
        delegated_behavior_possible=(rule.delegated_behavior,),
        violated_sandbox_rule=policy_rule,
        violated_boundary=rule.boundary,
        evidence=tuple([rule.rule_id, rule.erc7562_rule, *evidence]),
        confidence=rule.confidence,
        bypass_class=rule.bypass_class,
        policy=_POLICY,
    )
    return Finding(
        detector="eip7702_validation",
        rule_id=rule.rule_id,
        severity=rule.severity,
        title=title,
        description=description,
        file_path=file_path,
        line=line,
        category=DetectorCategory.EIP7702.value,
        cwe="CWE-345",
        confidence=rule.confidence,
        fix_suggestion=rule.fix,
        metadata={
            "standard": "ERC-7562",
            "erc7562_rule": rule.erc7562_rule,
            "sandbox_boundary": rule.boundary,
            "sandbox_bypass_class": rule.bypass_class,
            "sandbox_policy": _POLICY.to_dict(),
            "pre_behavior_trace": trace.to_dict(),
        },
    )


def _strip_comments(source: str) -> str:
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return source


def _extract_fn_body(lines: list[str], start_line: int, max_lines: int = 220) -> str:
    depth = 0
    body_lines = []
    started = False
    for i in range(start_line, min(start_line + max_lines, len(lines))):
        line = lines[i]
        body_lines.append(line)
        if "{" in line:
            depth += line.count("{")
            started = True
        if "}" in line:
            depth -= line.count("}")
        if started and depth <= 0:
            break
    return "\n".join(body_lines)


def _body_statements(fn_body: str) -> str:
    body_start = fn_body.find("{")
    if body_start == -1:
        return fn_body
    return fn_body[body_start + 1:]


def _gas_immediately_feeds_call(fn_body: str, pattern: re.Pattern) -> bool:
    match = pattern.search(fn_body)
    if not match:
        return False
    tail = fn_body[match.end():match.end() + 120]
    return bool(re.search(r"\.(?:call|staticcall|delegatecall)\s*\(", tail))
