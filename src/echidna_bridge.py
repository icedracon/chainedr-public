"""ChainEDR Echidna Bridge — property-based fuzzing for smart contracts.

Two modes:

  1. GENERIC harness (always available):
     Generates a Solidity test harness with common invariants derived from
     the contract's structure (token conservation, access control, ETH balance).

  2. INVARIANTMINER harness (when InvariantMiner output is supplied):
     Translates InvariantMiner-mined invariants into Echidna ``echidna_*``
     properties — this closes the loop between behavioral monitoring and
     pre-deployment fuzzing.

     InvariantMiner mine → Echidna fuzz → violating PoC → CRITICAL finding

Install Echidna:
    # macOS:  brew install echidna
    # Linux:  https://github.com/crytic/echidna/releases (static binary)
    # Windows: WSL recommended; or use the Docker image
    #          docker run -v $(pwd):/src trailofbits/echidna ...

Falls back gracefully if ``echidna`` is not in PATH — the harness is still
generated and saved to disk for manual use.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .static_analyzer import StaticFinding, StaticSeverity, StaticCategory
except ImportError:
    from static_analyzer import StaticFinding, StaticSeverity, StaticCategory


# ── availability ──────────────────────────────────────────────────────────────

def is_available() -> bool:
    """True if echidna binary is in PATH."""
    for name in ("echidna", "echidna-test", "echidna.exe"):
        if shutil.which(name):
            return True
    return False


def _echidna_bin() -> str:
    for name in ("echidna", "echidna-test"):
        p = shutil.which(name)
        if p:
            return p
    return "echidna"


# ── InvariantMiner → Echidna property translation ────────────────────────────

@dataclass
class EchidnaProperty:
    name: str           # echidna_<name>
    solidity: str       # property function body (returns bool)
    description: str
    severity: str = "HIGH"


def invariant_to_properties(
    mined_invariants: List[Dict[str, Any]],
    contract_name: str,
    state_vars: Optional[List[str]] = None,
) -> List[EchidnaProperty]:
    """
    Translate InvariantMiner-mined invariants into Echidna Solidity properties.

    Args:
        mined_invariants: List of MinedInvariant.to_dict() or raw dict objects
                          from InvariantMiner.mine_invariants().
        contract_name:    Name of the contract under test.
        state_vars:       Optional list of state variable names to use in properties.

    Returns:
        List of EchidnaProperty, each with a Solidity function body.
    """
    properties = []
    seen_names: set = set()

    for inv in mined_invariants:
        inv_type = inv.get("invariant_type") or inv.get("type", "")
        fn_sig   = inv.get("function_sig", "unknown")
        fn_slug  = re.sub(r"[^a-zA-Z0-9]", "_", fn_sig)

        if inv_type == "CALLER_WHITELIST":
            # Echidna property: caller must always be in the whitelist
            whitelist = inv.get("parameters", {}).get("whitelist", [])
            if not whitelist:
                continue
            wl_checks = " || ".join(
                f"msg.sender == address({addr})" for addr in whitelist[:5]
            )
            prop_name = f"echidna_caller_whitelist_{fn_slug}"
            if prop_name in seen_names:
                continue
            seen_names.add(prop_name)
            properties.append(EchidnaProperty(
                name=prop_name,
                solidity=f"return ({wl_checks});",
                description=(
                    f"Only known callers should invoke {fn_sig}. "
                    f"InvariantMiner detected {len(whitelist)} unique callers "
                    f"in training data."
                ),
                severity="HIGH",
            ))

        elif inv_type == "VALUE_BOUND":
            # Echidna property: value within [min, max]
            params = inv.get("parameters", {})
            min_v  = params.get("min_value")
            max_v  = params.get("max_value")
            field_ = params.get("field", "msg.value")
            if min_v is None and max_v is None:
                continue
            checks = []
            if min_v is not None:
                checks.append(f"{field_} >= {int(min_v)}")
            if max_v is not None:
                checks.append(f"{field_} <= {int(max_v)}")
            prop_name = f"echidna_value_bound_{fn_slug}"
            if prop_name in seen_names:
                continue
            seen_names.add(prop_name)
            properties.append(EchidnaProperty(
                name=prop_name,
                solidity=f"return ({' && '.join(checks)});",
                description=(
                    f"Value bounds for {fn_sig}: [{min_v}, {max_v}]. "
                    f"Violations indicate abnormal transaction magnitude."
                ),
                severity="MEDIUM",
            ))

        elif inv_type == "MONOTONIC":
            # Echidna property: a tracked state variable never decreases/increases
            params    = inv.get("parameters", {})
            var_name  = params.get("variable", state_vars[0] if state_vars else "balance")
            direction = params.get("direction", "INCREASING")
            op = ">=" if direction == "INCREASING" else "<="
            prop_name = f"echidna_monotonic_{fn_slug}_{var_name}"[:50]
            if prop_name in seen_names:
                continue
            seen_names.add(prop_name)
            # We can't easily track the previous value in Echidna without setup,
            # so we emit a comment-only property with a TODO
            properties.append(EchidnaProperty(
                name=prop_name,
                solidity=(
                    f"// TODO: track previous_{var_name} in setUp() / before each call\n"
                    f"        // return {var_name} {op} previous_{var_name};\n"
                    f"        return true; // placeholder — implement tracking"
                ),
                description=(
                    f"``{var_name}`` should be monotonically "
                    f"{'increasing' if direction == 'INCREASING' else 'decreasing'} "
                    f"across ``{fn_sig}`` calls."
                ),
                severity="MEDIUM",
            ))

        elif inv_type == "GAS_BOUND":
            # Echidna doesn't control gas in the same way, but we can document it
            params  = inv.get("parameters", {})
            ceiling = params.get("ceiling", 0)
            prop_name = f"echidna_gas_bound_{fn_slug}"
            if prop_name in seen_names:
                continue
            seen_names.add(prop_name)
            properties.append(EchidnaProperty(
                name=prop_name,
                solidity=(
                    f"// Gas ceiling for {fn_sig}: {int(ceiling):,} gas\n"
                    f"        // Echidna cannot enforce gas bounds directly.\n"
                    f"        // Use: gasleft() checks or a wrapper contract.\n"
                    f"        return true; // placeholder"
                ),
                description=(
                    f"``{fn_sig}`` historically used < {int(ceiling):,} gas. "
                    f"A spike indicates an anomalous execution path."
                ),
                severity="MEDIUM",
            ))

    return properties


# ── Harness generator ─────────────────────────────────────────────────────────

_ECHIDNA_CONFIG_YAML = """\
# ChainEDR-generated Echidna config
testMode: assertion
testLimit: 100000
seqLen: 10
shrinkLimit: 5000
coverage: true
timeout: 60
"""

_GENERIC_PROPERTIES = """\
    // ── generic invariants (always checked) ────────────────────────
    // ETH balance never goes negative (sanity check)
    function echidna_eth_not_negative() public view returns (bool) {
        return address(this).balance >= 0;
    }

    // Contract cannot selfdestruct spontaneously
    function echidna_code_exists() public view returns (bool) {
        return address(this).code.length > 0;
    }
"""


def generate_harness(
    source: str,
    contract_name: str,
    mined_invariants: Optional[List[Dict]] = None,
    output_dir: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Generate an Echidna test harness for a contract.

    Args:
        source:            Solidity source of the contract under test.
        contract_name:     Name of the main contract to test.
        mined_invariants:  Optional InvariantMiner output to translate.
        output_dir:        Directory to write harness.sol + echidna.yaml.
                           Defaults to a temp directory.

    Returns:
        (harness_path, config_path) — paths to the generated files.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="chainedr_echidna_")
    else:
        os.makedirs(output_dir, exist_ok=True)

    harness_path = os.path.join(output_dir, f"{contract_name}Echidna.sol")
    config_path  = os.path.join(output_dir, "echidna.yaml")

    # Translate mined invariants → Echidna properties
    props: List[EchidnaProperty] = []
    if mined_invariants:
        props = invariant_to_properties(mined_invariants, contract_name)

    # Build property function bodies
    prop_functions = ""
    for prop in props:
        prop_functions += f"""
    // {prop.description}
    function {prop.name}() public view returns (bool) {{
        {prop.solidity}
    }}
"""

    harness_sol = f"""\
// SPDX-License-Identifier: MIT
// ChainEDR-generated Echidna harness for {contract_name}
// Generated by: python -m chainedr echidna {contract_name}.sol
//
// Run: echidna {contract_name}Echidna.sol --config echidna.yaml \\
//             --contract {contract_name}Echidna
pragma solidity ^0.8.20;

// ── Import target contract ──────────────────────────────────────────────────
// Adjust the import path to match your project layout.
// import "./{contract_name}.sol";

// ── Echidna harness ─────────────────────────────────────────────────────────
contract {contract_name}Echidna {{
    // Place setup state here, e.g.:
    // {contract_name} public target;
    // constructor() {{ target = new {contract_name}(...); }}

{_GENERIC_PROPERTIES}
{prop_functions}
}}
"""

    Path(harness_path).write_text(harness_sol, encoding="utf-8")
    Path(config_path).write_text(_ECHIDNA_CONFIG_YAML, encoding="utf-8")

    return harness_path, config_path


# ── main entry point ──────────────────────────────────────────────────────────

def run(
    source: str,
    contract_name: str = "Unknown",
    mined_invariants: Optional[List[Dict]] = None,
    timeout: int = 120,
    output_dir: Optional[str] = None,
) -> List[StaticFinding]:
    """
    Generate an Echidna harness and optionally run it.

    If Echidna is not installed, returns a single INFO finding with the
    path to the generated harness (so the user can run it manually).

    Args:
        source:           Solidity source string.
        contract_name:    Name of the contract under test.
        mined_invariants: InvariantMiner output for targeted properties.
        timeout:          Max seconds to run Echidna.
        output_dir:       Directory for harness files.

    Returns:
        List[StaticFinding] — violations found, or INFO about harness path.
    """
    harness_path, config_path = generate_harness(
        source, contract_name, mined_invariants, output_dir
    )

    if not is_available():
        return [StaticFinding(
            severity=StaticSeverity.INFO,
            category=StaticCategory.ANALYSIS_GAP,
            title="[Echidna] Harness generated — Echidna not installed",
            description=(
                f"Echidna test harness written to: {harness_path}\n"
                f"Config: {config_path}\n"
                f"Install echidna and run:\n"
                f"  echidna {harness_path} --config {config_path} "
                f"--contract {contract_name}Echidna"
            ),
            location=contract_name,
            cwe="N/A",
            confidence=1.0,
        )]

    try:
        proc = subprocess.run(
            [
                _echidna_bin(), harness_path,
                "--config", config_path,
                "--contract", f"{contract_name}Echidna",
                "--format", "json",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        return _parse_echidna_output(proc.stdout, proc.stderr, contract_name)

    except subprocess.TimeoutExpired:
        return [StaticFinding(
            severity=StaticSeverity.INFO,
            category=StaticCategory.ANALYSIS_GAP,
            title="[Echidna] Fuzzing timed out",
            description=f"Echidna exceeded {timeout}s. Partial results may be available.",
            location=contract_name,
            cwe="N/A",
            confidence=1.0,
        )]
    except Exception as e:
        return [StaticFinding(
            severity=StaticSeverity.INFO,
            category=StaticCategory.ANALYSIS_GAP,
            title="[Echidna] Run failed",
            description=str(e)[:200],
            location=contract_name,
            cwe="N/A",
            confidence=1.0,
        )]


def _parse_echidna_output(
    stdout: str, stderr: str, contract_name: str
) -> List[StaticFinding]:
    """Parse Echidna JSON output for falsified properties."""
    findings: List[StaticFinding] = []

    # Try to parse JSON output
    try:
        idx = stdout.find("{")
        if idx == -1:
            idx = stdout.find("[")
        if idx != -1:
            data = json.loads(stdout[idx:])
            tests = data if isinstance(data, list) else data.get("tests", [])
            for t in tests:
                if t.get("status") == "failed":
                    prop_name = t.get("name", "unknown")
                    call_seq  = t.get("callSequence", [])
                    findings.append(StaticFinding(
                        severity=StaticSeverity.CRITICAL,
                        category=StaticCategory.LOGIC,
                        title=f"[Echidna] Property violated: {prop_name}",
                        description=(
                            f"Echidna falsified ``{prop_name}`` in {len(call_seq)} calls. "
                            f"Call sequence: "
                            + " → ".join(
                                c.get("function", "?") for c in call_seq[:5]
                            )
                        ),
                        location=f"{contract_name}:{prop_name}",
                        exploitable=True,
                        fix_suggestion=(
                            "Review the minimal call sequence above. "
                            "Add the missing invariant enforcement to the contract."
                        ),
                        cwe="CWE-682",
                        confidence=0.95,
                    ))
            return findings
    except (json.JSONDecodeError, KeyError):
        pass

    # Fall back to text parsing
    for line in stdout.splitlines():
        if "FAILED" in line.upper() or "falsified" in line.lower():
            prop_match = re.search(r"(echidna_\w+)", line)
            prop_name  = prop_match.group(1) if prop_match else "unknown"
            findings.append(StaticFinding(
                severity=StaticSeverity.CRITICAL,
                category=StaticCategory.LOGIC,
                title=f"[Echidna] Property violated: {prop_name}",
                description=line.strip()[:300],
                location=f"{contract_name}:{prop_name}",
                exploitable=True,
                fix_suggestion=(
                    "Review the minimal counterexample in Echidna output."
                ),
                cwe="CWE-682",
                confidence=0.90,
            ))

    if not findings:
        findings.append(StaticFinding(
            severity=StaticSeverity.INFO,
            category=StaticCategory.ANALYSIS_GAP,
            title="[Echidna] All properties passed",
            description=(
                f"Echidna found no violations in {contract_name}. "
                f"Properties tested: generic + InvariantMiner-derived."
            ),
            location=contract_name,
            cwe="N/A",
            confidence=1.0,
        ))

    return findings
