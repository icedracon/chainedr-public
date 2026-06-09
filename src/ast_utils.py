"""
solc-AST utilities — the foundation for moving EIP-7702 checks from regex toward
semantic analysis (Tier 2).

Regex is brittle: it can't tell an interface from a contract with multi-line
signatures, a constructor-time `code.length` check from a runtime one, or a
contract that namespaces storage via ERC-7201. The AST can.

This module is *additive*: it compiles a source with solc and extracts
structural facts. Detectors can consult it for high-confidence signals and fall
back to regex when solc is unavailable, so the existing pipeline is never
weakened (benchmark recall stays intact).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field


def solc_available() -> bool:
    return shutil.which("solc") is not None


def compile_ast(source: str, solc: str = "solc") -> dict | None:
    """Return the compact-JSON AST for `source`, or None if solc is unavailable
    or compilation fails (caller should fall back to regex)."""
    if not (shutil.which(solc) or solc != "solc"):
        return None
    try:
        proc = subprocess.run(
            [solc, "--combined-json", "ast", "-"],
            input=source.encode(), capture_output=True, timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        data = json.loads(proc.stdout)
        # {"sources": {"<stdin>": {"AST": {...}}}}
        for _, s in data.get("sources", {}).items():
            ast = s.get("AST") or s.get("ast")
            if ast:
                return ast
    except Exception:
        return None
    return None


@dataclass
class ContractFacts:
    name: str
    kind: str                       # "contract" | "interface" | "library"
    abstract: bool = False
    has_function_body: bool = False
    uses_erc7201: bool = False      # @custom:storage-location erc7201 annotation
    verifies_signatures: bool = False
    reads_code_length: bool = False


_SIG_FNS = {"ecrecover", "isValidSignature", "tryRecover", "recover"}


def _walk(node, fn):
    if isinstance(node, dict):
        fn(node)
        for v in node.values():
            _walk(v, fn)
    elif isinstance(node, list):
        for v in node:
            _walk(v, fn)


def extract_facts(source: str, solc: str = "solc") -> list[ContractFacts]:
    """Structural facts per contract via AST. Empty list if AST unavailable."""
    ast = compile_ast(source, solc)
    if not ast:
        return []
    out: list[ContractFacts] = []
    for node in ast.get("nodes", []):
        if node.get("nodeType") != "ContractDefinition":
            continue
        cf = ContractFacts(
            name=node.get("name", "?"),
            kind=node.get("contractKind", "contract"),
            abstract=bool(node.get("abstract", False)),
        )
        # storage-location annotation lives in structured documentation
        doc = (node.get("documentation") or {})
        doctext = doc.get("text", "") if isinstance(doc, dict) else str(doc or "")
        if "erc7201" in doctext.lower() or "storage-location" in doctext.lower():
            cf.uses_erc7201 = True

        def visit(n):
            nt = n.get("nodeType")
            if nt == "FunctionDefinition" and n.get("body"):
                cf.has_function_body = True
            if nt == "StructDefinition":
                sd = (n.get("documentation") or {})
                t = sd.get("text", "") if isinstance(sd, dict) else str(sd or "")
                if "erc7201" in t.lower():
                    cf.uses_erc7201 = True
            if nt in ("Identifier", "MemberAccess"):
                nm = n.get("name") or n.get("memberName") or ""
                if nm in _SIG_FNS:
                    cf.verifies_signatures = True
                if nm == "code":
                    cf.reads_code_length = True

        _walk(node, visit)
        out.append(cf)
    return out


def is_interface_file_ast(source: str, solc: str = "solc") -> bool | None:
    """AST-based interface detection. Returns True/False, or None if AST
    unavailable (caller falls back to the regex heuristic)."""
    facts = extract_facts(source, solc)
    if not facts:
        return None
    # interface-only: at least one declaration, none concrete-with-body
    if any(f.kind in ("contract", "library") and f.has_function_body for f in facts):
        return False
    return all(f.kind == "interface" for f in facts) and len(facts) > 0
