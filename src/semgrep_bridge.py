"""
ChainEDR — Semgrep Bridge

Runs Semgrep with security-focused Solidity rulesets and normalizes output
into ChainEDR's StaticFinding format.

Rulesets (tried in priority order, first that produces results wins):
  1. Local rules file  (chainedr/data/semgrep_rules.yaml) — offline, fastest
  2. p/smart-contracts — official Semgrep Solidity rules
  3. p/solidity        — community Solidity rules

Semgrep exits 0 (no findings) or 1 (findings found) — both are normal.
Exit 2+ means real error.

JSON schema (semgrep --json):
  {
    "results": [{
      "check_id":  "ruleset.rule-id",
      "path":      "contracts/Foo.sol",
      "start":     {"line": 42, "col": 5, ...},
      "end":       {"line": 44, "col": 10, ...},
      "extra": {
        "message":  str,
        "severity": "ERROR"|"WARNING"|"INFO",
        "metadata": {"cwe": [...], "confidence": "HIGH"|"MEDIUM"|"LOW", ...},
        "lines":    str   // source snippet
      }
    }],
    "errors": [...]
  }
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("chainedr.semgrep")

# Ruleset priority: local file → remote sets
_RULESETS = [
    str(Path(__file__).parent / "data" / "semgrep_rules.yaml"),  # local first
    "p/smart-contracts",
    "p/solidity",
]

# Semgrep severity → ChainEDR severity
# smart-contracts ruleset marks gas findings as INFO — we keep them only if
# they're also security relevant (has CWE). Pure gas/style is dropped.
_SEV_MAP: Dict[str, str] = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}

# Rule IDs that are pure style/gas — not security findings, skip them
_STYLE_RULES: frozenset = frozenset({
    "use-custom-error-not-require",
    "use-short-revert-string",
    "non-payable-constructor",
    "use-scientific-notation",
    "constants-instead-of-literals",
    "use-string-error",
    "missing-zero-check",          # too noisy, low signal
    "unindexed-events",
})


def _semgrep_available() -> bool:
    if not shutil.which("semgrep"):
        logger.info("semgrep not found — skipping (pip install semgrep)")
        return False
    return True


def _pick_ruleset() -> str | None:
    """Return first available ruleset (local file exists, or use remote id)."""
    for rs in _RULESETS:
        if rs.endswith(".yaml") or rs.endswith(".yml"):
            if Path(rs).exists():
                return rs
            continue   # local file missing — try next
        return rs      # remote ruleset id — always try
    return None


def run_semgrep(
    directory: str,
    min_severity: str = "WARNING",   # ERROR | WARNING | INFO
) -> List[Dict[str, Any]]:
    """
    Run Semgrep on `directory`, return normalized finding dicts.

    Each dict:
      source, title, severity, confidence, location, description,
      cwe, fingerprint
    """
    if not _semgrep_available():
        return []

    ruleset = _pick_ruleset()
    if ruleset is None:
        logger.warning("semgrep: no ruleset available")
        return []

    cmd = [
        "semgrep",
        "--config", ruleset,
        "--json",
        "--quiet",
        "--no-git-ignore",
        directory,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
        # 0 = clean, 1 = findings, 2+ = error
        if result.returncode >= 2:
            logger.warning(
                "semgrep error (exit %d): %s",
                result.returncode,
                result.stderr[:300],
            )
            return []
    except subprocess.TimeoutExpired:
        logger.warning("semgrep timed out on %s", directory)
        return []
    except Exception as e:
        logger.warning("semgrep failed: %s", e)
        return []

    if not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except Exception as e:
        logger.warning("semgrep JSON parse error: %s", e)
        return []

    return _normalize(data, min_severity)


def _normalize(data: dict, min_severity: str = "WARNING") -> List[Dict[str, Any]]:
    _sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    min_rank  = _sev_rank.get(min_severity, 1)

    findings = []
    for item in data.get("results", []):
        extra    = item.get("extra", {})
        raw_sev  = extra.get("severity", "WARNING").upper()
        check_id = item.get("check_id", "")
        rule_id  = check_id.split(".")[-1]  # strip ruleset prefix

        # Drop pure style rules
        if rule_id in _STYLE_RULES:
            continue

        # Severity filter
        if _sev_rank.get(raw_sev, 99) > min_rank:
            continue

        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else ""
        conf_raw = metadata.get("confidence", "MEDIUM").upper()
        conf_map = {"HIGH": 0.85, "MEDIUM": 0.65, "LOW": 0.40}

        path     = item.get("path", "")
        start_ln = item.get("start", {}).get("line", 0)
        message  = extra.get("message", "")
        snippet  = extra.get("lines", "").strip()[:200]

        location = f"{path}:{start_ln}"
        description = message
        if snippet:
            description += f"\n\nSource:\n{snippet}"

        findings.append({
            "source":      "semgrep",
            "title":       f"[Semgrep/{rule_id}] {message[:100]}",
            "severity":    _SEV_MAP.get(raw_sev, "MEDIUM"),
            "confidence":  conf_map.get(conf_raw, 0.65),
            "location":    location,
            "description": description,
            "exploitable": raw_sev == "ERROR",
            "cwe":         cwe,
            "fingerprint": f"semgrep:{check_id}:{path}:{start_ln}",
        })

    return findings


def semgrep_to_static_findings(directory: str):
    """
    Convenience wrapper — returns StaticFinding objects for direct append.
    """
    try:
        from .static_analyzer import StaticFinding, StaticSeverity, StaticCategory
    except ImportError:
        return []

    _sev = {
        "CRITICAL": StaticSeverity.CRITICAL,
        "HIGH":     StaticSeverity.HIGH,
        "MEDIUM":   StaticSeverity.MEDIUM,
        "LOW":      StaticSeverity.LOW,
        "INFO":     StaticSeverity.INFO,
    }

    out = []
    for f in run_semgrep(directory):
        out.append(StaticFinding(
            severity=_sev.get(f["severity"], StaticSeverity.MEDIUM),
            category=StaticCategory.LOGIC,
            title=f["title"],
            description=f["description"],
            location=f["location"],
            exploitable=f["exploitable"],
            confidence=f["confidence"],
            cwe=f.get("cwe", ""),
            fix_suggestion="",
        ))
    return out
