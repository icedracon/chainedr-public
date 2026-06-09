"""
ChainEDR — Pyrometer Bridge

Pyrometer (by Nascent) does value-range analysis — tracks what values a
variable CAN hold at every program point. Catches:
  - Integer overflow/underflow when SafeMath is absent
  - Division by zero when denominator can be 0
  - Array out-of-bounds when index is unbounded
  - Reachability of assumed-impossible branches

Install: cargo install pyrometer
Docs:    https://github.com/nascentxyz/pyrometer

JSON output schema (pyrometer analyze --output-format json):
  {
    "analyses": [{
      "contract":  str,
      "function":  str,
      "issue":     str,
      "severity":  "Critical"|"High"|"Medium"|"Low"|"Informational",
      "range":     str,   // value range that triggered the issue
      "location":  {"file": str, "line": int, "col": int}
    }]
  }

Note: Schema is provisional — Pyrometer is pre-1.0 and output format may
change. The bridge validates required keys before normalizing.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("chainedr.pyrometer")

MIN_VERSION = (0, 1, 0)

_IMPACT_MAP: Dict[str, str] = {
    "critical":      "CRITICAL",
    "high":          "HIGH",
    "medium":        "MEDIUM",
    "low":           "LOW",
    "informational": "INFO",
}


def _pyrometer_available() -> bool:
    if not shutil.which("pyrometer"):
        logger.info(
            "pyrometer not found — skipping (cargo install pyrometer)"
        )
        return False
    try:
        out = subprocess.run(
            ["pyrometer", "--version"],
            capture_output=True, text=True, timeout=10
        )
        raw = out.stdout.strip().split()[-1].lstrip("v")
        ver = tuple(int(x) for x in raw.split(".")[:3])
        if ver < MIN_VERSION:
            logger.warning("pyrometer %s < min %s — skipping", raw, MIN_VERSION)
            return False
        return True
    except Exception as e:
        logger.info("pyrometer version check: %s", e)
        return False


def run_pyrometer(directory: str) -> List[Dict[str, Any]]:
    """
    Run Pyrometer value-range analysis on `directory`.
    Returns normalized finding dicts.
    """
    if not _pyrometer_available():
        return []

    # Pyrometer operates on files or directories
    cmd = ["pyrometer", "analyze", "--output-format", "json", directory]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode not in (0, 1):
            logger.warning(
                "pyrometer exited %d: %s",
                result.returncode,
                result.stderr[:300],
            )
            return []
    except subprocess.TimeoutExpired:
        logger.warning("pyrometer timed out on %s", directory)
        return []
    except Exception as e:
        logger.warning("pyrometer failed: %s", e)
        return []

    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except Exception as e:
        logger.warning("pyrometer JSON parse error: %s", e)
        return []

    return _normalize(data)


def _normalize(data: dict) -> List[Dict[str, Any]]:
    findings = []
    for item in data.get("analyses", []):
        if not isinstance(item, dict):
            continue

        # Validate required keys — schema may drift across versions
        if not all(k in item for k in ("issue", "severity")):
            logger.debug("pyrometer item missing required keys: %s", item)
            continue

        sev_raw  = item.get("severity", "medium").lower()
        contract = item.get("contract", "")
        function = item.get("function", "")
        issue    = item.get("issue", "")
        rng      = item.get("range", "")
        loc      = item.get("location", {})

        file_path = loc.get("file", "")
        line_no   = loc.get("line", 0)
        location  = f"{file_path}:{line_no}" if file_path else (contract or "unknown")

        description = issue
        if rng:
            description += f"\n\nValue range: {rng}"
        if function:
            description = f"{function}(): {description}"

        fingerprint = f"pyrometer:{issue[:60]}:{file_path}:{line_no}"

        findings.append({
            "source":      "pyrometer",
            "title":       f"[Pyrometer] {issue[:120]}",
            "severity":    _IMPACT_MAP.get(sev_raw, "MEDIUM"),
            "confidence":  0.80,   # value-range analysis has low FP rate
            "location":    location,
            "description": description,
            "exploitable": sev_raw in ("critical", "high"),
            "fingerprint": fingerprint,
        })

    return findings


def pyrometer_to_static_findings(directory: str):
    """Returns StaticFinding objects for direct append to result.findings."""
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
    for f in run_pyrometer(directory):
        out.append(StaticFinding(
            severity=_sev.get(f["severity"], StaticSeverity.MEDIUM),
            category=StaticCategory.PRECISION,   # value-range = arithmetic class
            title=f["title"],
            description=f["description"],
            location=f["location"],
            exploitable=f["exploitable"],
            confidence=f["confidence"],
            cwe="CWE-682",
            fix_suggestion=(
                "Use SafeMath or Solidity 0.8+ checked arithmetic. "
                "Add explicit bounds validation for identified range."
            ),
        ))
    return out
