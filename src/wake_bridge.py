"""
ChainEDR — Wake Bridge

Runs Ackee Blockchain's Wake detector suite (eth-wake) and normalizes
findings into ChainEDR's StaticFinding format.

Wake is Python-native (pip install eth-wake) and runs cross-reference
analysis that complements Slither's intra-contract view. Key detectors:
  - unchecked-return-value   (cross-function awareness)
  - unsafe-erc20-call        (OZ SafeERC20 gap)
  - reentrancy               (with call-graph precision)
  - tx-origin                (phishing surface)
  - balance-based-branching  (MEV-sensitive logic)

JSON output schema (wake detect --export json all):
  [{
    "detector_name": str,
    "impact":        "critical"|"high"|"medium"|"low"|"warning"|"info",
    "confidence":    "high"|"medium"|"low",
    "uri":           str,
    "detection": {
      "message": str,
      "location": {
        "path": str, "relative_path": str|null, "contract": str|null,
        "start_line": int, "start_col": int, "end_line": int, "end_col": int,
        "source": str
      },
      "subdetections": [...]   // recursive, same structure
    },
    "suppressed": bool
  }]

File written to: {project_root}/.wake/detections.json
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("chainedr.wake")

MIN_VERSION = (4, 0, 0)   # 4.x+ required for --export json

_IMPACT_TO_SEV: Dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "warning":  "LOW",
    "info":     "INFO",
}

_CONF_TO_FLOAT: Dict[str, float] = {
    "high":   0.90,
    "medium": 0.65,
    "low":    0.40,
}

# Detectors Wake catches that ChainEDR novel checks also cover — skip to avoid
# duplicates when both tools are active (dedup handles it, but cleaner here).
_SKIP_DETECTORS: frozenset = frozenset()   # keep all for now; dedup handles it


def _wake_available() -> bool:
    if not shutil.which("wake"):
        logger.info("wake not found — skipping (pip install eth-wake)")
        return False
    try:
        out = subprocess.run(
            ["wake", "--version"],
            capture_output=True, text=True, timeout=10
        )
        # "wake 4.22.1"
        raw = out.stdout.strip().split()[-1]
        ver = tuple(int(x) for x in raw.split(".")[:3])
        if ver < MIN_VERSION:
            logger.warning("wake %s < min %s — skipping", raw, MIN_VERSION)
            return False
        return True
    except Exception as e:
        logger.warning("wake version check failed: %s", e)
        return False


def run_wake(directory: str, min_impact: str = "medium") -> List[Dict[str, Any]]:
    """
    Run Wake detectors on `directory`, return normalized finding dicts.

    Each dict:
      source, title, severity, confidence, location, description, fingerprint
    """
    if not _wake_available():
        return []

    project_dir = Path(directory).resolve()
    output_file = project_dir / ".wake" / "detections.json"

    try:
        result = subprocess.run(
            [
                "wake", "detect",
                "--export", "json",
                "all",
                "--min-impact", min_impact,
                "--min-confidence", "medium",
            ],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=180,
        )
        # Wake exit codes: 0=clean, 1=info, 2=medium, 3=high/critical — all normal.
        # Anything higher (e.g. 100+) is a real error (compilation failure, etc.)
        if result.returncode > 10:
            logger.warning(
                "wake exited %d: %s", result.returncode, result.stderr[:300]
            )
            return []
    except subprocess.TimeoutExpired:
        logger.warning("wake timed out on %s", directory)
        return []
    except Exception as e:
        logger.warning("wake subprocess failed: %s", e)
        return []

    if not output_file.exists():
        logger.info("wake produced no detections.json — no findings")
        return []

    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("wake JSON parse error: %s", e)
        return []

    return _normalize(data)


def _normalize(data: list) -> List[Dict[str, Any]]:
    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue

        detector = item.get("detector_name", "unknown")
        if detector in _SKIP_DETECTORS:
            continue

        impact    = item.get("impact", "medium").lower()
        conf_raw  = item.get("confidence", "medium").lower()
        suppressed = item.get("suppressed", False)

        detection = item.get("detection", {})
        message   = detection.get("message", "")
        loc       = detection.get("location", {})

        rel_path  = loc.get("relative_path") or loc.get("path", "")
        contract  = loc.get("contract") or ""
        start_ln  = loc.get("start_line", 0)
        source_snip = loc.get("source", "").strip()[:200]

        location_str = f"{rel_path}:{start_ln}"
        if contract:
            location_str = f"{contract}:{start_ln} ({rel_path})"

        findings.append({
            "source":      "wake",
            "title":       f"[Wake/{detector}] {message[:120]}",
            "severity":    _IMPACT_TO_SEV.get(impact, "MEDIUM"),
            "confidence":  _CONF_TO_FLOAT.get(conf_raw, 0.65),
            "location":    location_str,
            "description": (
                f"{message}\n\nSource:\n{source_snip}"
                if source_snip else message
            ),
            "exploitable": impact in ("critical", "high"),
            "suppressed":  suppressed,
            "fingerprint": f"wake:{detector}:{rel_path}:{start_ln}",
            "uri":         item.get("uri", ""),
        })

    return findings


def wake_to_static_findings(directory: str):
    """
    Convenience wrapper — returns StaticFinding objects for direct append to
    StaticAnalysisResult.findings.
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
    for f in run_wake(directory):
        if f.get("suppressed"):
            continue
        out.append(StaticFinding(
            severity=_sev.get(f["severity"], StaticSeverity.MEDIUM),
            category=StaticCategory.LOGIC,
            title=f["title"],
            description=f["description"],
            location=f["location"],
            exploitable=f["exploitable"],
            confidence=f["confidence"],
            fix_suggestion="See Wake docs: " + f.get("uri", ""),
            cwe="",
        ))
    return out
