"""
ChainEDR Detector Plugin Interface

Every detector (Solidity, EIP-7702, ZK verifier, Noir, Aztec) implements
the same Detector ABC. The scan engine discovers and runs all registered
detectors automatically.

Usage:
    class MyDetector(Detector):
        name = "my_detector"
        capabilities = ["solidity", "eip7702"]

        def discover(self, ctx: ProjectContext) -> bool:
            return ctx.has_solidity_files

        def scan(self, ctx: ProjectContext, opts: ScanOptions) -> List[Finding]:
            ...
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence
from pathlib import Path


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectorCategory(Enum):
    SOLIDITY = "solidity"
    EIP7702 = "eip7702"
    ZK_VERIFIER = "zk_verifier"
    ZK_CIRCUIT = "zk_circuit"
    NOIR = "noir"
    AZTEC = "aztec"
    BRIDGE = "bridge"
    RUNTIME = "runtime"


@dataclass
class Finding:
    """Normalized finding across all detector types."""
    detector: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str = ""
    file_path: str = ""
    line: int = 0
    category: str = ""
    cwe: str = ""
    confidence: float = 0.0
    exploitable: bool = False
    fix_suggestion: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def analysis_depth(self) -> str:
        """Return the reviewer-facing evidence depth for this finding."""
        metadata = self.metadata or {}

        explicit = metadata.get("analysis_depth")
        if isinstance(explicit, str) and explicit:
            return explicit

        dynamic = metadata.get("dynamic_confirmation") or {}
        if dynamic.get("status") in {"confirmed", "refuted"}:
            return "dynamic_confirmation"

        semantic = metadata.get("semantic_context") or {}
        semantic_analysis = semantic.get("analysis")
        if semantic_analysis in {"standard_json_ast", "deep_ast", "deep_fallback", "regex"}:
            return semantic_analysis
        if semantic.get("semantic_index"):
            return "semantic_index"

        if metadata.get("experimental") or metadata.get("extended"):
            return "experimental"

        if self.detector == "solidity" or str(self.rule_id).startswith("SL-"):
            return "external_tool"

        return "static_heuristic"

    def to_dict(self) -> dict:
        data = {
            "detector": self.detector,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "file_path": self.file_path,
            "line": self.line,
            "category": self.category,
            "cwe": self.cwe,
            "confidence": round(self.confidence, 2),
            "analysis_depth": self.analysis_depth(),
            "exploitable": self.exploitable,
            "fix": self.fix_suggestion,
        }
        if self.metadata:
            data["metadata"] = self.metadata
        try:
            from .reviewer_confidence import attach_reviewer_confidence
        except ImportError:
            from reviewer_confidence import attach_reviewer_confidence

        attach_reviewer_confidence(data)
        return data


@dataclass
class ScanOptions:
    """Options passed to every detector's scan()."""
    min_severity: Severity = Severity.LOW
    use_external_tools: bool = True
    external_timeout: int = 120
    use_ast: bool = True
    deep: bool = False
    extended: bool = False
    use_slither: bool = True
    use_mythril: bool = False
    parallel: bool = True
    max_workers: int = 4
    ignore_rules: set = field(default_factory=set)
    # CI-specific
    sarif_path: Optional[str] = None
    json_path: Optional[str] = None
    fail_on: Optional[str] = None  # "critical", "high", "medium"
    baseline_path: Optional[str] = None  # previous run for diff


@dataclass
class ScanResult:
    """Result from a single detector's scan()."""
    detector_name: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    elapsed_s: float = 0.0
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


class Detector(ABC):
    """
    Abstract base for all ChainEDR detectors.

    Subclasses must define:
      - name: str (e.g., "solidity", "eip7702", "noir")
      - capabilities: List[str] (e.g., ["solidity", "eip7702"])
      - discover(): does this detector apply to the project?
      - scan(): run analysis, return ScanResult
    """

    name: str = ""
    capabilities: List[str] = []

    @abstractmethod
    def discover(self, ctx) -> bool:
        """Return True if this detector is applicable to the project."""
        ...

    @abstractmethod
    def scan(self, ctx, opts: ScanOptions) -> ScanResult:
        """Run the detector. Return a ScanResult with normalized findings."""
        ...

    def _timed_scan(self, ctx, opts: ScanOptions) -> ScanResult:
        """Wrapper that adds elapsed time to scan result."""
        t0 = time.perf_counter()
        result = self.scan(ctx, opts)
        result.elapsed_s = time.perf_counter() - t0
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

_REGISTRY: List[type] = []


def register_detector(cls: type) -> type:
    """Register one implementation per public detector name."""
    for existing in _REGISTRY:
        if getattr(existing, "name", "") == getattr(cls, "name", ""):
            return cls
    _REGISTRY.append(cls)
    return cls


def get_all_detectors() -> List[Detector]:
    """Instantiate and return all registered detectors."""
    return [cls() for cls in _REGISTRY]


def discover_applicable(ctx, detectors: Optional[List[Detector]] = None) -> List[Detector]:
    """Return only detectors whose discover() returns True."""
    if detectors is None:
        detectors = get_all_detectors()
    return [d for d in detectors if d.discover(ctx)]
