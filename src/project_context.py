"""
ChainEDR Project Context Discovery

Discovers project type, structure, and files for the scanner to operate on.
Supports: Solidity (Foundry, Hardhat, bare), Noir (Nargo), Aztec.nr.
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set


class ProjectType(Enum):
    SOLIDITY_FOUNDRY = "solidity_foundry"
    SOLIDITY_HARDHAT = "solidity_hardhat"
    SOLIDITY_BARE = "solidity_bare"
    NOIR = "noir"
    AZTEC = "aztec"
    UNKNOWN = "unknown"


@dataclass
class ProjectContext:
    """
    Immutable snapshot of a project's structure for detectors to query.

    Created once per `chainedr scan`, shared across all detectors.
    """
    root: Path
    project_types: List[ProjectType] = field(default_factory=list)

    # Solidity
    solidity_files: List[Path] = field(default_factory=list)
    foundry_root: Optional[Path] = None
    hardhat_root: Optional[Path] = None
    remappings: Dict[str, str] = field(default_factory=dict)

    # Noir
    noir_root: Optional[Path] = None
    nargo_toml: Optional[Path] = None
    noir_files: List[Path] = field(default_factory=list)

    # Aztec
    aztec_root: Optional[Path] = None
    aztec_files: List[Path] = field(default_factory=list)

    # Source cache: filename -> content (loaded lazily)
    _source_cache: Dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def has_solidity(self) -> bool:
        return bool(self.solidity_files)

    @property
    def has_noir(self) -> bool:
        return bool(self.noir_files)

    @property
    def has_aztec(self) -> bool:
        return bool(self.aztec_files)

    @property
    def has_foundry(self) -> bool:
        return self.foundry_root is not None

    @property
    def has_hardhat(self) -> bool:
        return self.hardhat_root is not None

    @property
    def all_files(self) -> List[Path]:
        return self.solidity_files + self.noir_files + self.aztec_files

    @property
    def total_loc(self) -> int:
        return sum(len(self.read_file(f).splitlines()) for f in self.all_files)

    def read_file(self, path: Path) -> str:
        """Read file content with caching."""
        key = str(path)
        if key not in self._source_cache:
            self._source_cache[key] = path.read_text(encoding="utf-8", errors="replace")
        return self._source_cache[key]


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "cache", "out", "artifacts", "build",
    "target", "lib", "forge-std", "openzeppelin-contracts",
    "DeFiHackLabs", "__pycache__", ".venv", "venv",
})

_SKIP_SOL_PATTERNS = frozenset({
    ".t.sol", ".s.sol", "Test.sol", "Mock.sol", "test/", "script/",
    "forge-std/", "openzeppelin/",
})


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.startswith(".")


def _is_scannable_sol(path: Path, root: Path) -> bool:
    """Filter out test/script/lib Solidity files."""
    rel = str(path.relative_to(root)).replace("\\", "/")
    return not any(p in rel for p in _SKIP_SOL_PATTERNS)


def discover_project(target: str | Path) -> ProjectContext:
    """
    Discover project structure from a target path (file or directory).

    Walks the directory tree once, classifying files and detecting
    framework markers (foundry.toml, hardhat.config.*, Nargo.toml, etc).
    """
    target = Path(target).resolve()

    if target.is_file():
        root = target.parent
        ctx = ProjectContext(root=root)
        ext = target.suffix.lower()
        if ext == ".sol":
            ctx.solidity_files = [target]
            ctx.project_types = [_detect_solidity_framework(root)]
        elif ext == ".nr":
            ctx.noir_files = [target]
            ctx.project_types = [ProjectType.NOIR]
            _detect_noir(root, ctx)
        return ctx

    root = target
    ctx = ProjectContext(root=root)

    sol_files: List[Path] = []
    nr_files: List[Path] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]

        dp = Path(dirpath)

        # Framework markers
        if "foundry.toml" in filenames:
            ctx.foundry_root = dp
            ctx.remappings = _parse_foundry_remappings(dp / "foundry.toml")

        if "hardhat.config.js" in filenames or "hardhat.config.ts" in filenames:
            ctx.hardhat_root = dp

        if "Nargo.toml" in filenames:
            ctx.nargo_toml = dp / "Nargo.toml"
            ctx.noir_root = dp

        if "Aztec.toml" in filenames or _has_aztec_marker(dp, filenames):
            ctx.aztec_root = dp

        for fname in filenames:
            fp = dp / fname
            if fname.endswith(".sol"):
                if _is_scannable_sol(fp, root):
                    sol_files.append(fp)
            elif fname.endswith(".nr"):
                nr_files.append(fp)

    ctx.solidity_files = sol_files
    ctx.noir_files = nr_files

    # Classify Aztec .nr files separately
    if ctx.aztec_root:
        aztec_files = [f for f in nr_files if _is_aztec_file(f, ctx.aztec_root)]
        ctx.aztec_files = aztec_files
        ctx.noir_files = [f for f in nr_files if f not in aztec_files]

    # Determine project types
    types = []
    if sol_files:
        if ctx.foundry_root:
            types.append(ProjectType.SOLIDITY_FOUNDRY)
        elif ctx.hardhat_root:
            types.append(ProjectType.SOLIDITY_HARDHAT)
        else:
            types.append(ProjectType.SOLIDITY_BARE)
    if ctx.noir_files:
        types.append(ProjectType.NOIR)
    if ctx.aztec_files:
        types.append(ProjectType.AZTEC)
    if not types:
        types.append(ProjectType.UNKNOWN)
    ctx.project_types = types

    return ctx


def _detect_solidity_framework(root: Path) -> ProjectType:
    for p in [root] + list(root.parents):
        if (p / "foundry.toml").exists():
            return ProjectType.SOLIDITY_FOUNDRY
        if (p / "hardhat.config.js").exists() or (p / "hardhat.config.ts").exists():
            return ProjectType.SOLIDITY_HARDHAT
    return ProjectType.SOLIDITY_BARE


def _parse_foundry_remappings(foundry_toml: Path) -> Dict[str, str]:
    """Extract remappings from foundry.toml [profile.default] section."""
    remappings: Dict[str, str] = {}
    try:
        text = foundry_toml.read_text(errors="replace")
        import re
        for m in re.finditer(r'"([^"]+)=([^"]+)"', text):
            remappings[m.group(1)] = m.group(2)
    except Exception:
        pass

    # Also check remappings.txt
    remap_txt = foundry_toml.parent / "remappings.txt"
    if remap_txt.exists():
        for line in remap_txt.read_text(errors="replace").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                remappings[k.strip()] = v.strip()

    return remappings


def _detect_noir(root: Path, ctx: ProjectContext):
    """Look for Nargo.toml up the tree."""
    for p in [root] + list(root.parents):
        nargo = p / "Nargo.toml"
        if nargo.exists():
            ctx.nargo_toml = nargo
            ctx.noir_root = p
            return


def _has_aztec_marker(dp: Path, filenames: list) -> bool:
    """Detect Aztec project by characteristic files."""
    return any(f in filenames for f in [
        "aztec-nargo-toml", ".aztec",
    ]) or any(
        f.endswith(".nr") and "aztec" in f.lower() for f in filenames
    )


def _is_aztec_file(path: Path, aztec_root: Path) -> bool:
    """Check if a .nr file is Aztec-specific (vs pure Noir)."""
    try:
        rel = path.relative_to(aztec_root)
        return True
    except ValueError:
        return False
