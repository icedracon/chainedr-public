"""
ChainEDR Analyzer CLI v3.0 - static Pectra-era smart-account scanner

Public contract: exactly 5 top-level commands.

  chainedr scan   — Main scanner (Solidity, EIP-7702, ZK, Noir, Aztec)
  chainedr ci     — CI/CD wrapper (SARIF/JSON, severity gates, baseline diff)
  chainedr prove  — Evidence mode (PoCs, finding bundles, paper artifacts)
  chainedr live   — Optional runtime/on-chain research workflows
  chainedr doctor — Environment, dependency, license, tool-health checks

All old commands (audit, vectors, bounty, poc, baseline, bench, debug, init)
remain as hidden aliases routing through the legacy __main__.main() entrypoint.
"""

from __future__ import annotations

import sys
import os
import re
import json
import time
import argparse
import importlib
from pathlib import Path
from typing import List, Optional

__version__ = "3.0.0"


# ──────────────────────────────────────────────────────────────
# Terminal helpers (Windows-safe ANSI)
# ──────────────────────────────────────────────────────────────

def _enable_colors():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

_enable_colors()


class C:
    _off = os.environ.get("NO_COLOR") is not None
    RED    = "" if _off else "\033[91m"
    GREEN  = "" if _off else "\033[92m"
    YELLOW = "" if _off else "\033[93m"
    BLUE   = "" if _off else "\033[94m"
    CYAN   = "" if _off else "\033[96m"
    BOLD   = "" if _off else "\033[1m"
    DIM    = "" if _off else "\033[2m"
    RESET  = "" if _off else "\033[0m"


def ok(msg):    print(f"  {C.GREEN}✓{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}!{C.RESET} {msg}")
def fail(msg):  print(f"  {C.RED}✗{C.RESET} {msg}")
def info(msg):  print(f"  {C.CYAN}*{C.RESET} {msg}")
def dim(msg):   print(f"  {C.DIM}{msg}{C.RESET}")


def banner():
    print(f"""
{C.CYAN}{C.BOLD}   _____ _           _       ______ _____  ____
  / ____| |         (_)     |  ____|  __ \\|  _ \\
 | |    | |__   __ _ _ _ __ | |__  | |  | | |_) |
 | |    | '_ \\ / _` | | '_ \\|  __| | |  | |  _ <
 | |____| | | | (_| | | | | | |____| |__| | |_) |
  \\_____|_| |_|\\__,_|_|_| |_|______|_____/|____/ {C.RESET}
                                      {C.DIM}v{__version__}{C.RESET}
  {C.DIM}Static analysis for Pectra-era smart-account assumptions{C.RESET}
""")


def section(title):
    print(f"\n{C.BLUE}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}{title}{C.RESET}")
    print(f"{C.BLUE}{'─' * 60}{C.RESET}")


# ──────────────────────────────────────────────────────────────
# Severity gate for CI exit codes
# ──────────────────────────────────────────────────────────────

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _check_gate(findings, fail_on: str) -> int:
    """Return 1 if any finding meets or exceeds the severity gate."""
    if str(fail_on).lower() == "none":
        return 0
    gate = _SEV_RANK.get(fail_on.upper(), 99)
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if _SEV_RANK.get(sev.upper(), 99) <= gate:
            return 1
    return 0


def _emit_prove_skeletons(args, all_findings) -> None:
    """Generate Foundry PoC skeletons for matching findings, if requested.

    Wires `chainedr scan --prove` / `--prove-on-finding RULE_ID` directly into
    the scan pipeline so a developer doesn't have to chain into `chainedr
    prove poc --from-json`. Silently no-ops when neither flag is set so the
    default scan stays clean.
    """
    prove_filter = list(getattr(args, "prove_on_finding", []) or [])
    if not (getattr(args, "prove", False) or prove_filter):
        return
    try:
        from .poc_skeletons import generate_skeletons, SUPPORTED_RULES
    except ImportError:
        from poc_skeletons import generate_skeletons, SUPPORTED_RULES

    out_dir = Path(getattr(args, "prove_out", "chainedr-poc"))
    finding_dicts: list = []
    for f in all_findings:
        try:
            finding_dicts.append(f.to_dict())
        except Exception:
            continue
    if prove_filter:
        wanted = {rid.strip() for rid in prove_filter}
        finding_dicts = [
            fd for fd in finding_dicts
            if (fd.get("rule_id") or fd.get("check_id")) in wanted
        ]
    finding_dicts = [
        fd for fd in finding_dicts
        if (fd.get("rule_id") or fd.get("check_id")) in SUPPORTED_RULES
    ]
    if not finding_dicts:
        warn("--prove requested but no supported findings to skeleton.")
        return
    manifest = generate_skeletons(
        finding_dicts, out_dir, include_uncertain=True,
    )
    ok(f"PoC skeletons: {manifest.get('generated', 0)} written to {out_dir}/")


# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr scan
# ──────────────────────────────────────────────────────────────

def cmd_scan(args):
    """
    Main scanner — discovers project type, runs all applicable detectors.

    Covers: Solidity (Foundry/Hardhat/bare), EIP-7702, ZK verifier,
    Noir/Nargo, Aztec.nr. Outputs findings to terminal + optional
    SARIF/JSON files.
    """
    from .project_context import discover_project
    from .detector_plugin import ScanOptions, discover_applicable, Finding, Severity
    # Import builtin detectors to register them
    from . import detectors_builtin  # noqa: F401
    try:
        from . import eip7702_validation  # noqa: F401
    except ImportError:
        pass
    target = Path(args.target).resolve()
    if not target.exists():
        fail(f"Target not found: {target}")
        return 2
    _apply_auditor_profile(args)

    # Compact format is for IDE problem matchers / grep pipelines — no banner,
    # no decorative sections, no per-detector progress noise.
    compact_mode = getattr(args, "format", "text") == "compact"

    if not compact_mode:
        banner()
        section(f"Scanning {target.name}")

    # Discover project structure
    t0 = time.perf_counter()
    ctx = discover_project(target)

    if not compact_mode:
        info(f"Project types: {', '.join(pt.value for pt in ctx.project_types)}")
        info(f"Files: {len(ctx.solidity_files)} .sol, {len(ctx.noir_files)} .nr, "
             f"{len(ctx.aztec_files)} aztec.nr")
        if ctx.foundry_root:
            info(f"Foundry root: {ctx.foundry_root}")

    # Build scan options
    opts = ScanOptions(
        use_slither=not getattr(args, "no_external", False),
        use_ast=not getattr(args, "no_ast", False),
        deep=bool(getattr(args, "deep", False) and not getattr(args, "no_ast", False)),
        extended=bool(getattr(args, "extended", False)),
        use_mythril=getattr(args, "mythril", False),
        use_external_tools=not getattr(args, "no_external", False),
        external_timeout=getattr(args, "external_timeout", 120),
        ignore_rules=set(getattr(args, "ignore", []) or []),
    )

    # Min severity filter
    min_sev = str(getattr(args, "min_severity", "LOW")).upper()
    min_rank = _SEV_RANK.get(min_sev, 3)

    # Discover applicable detectors
    detectors = discover_applicable(ctx)
    if not detectors:
        warn("No applicable detectors found for this project.")
        if _is_auditor_profile(args):
            elapsed = time.perf_counter() - t0
            _write_sarif(getattr(args, "sarif", None) or "chainedr.sarif", [])
            _write_json(getattr(args, "json_out", None) or "chainedr.json", [], ctx, elapsed)
            _write_auditor_artifacts_from_json(
                args,
                source_root=(target if target.is_dir() else target.parent),
            )
            ok(f"Auditor report: {getattr(args, 'output_dir', 'chainedr-report')}")
        return 0

    if not compact_mode:
        info(f"Detectors: {', '.join(d.name for d in detectors)}")

    # Run all detectors
    all_findings: List[Finding] = []
    for det in detectors:
        try:
            result = det._timed_scan(ctx, opts)
            n = len(result.findings)
            if not compact_mode:
                if n > 0:
                    ok(f"  [{det.name}] {n} findings ({result.files_scanned} files, "
                       f"{result.lines_scanned} lines, {result.elapsed_s:.2f}s)")
                else:
                    dim(f"  [{det.name}] clean ({result.files_scanned} files, {result.elapsed_s:.2f}s)")
            all_findings.extend(result.findings)
            if result.error and not compact_mode:
                warn(f"  [{det.name}] {result.error}")
        except Exception as e:
            if not compact_mode:
                warn(f"  [{det.name}] error: {e}")

    elapsed = time.perf_counter() - t0

    # Filter by severity
    all_findings = [f for f in all_findings
                    if _SEV_RANK.get(f.severity.value, 99) <= min_rank]

    # Filter ignored rules
    if opts.ignore_rules:
        all_findings = [f for f in all_findings
                        if not any(
                            r.lower() in f.title.lower()
                            or r.lower() == f.rule_id.lower()
                            or r.lower() == f.detector.lower()
                            for r in opts.ignore_rules
                        )]

    # The legacy Solidity analyzer and specialist plugins may report the same
    # issue. Prefer the specialist detector when title/location match.
    deduped = {}
    for f in all_findings:
        key = (f.title.lower(), f.file_path, f.location)
        prev = deduped.get(key)
        if prev is None or (prev.detector == "solidity" and f.detector != "solidity"):
            deduped[key] = f
    all_findings = list(deduped.values())

    try:
        from .proof_adapters import attach_proof_adapters
    except ImportError:
        from proof_adapters import attach_proof_adapters
    attach_proof_adapters(all_findings)

    # Sort by severity
    all_findings.sort(key=lambda f: _SEV_RANK.get(f.severity.value, 99))

    # Optional dynamic confirmation. Keep this after static filtering/dedup so
    # confirmation work is bounded to what the user will actually see.
    confirmation_summary = None
    if getattr(args, "confirm", False):
        try:
            from .confirmation import (
                ConfirmationOptions,
                DEFAULT_CONFIRM_EOA,
                DEFAULT_CONFIRM_IMPLEMENTATION,
                confirm_findings,
            )
        except ImportError:
            from confirmation import (
                ConfirmationOptions,
                DEFAULT_CONFIRM_EOA,
                DEFAULT_CONFIRM_IMPLEMENTATION,
                confirm_findings,
            )

        confirm_opts = ConfirmationOptions(
            enabled=True,
            rpc_url=getattr(args, "confirm_rpc_url", None) or os.environ.get("RPC_URL"),
            eoa=getattr(args, "confirm_eoa", None) or DEFAULT_CONFIRM_EOA,
            implementation=(
                getattr(args, "confirm_implementation", None)
                or DEFAULT_CONFIRM_IMPLEMENTATION
            ),
            fork_block=getattr(args, "confirm_fork_block", None),
            strict=getattr(args, "confirm_strict", False),
        )
        try:
            confirmation_summary = confirm_findings(all_findings, confirm_opts)
        except Exception as e:
            fail(f"Dynamic confirmation failed: {e}")
            return 2

    # Compact format: one-line "file:line:col: [SEV/GRADE] RULE_ID — title"
    # per finding, no banner, no summary. IDE problem matchers and grep
    # pipelines consume this directly.
    if getattr(args, "format", "text") == "compact":
        for f in all_findings:
            try:
                f_dict = f.to_dict()
            except Exception:
                f_dict = {}
            rc = (f_dict.get("reviewer_confidence") or {}) if f_dict else {}
            grade = rc.get("grade") or "?"
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            path = f.file_path or "<unknown>"
            line = f.line or 0
            rule_id = getattr(f, "rule_id", "") or f.detector
            print(f"{path}:{line}:1: [{sev}/{grade}] {rule_id} {f.title}")

        fmt_compact = getattr(args, "format", "text")
        if fmt_compact == "compact" or getattr(args, "sarif", None):
            sarif_path = getattr(args, "sarif", None)
            if sarif_path:
                _write_sarif(sarif_path, all_findings)
        if getattr(args, "json_out", None):
            _write_json(getattr(args, "json_out"), all_findings, ctx, elapsed)

        # Prove skeletons also fire in compact mode — devs running the watch
        # linter still want a PoC file when a real AA7702 finding lands.
        _emit_prove_skeletons(args, all_findings)

        fail_on = getattr(args, "fail_on", None)
        if fail_on:
            return _check_gate(all_findings, fail_on)
        return 0

    # Print findings
    section(f"Findings ({len(all_findings)})")

    # Evidence-grade colors (A=strong, D=needs evidence). Surface auditor
    # confidence directly in the terminal so reviewers see proof maturity at a
    # glance instead of having to open the JSON.
    grade_color = {"A": C.GREEN, "B": C.CYAN, "C": C.YELLOW, "D": C.DIM}

    finding_dicts: List[dict] = []

    if not all_findings:
        ok("No findings detected.")
    else:
        for i, f in enumerate(all_findings, 1):
            sev_color = {
                "CRITICAL": C.RED, "HIGH": C.RED,
                "MEDIUM": C.YELLOW, "LOW": C.CYAN,
            }.get(f.severity.value, C.DIM)

            try:
                f_dict = f.to_dict()
            except Exception:
                f_dict = {}
            finding_dicts.append(f_dict)
            rc = (f_dict.get("reviewer_confidence") or {}) if f_dict else {}
            grade = rc.get("grade") or "?"
            tier = rc.get("tier") or ""
            g_col = grade_color.get(grade, C.DIM)

            conf_str = f" {f.confidence:.0%}" if f.confidence > 0 else ""
            expl = f" {C.RED}[EXPLOITABLE]{C.RESET}" if f.exploitable else ""

            print(f"\n  {sev_color}[{f.severity.value}]{C.RESET} "
                  f"{g_col}[{grade}]{C.RESET} #{i}: "
                  f"{C.BOLD}{f.title}{C.RESET}{expl}"
                  f" {C.DIM}[{f.detector}{conf_str}]{C.RESET}")
            if f.file_path:
                print(f"    {C.DIM}{f.file_path}:{f.line if f.line else f.location}{C.RESET}")
            if tier:
                tier_label = tier.replace("_", " ")
                print(f"    {g_col}Evidence: {tier_label}{C.RESET}")
            if f.description:
                print(f"    {C.DIM}{f.description[:200]}{C.RESET}")
            proof = (f.metadata or {}).get("proof_recipe") if f.metadata else None
            if proof:
                proof_status = proof.get("proof_status") or proof.get("status", "unknown")
                print(f"    {C.CYAN}Proof: {proof_status} / {proof.get('readiness', 'unknown')} "
                      f"via {proof.get('kind', 'manual_review')}{C.RESET}")
                objective = proof.get("objective")
                if objective:
                    print(f"    {C.DIM}Objective: {objective[:160]}{C.RESET}")
                semantic = proof.get("semantic") or {}
                sig_missing = (semantic.get("signature_model") or {}).get("missing") or []
                userop_missing = (semantic.get("userop_model") or {}).get("missing") or []
                if sig_missing:
                    print(f"    {C.DIM}Signature gaps: {', '.join(sig_missing)}{C.RESET}")
                if userop_missing:
                    print(f"    {C.DIM}UserOp gaps: {', '.join(userop_missing)}{C.RESET}")
                adapters = (f.metadata or {}).get("proof_adapters") or proof.get("adapters") or []
                if adapters:
                    names = ", ".join(
                        f"{a.get('adapter_id', 'adapter')}:{a.get('status', 'planned')}"
                        for a in adapters[:2]
                    )
                    print(f"    {C.DIM}Adapters: {names}{C.RESET}")
            if f.fix_suggestion:
                print(f"    {C.GREEN}Fix: {f.fix_suggestion[:120]}{C.RESET}")

    # Summary
    section("Summary")
    by_sev = {}
    for f in all_findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    by_det = {}
    for f in all_findings:
        by_det[f.detector] = by_det.get(f.detector, 0) + 1

    by_grade: dict = {}
    for f_dict in finding_dicts:
        rc = (f_dict.get("reviewer_confidence") or {}) if f_dict else {}
        g = rc.get("grade") or "?"
        by_grade[g] = by_grade.get(g, 0) + 1

    total_loc = sum(len(ctx.read_file(f).splitlines()) for f in ctx.all_files)
    print(f"\n  Files:     {len(ctx.all_files)}")
    print(f"  LOC:       {total_loc:,}")
    print(f"  Time:      {elapsed:.2f}s")
    print(f"  Findings:  {len(all_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = by_sev.get(sev, 0)
        if cnt:
            col = C.RED if sev in ("CRITICAL", "HIGH") else (C.YELLOW if sev == "MEDIUM" else C.DIM)
            print(f"    {col}{sev}: {cnt}{C.RESET}")
    if by_grade:
        print(f"\n  Evidence grades (A=strong → D=needs confirmation):")
        for g in ["A", "B", "C", "D", "?"]:
            cnt = by_grade.get(g, 0)
            if cnt:
                col = grade_color.get(g, C.DIM)
                print(f"    {col}{g}: {cnt}{C.RESET}")
    if by_det:
        det_str = ", ".join(f"{k}={v}" for k, v in sorted(by_det.items()))
        dim(f"  By detector: {det_str}")

    if confirmation_summary:
        cs = confirmation_summary
        print("\n  Dynamic confirmation:")
        print(f"    status:    {cs.status}")
        print(f"    eligible:  {cs.eligible}")
        if cs.confirmed:
            print(f"    confirmed: {cs.confirmed}")
        if cs.refuted:
            print(f"    refuted:   {cs.refuted}")
        if cs.skipped:
            print(f"    skipped:   {cs.skipped}")
        if cs.reason:
            print(f"    reason:    {cs.reason}")

    # Output files
    fmt = getattr(args, "format", "text")

    if fmt == "sarif" or getattr(args, "sarif", None):
        sarif_path = getattr(args, "sarif", None) or "chainedr.sarif"
        _write_sarif(sarif_path, all_findings)
        ok(f"SARIF: {sarif_path}")

    if fmt == "json" or getattr(args, "json_out", None):
        json_path = getattr(args, "json_out", None) or "chainedr.json"
        _write_json(json_path, all_findings, ctx, elapsed)
        ok(f"JSON: {json_path}")

    if _is_auditor_profile(args):
        _write_auditor_artifacts_from_json(args, source_root=(target if target.is_dir() else target.parent))
        ok(f"Auditor report: {getattr(args, 'output_dir', 'chainedr-report')}")

    # PoC skeleton generation — see _emit_prove_skeletons.
    _emit_prove_skeletons(args, all_findings)

    # Severity gate
    fail_on = getattr(args, "fail_on", None)
    if fail_on:
        return _check_gate(all_findings, fail_on)

    return 0


# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr ci
# ──────────────────────────────────────────────────────────────

def cmd_ci(args):
    """
    CI/CD wrapper. Outputs SARIF/JSON, severity gates, baseline diff.

    Designed for GitHub Actions, GitLab CI, etc.
    Exit codes: 0=clean, 1=findings above gate, 2=tool error.
    """
    target = getattr(args, "target_opt", None) or getattr(args, "target", None)

    if getattr(args, "ci_command", None) == "init" or target == "init":
        return _ci_init(args)

    # Default: run scan with CI defaults
    args.target = target or "."
    _apply_auditor_profile(args)

    # Force SARIF + JSON output
    if not getattr(args, "sarif", None):
        args.sarif = "chainedr.sarif"
    if not getattr(args, "json_out", None):
        args.json_out = "chainedr.json"
    if not getattr(args, "fail_on", None):
        args.fail_on = "high"

    # Baseline diff
    baseline_path = getattr(args, "baseline", None)
    result = cmd_scan(args)

    if baseline_path and Path(baseline_path).exists():
        _apply_baseline_diff(args.json_out, baseline_path)

    return result


_GITHUB_ACTIONS_WORKFLOW_TEMPLATE = """\
name: ChainEDR EIP-7702 Security Scan

on:
  pull_request:
    paths:
      - "**/*.sol"
      - "**/*.nr"
      - "foundry.toml"
      - "hardhat.config.*"
      - "remappings.txt"
      - ".github/workflows/chainedr.yml"
  push:
    branches: [main, master, develop]
    paths:
      - "**/*.sol"
      - "**/*.nr"
      - "foundry.toml"
      - "hardhat.config.*"
      - "remappings.txt"
      - ".github/workflows/chainedr.yml"
  workflow_dispatch:

permissions:
  contents: read
  actions: read
  security-events: write

concurrency:
  group: chainedr-template-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  chainedr:
    name: Analyze smart contracts
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install ChainEDR
        shell: bash
        run: |
          python -m pip install --upgrade pip
          if [ -f "src/pyproject.toml" ]; then
            python -m pip install ./src
          else
            python -m pip install chainedr
          fi

      - name: Select scan target
        id: target
        shell: bash
        run: |
          set -euo pipefail
          if [ -d contracts ]; then
            echo "path=contracts" >> "$GITHUB_OUTPUT"
          elif [ -d src ] && find src -name '*.sol' -print -quit | grep -q .; then
            echo "path=src" >> "$GITHUB_OUTPUT"
          else
            echo "path=." >> "$GITHUB_OUTPUT"
          fi

      - name: Run ChainEDR scan
        id: scan
        continue-on-error: true
        shell: bash
        run: |
          chainedr ci "${{ steps.target.outputs.path }}" \\
            --profile auditor \\
            --out-dir chainedr-report \\
            --no-external \\
            --deep \\
            --fail-on high

      - name: Normalize report files
        if: always()
        shell: bash
        run: |
          mkdir -p chainedr-report
          if [ ! -f chainedr-report/scan.json ]; then
            cat > chainedr-report/scan.json <<'JSON'
          {"findings":[],"status":"no-results","message":"ChainEDR did not produce JSON; inspect workflow logs."}
          JSON
          fi
          if [ ! -f chainedr-report/chainedr.sarif ]; then
            cat > chainedr-report/chainedr.sarif <<'SARIF'
          {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"ChainEDR","informationUri":"https://github.com/icedracon/chainedr","rules":[]}},"results":[]}]}
          SARIF
          fi
          if [ ! -f chainedr-report/evidence_bundle.md ]; then
            printf '# ChainEDR Evidence Bundle\\n\\nChainEDR did not produce a full evidence bundle; inspect workflow logs.\\n' > chainedr-report/evidence_bundle.md
          fi
          if [ ! -f chainedr-report/executive_summary.md ]; then
            printf '# ChainEDR Executive Summary\\n\\nChainEDR did not produce a full executive summary; inspect workflow logs.\\n' > chainedr-report/executive_summary.md
          fi
          if [ ! -f chainedr-report/manifest.json ]; then
            printf '{"profile":"auditor","status":"no-results","message":"ChainEDR did not produce a full auditor manifest; inspect workflow logs."}\\n' > chainedr-report/manifest.json
          fi

      - name: Summarize ChainEDR results
        if: always()
        shell: bash
        env:
          CHAINEDR_TARGET: ${{ steps.target.outputs.path }}
        run: |
          python - <<'PY'
          import json
          import os
          from collections import Counter
          from pathlib import Path

          report_path = Path("chainedr-report/scan.json")
          try:
              data = json.loads(report_path.read_text(encoding="utf-8"))
          except Exception as exc:
              data = {"findings": [], "message": f"Could not parse report: {exc}"}

          findings = data if isinstance(data, list) else data.get("findings", [])
          severities = Counter(str(f.get("severity", "UNKNOWN")).upper() for f in findings)
          lines = [
              "## ChainEDR Security Scan",
              "",
              f"Target: `{os.environ.get('CHAINEDR_TARGET', '.')}`",
              f"Findings: **{len(findings)}**",
              "",
              "| Severity | Count |",
              "| --- | ---: |",
          ]
          for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
              lines.append(f"| {severity} | {severities.get(severity, 0)} |")
          if isinstance(data, dict) and data.get("message"):
              lines.extend(["", f"Note: {data['message']}"])
          with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
              handle.write("\\n".join(lines) + "\\n")
          PY

      - uses: github/codeql-action/upload-sarif@v4
        if: always() && hashFiles('chainedr-report/chainedr.sarif') != ''
        continue-on-error: true
        with:
          sarif_file: chainedr-report/chainedr.sarif
          category: chainedr

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: chainedr-report
          path: chainedr-report/**
          retention-days: 14
"""


_PRECOMMIT_HOOK_SH = """\
#!/usr/bin/env bash
# Installed by `chainedr ci init --hook precommit`.
#
# Runs ChainEDR's compact-format scan over staged Solidity files. Fails
# the commit if any HIGH or CRITICAL finding lands. Bypass with
# `git commit --no-verify` when you really need to (e.g. WIP commits).

set -u

# Collect staged .sol files only — skip non-Solidity changes so the hook
# stays fast on mixed PRs.
mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACMR | grep -E '\\.sol$' || true)

if [ "${#STAGED[@]}" -eq 0 ]; then
  exit 0
fi

if ! command -v chainedr >/dev/null 2>&1; then
  echo "chainedr pre-commit: chainedr CLI not on PATH; skipping." >&2
  exit 0
fi

echo "chainedr pre-commit: scanning ${#STAGED[@]} staged .sol file(s)"

# Scan each staged file individually so the failing path is obvious; the
# `--fail-on high` flag returns non-zero if any HIGH/CRITICAL finding is
# emitted, which blocks the commit.
RC=0
for f in "${STAGED[@]}"; do
  chainedr scan "$f" --format compact --fail-on high || RC=1
done

if [ "$RC" -ne 0 ]; then
  echo
  echo "chainedr pre-commit: blocking commit (HIGH+ finding above). Use" >&2
  echo "  git commit --no-verify" >&2
  echo "to skip this hook for a WIP commit." >&2
fi

exit $RC
"""


_PREPUSH_HOOK_SH = """\
#!/usr/bin/env bash
# Installed by `chainedr ci init --hook prepush`.
#
# Runs ChainEDR's compact-format scan on every Solidity file in the
# repo before push. Fails the push if any HIGH or CRITICAL finding is
# present. Bypass with `git push --no-verify`.

set -u

if ! command -v chainedr >/dev/null 2>&1; then
  echo "chainedr pre-push: chainedr CLI not on PATH; skipping." >&2
  exit 0
fi

echo "chainedr pre-push: full-repo scan"
chainedr scan . --format compact --fail-on high
"""


def _install_git_hook(kind: str) -> int:
    """Write a chainedr-driven git hook into .git/hooks/<kind>.

    Supported kinds: ``precommit`` -> ``.git/hooks/pre-commit``,
    ``prepush`` -> ``.git/hooks/pre-push``. Refuses to clobber a
    pre-existing hook unless it is empty or already begins with our
    marker comment.
    """
    hook_dir = Path(".git/hooks")
    if not hook_dir.is_dir():
        fail("No .git/hooks directory; run `git init` first.")
        return 2
    if kind == "precommit":
        dest = hook_dir / "pre-commit"
        body = _PRECOMMIT_HOOK_SH
    elif kind == "prepush":
        dest = hook_dir / "pre-push"
        body = _PREPUSH_HOOK_SH
    else:
        fail(f"Unknown hook kind: {kind}")
        return 2

    marker = "Installed by `chainedr ci init"
    if dest.exists():
        existing = dest.read_text(encoding="utf-8", errors="replace")
        if marker not in existing and existing.strip():
            warn(f"Refusing to overwrite existing {dest}; remove it manually "
                 f"or set ChainEDR's body inside it by hand.")
            return 1

    dest.write_text(body, encoding="utf-8")
    try:
        os.chmod(dest, 0o755)
    except Exception:
        pass
    ok(f"Git hook installed: {dest}")
    return 0


def _ci_init(args):
    """Generate GitHub Action workflow file (and optionally a git hook)."""
    workflow = _GITHUB_ACTIONS_WORKFLOW_TEMPLATE
    gh_dir = Path(".github/workflows")
    gh_dir.mkdir(parents=True, exist_ok=True)
    dest = gh_dir / "chainedr.yml"
    dest.write_text(workflow, encoding="utf-8")
    ok(f"GitHub Action written to {dest}")

    # Also generate .chainedr.toml
    toml_content = """\
[scan]
min_severity = "LOW"
ignore = []
no_external = false
external_timeout = 120

[ci]
fail_on = "high"
sarif = "chainedr.sarif"
json = "chainedr.json"
"""
    toml_path = Path(".chainedr.toml")
    if not toml_path.exists():
        toml_path.write_text(toml_content, encoding="utf-8")
        ok(f"Config written to {toml_path}")

    hook_kind = getattr(args, "hook", None)
    if hook_kind:
        rc = _install_git_hook(hook_kind)
        if rc != 0:
            return rc

    return 0


def _is_auditor_profile(args) -> bool:
    return str(getattr(args, "profile", "default") or "default").lower() == "auditor"


def _apply_auditor_profile(args):
    """Apply reviewer-friendly output defaults for ``--profile auditor``."""
    if not _is_auditor_profile(args):
        return None

    output_dir = Path(getattr(args, "output_dir", None) or "chainedr-report")
    output_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir = str(output_dir)

    if not getattr(args, "json_out", None):
        args.json_out = str(output_dir / "scan.json")
    if not getattr(args, "sarif", None):
        args.sarif = str(output_dir / "chainedr.sarif")
    if not getattr(args, "no_ast", False):
        args.deep = True
    return output_dir


def _apply_baseline_diff(current_json: str, baseline_json: str):
    """Filter current findings to show only NEW ones vs baseline."""
    try:
        current = json.loads(Path(current_json).read_text())
        baseline = json.loads(Path(baseline_json).read_text())
        baseline_keys = {
            (f["rule_id"], f.get("file_path", ""), f.get("title", ""))
            for f in baseline.get("findings", [])
        }
        new_findings = [
            f for f in current.get("findings", [])
            if (f["rule_id"], f.get("file_path", ""), f.get("title", "")) not in baseline_keys
        ]
        current["findings"] = new_findings
        current["baseline_diff"] = {
            "total_before": len(baseline.get("findings", [])),
            "total_after": len(new_findings),
            "new": len(new_findings),
        }
        Path(current_json).write_text(json.dumps(current, indent=2))
        info(f"Baseline diff: {len(new_findings)} new findings "
             f"(was {len(baseline.get('findings', []))})")
    except Exception as e:
        warn(f"Baseline diff failed: {e}")


# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr prove
# ──────────────────────────────────────────────────────────────

def _artifact_rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _write_auditor_artifacts_from_json(args, source_root: Path | None = None) -> dict:
    """Write auditor-friendly Markdown and manifest artifacts beside scan JSON."""
    if not _is_auditor_profile(args):
        return {}

    output_dir = Path(getattr(args, "output_dir", None) or "chainedr-report")
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = Path(getattr(args, "json_out", None) or output_dir / "scan.json")
    sarif_path = Path(getattr(args, "sarif", None) or output_dir / "chainedr.sarif")
    evidence_path = output_dir / "evidence_bundle.md"
    executive_path = output_dir / "executive_summary.md"
    manifest_path = output_dir / "manifest.json"

    if not json_path.exists():
        return {}

    root = source_root or Path(getattr(args, "target", ".")).resolve()
    if root.is_file():
        root = root.parent

    try:
        from .evidence import write_evidence_bundle
    except ImportError:
        from evidence import write_evidence_bundle

    evidence_result = write_evidence_bundle(
        json_path,
        evidence_path,
        source_root=root,
        max_findings=50,
    )

    report = json.loads(json_path.read_text(encoding="utf-8"))
    if isinstance(report, list):
        report = {"findings": report, "summary": {"total": len(report)}}
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []

    by_severity = summary.get("by_severity") or {}
    by_detector = summary.get("by_detector") or {}
    by_confidence = summary.get("by_reviewer_confidence") or {}
    by_tier = summary.get("by_reviewer_tier") or {}

    lines = [
        "# ChainEDR Executive Summary",
        "",
        f"Target: `{getattr(args, 'target', '.')}`",
        f"Profile: `{getattr(args, 'profile', 'auditor')}`",
        f"Elapsed: `{report.get('elapsed_s', 'unknown')}` seconds",
        f"Files scanned: `{(report.get('project') or {}).get('files', 'unknown')}`",
        "",
        "## Finding Overview",
        "",
        f"- Total findings: **{len(findings)}**",
        f"- Severity mix: `{json.dumps(by_severity, sort_keys=True)}`",
        f"- Detector mix: `{json.dumps(by_detector, sort_keys=True)}`",
        f"- Reviewer confidence mix: `{json.dumps(by_confidence, sort_keys=True)}`",
        f"- Reviewer tier mix: `{json.dumps(by_tier, sort_keys=True)}`",
        "",
        "## Artifacts",
        "",
        f"- JSON report: `{_artifact_rel(json_path, output_dir)}`",
        f"- SARIF report: `{_artifact_rel(sarif_path, output_dir)}`",
        f"- Evidence bundle: `{_artifact_rel(evidence_path, output_dir)}`",
        f"- Manifest: `{_artifact_rel(manifest_path, output_dir)}`",
        "",
        "## Reviewer Note",
        "",
        "Static findings are candidates until a human review, fork proof, or",
        "target-specific reproduction confirms impact. Use the evidence bundle for",
        "source context and proof-readiness notes before escalating a finding.",
        "",
    ]

    if findings:
        lines.extend(["## Top Findings", ""])
        for idx, finding in enumerate(findings[:10], 1):
            rule_id = finding.get("rule_id") or finding.get("check_id") or "UNKNOWN"
            severity = finding.get("severity") or "UNKNOWN"
            title = finding.get("title") or "Untitled finding"
            file_path = finding.get("file_path") or "unknown"
            line = finding.get("line") or finding.get("location") or "?"
            lines.append(f"{idx}. **{severity}** `{rule_id}` - {title} (`{file_path}:{line}`)")
        lines.append("")
    else:
        lines.extend(["## Top Findings", "", "No findings were present in the scan JSON.", ""])

    executive_path.write_text("\n".join(lines), encoding="utf-8")

    manifest = {
        "profile": "auditor",
        "target": str(getattr(args, "target", ".")),
        "output_dir": str(output_dir),
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_detector": by_detector,
            "by_reviewer_confidence": by_confidence,
            "by_reviewer_tier": by_tier,
        },
        "artifacts": {
            "json": str(json_path),
            "sarif": str(sarif_path),
            "evidence_bundle": str(evidence_path),
            "executive_summary": str(executive_path),
            "manifest": str(manifest_path),
        },
        "evidence": evidence_result,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def cmd_prove(args):
    """
    Evidence/report mode. Generates PoCs, finding bundles, paper artifacts.

    Subcommands:
      chainedr prove demo                — Generate a reviewer demo pack
      chainedr prove bundle --from-json  — Turn scan JSON into evidence Markdown
      chainedr prove poc <target>        — Generate Foundry PoC reproducers
      chainedr prove report <target>     — Full audit report (MD + SARIF)
      chainedr prove benchmark <corpus>  — Labeled-corpus benchmark (F1, ROC)
      chainedr prove replay              — Replay offline benchmark
    """
    sub = getattr(args, "prove_command", None)
    if not sub:
        warn("Usage: chainedr prove {demo|bundle|poc|report|benchmark|replay}")
        return 1

    if sub == "demo":
        from .evidence import run_friend_demo

        result = run_friend_demo(
            Path(args.output_dir),
            include_benchmark=not getattr(args, "skip_benchmark", False),
        )
        ok(f"Demo pack written to {result['output_dir']}")
        ok(f"Report: {result['report']}")
        if result.get("benchmark_samples"):
            ok(f"Benchmark: {result['benchmark_samples']} samples, F1={result['benchmark_f1']}")
        return 0
    elif sub == "bundle":
        from .evidence import write_evidence_bundle

        if not getattr(args, "from_json", None):
            fail("chainedr prove bundle requires --from-json <scan.json>")
            return 2
        source_root = Path(args.source_root).resolve() if args.source_root else None
        result = write_evidence_bundle(
            Path(args.from_json),
            Path(args.output),
            source_root=source_root,
            max_findings=args.max_findings,
        )
        ok(f"Evidence bundle written to {result['output']}")
        ok(f"Findings included: {result['findings']}")
        return 0

    if sub == "poc":
        if not getattr(args, "from_json", None):
            fail("chainedr prove poc requires --from-json <scan.json>")
            return 2
        from .poc_skeletons import generate_from_scan_json

        manifest = generate_from_scan_json(
            Path(args.from_json),
            Path(args.output_dir),
            include_uncertain=getattr(args, "include_uncertain", False),
        )
        ok(f"PoC skeletons written: {manifest['generated']}")
        ok(f"Manifest: {Path(args.output_dir) / 'MANIFEST.md'}")
        return 0
    else:
        fail(f"Unknown prove subcommand: {sub}")
        return 1


# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr live
# ──────────────────────────────────────────────────────────────



# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr doctor
# ──────────────────────────────────────────────────────────────

def cmd_doctor(args):
    """
    Environment, dependency, and tool-health checks.

    Extended: also checks Noir (nargo) and Aztec (aztec-nargo) tooling.
    """
    import shutil
    import subprocess

    banner()
    section("ChainEDR Doctor — Tool Health Check")

    tools = {
        "Static analyzers": [
            ("solc", "--version"),
            ("slither", "--version"),
            ("aderyn", "--version"),
            ("wake", "--version"),
        ],
        "Symbolic/fuzz": [
            ("myth", "--version"),
            ("halmos", "--version"),
            ("echidna", "--version"),
        ],
        "Noir/Aztec": [
            ("nargo", "--version"),
            ("aztec-nargo", "--version"),
        ],
        "Build tools": [
            ("forge", "--version"),
            ("hardhat", "--version"),
        ],
    }

    core_ok = True
    for group, cmds in tools.items():
        print(f"\n  {C.BOLD}{group}{C.RESET}")
        for cmd, flag in cmds:
            if not shutil.which(cmd):
                dim(f"{cmd:15s} not installed")
                continue
            try:
                r = subprocess.run(
                    [cmd, flag], capture_output=True, text=True, timeout=6,
                )
                ver = (r.stdout or r.stderr).strip().splitlines()[0][:50]
                if r.returncode == 0:
                    ok(f"{cmd:15s} {ver}")
                else:
                    warn(f"{cmd:15s} exit {r.returncode}")
            except Exception as e:
                warn(f"{cmd:15s} error: {e}")

    # Internal modules
    print(f"\n  {C.BOLD}Internal modules{C.RESET}")
    modules = [
        "static_analyzer", "eip7702_detector", "bridge_detectors",
        "detector_plugin", "project_context",
        "eip7702_validation", "owasp_2026", "sarif_output",
    ]
    for mod in modules:
        try:
            importlib.import_module(f".{mod}", package=__package__)
            ok(f"{mod:25s} OK")
        except ImportError:
            try:
                __import__(mod)
                ok(f"{mod:25s} OK (standalone)")
            except ImportError:
                fail(f"{mod:25s} not available")
                core_ok = False

    section("Verdict")
    if core_ok:
        ok("Core scanner ready. Optional tools above improve coverage when installed.")
    else:
        fail("Core scanner modules are missing or broken.")
    return 0 if core_ok else 1


# ──────────────────────────────────────────────────────────────
# Output writers
# ──────────────────────────────────────────────────────────────

def _write_sarif(path: str, findings):
    """Write SARIF 2.1.0 for GitHub Code Scanning."""
    rules = {}
    results = []

    for f in findings:
        rid = f.rule_id or f.category or "unknown"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.title[:80],
                "shortDescription": {"text": f.title[:80]},
                "properties": {"tags": [f.detector, f.severity.value]},
            }

        sev_level = {"CRITICAL": "error", "HIGH": "error",
                     "MEDIUM": "warning", "LOW": "note"}.get(f.severity.value, "none")

        properties = {
            "detector": f.detector,
            "confidence": round(f.confidence, 2),
            "exploitable": f.exploitable,
            "cwe": f.cwe,
        }
        if getattr(f, "metadata", None):
            properties["metadata"] = f.metadata

        results.append({
            "ruleId": rid,
            "level": sev_level,
            "message": {"text": f.description[:500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file_path or "unknown",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(f.line, 1)},
                },
            }],
            "properties": properties,
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ChainEDR",
                    "version": __version__,
                    "informationUri": "https://github.com/icedracon/chainedr",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(sarif, indent=2))


def _write_json(path: str, findings, ctx, elapsed: float):
    """Write machine-readable JSON report."""
    from datetime import datetime, timezone
    serialized_findings = [f.to_dict() for f in findings]

    data = {
        "chainedr_version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(elapsed, 2),
        "project": {
            "types": [pt.value for pt in ctx.project_types],
            "files": len(ctx.all_files),
        },
        "summary": {
            "total": len(findings),
            "by_severity": {},
            "by_detector": {},
            "by_reviewer_confidence": {},
            "by_reviewer_tier": {},
        },
        "findings": serialized_findings,
    }

    for f in findings:
        sev = f.severity.value
        data["summary"]["by_severity"][sev] = data["summary"]["by_severity"].get(sev, 0) + 1
        data["summary"]["by_detector"][f.detector] = data["summary"]["by_detector"].get(f.detector, 0) + 1
    for finding in serialized_findings:
        reviewer_confidence = finding.get("reviewer_confidence") or {}
        grade = reviewer_confidence.get("grade", "unknown")
        data["summary"]["by_reviewer_confidence"][grade] = (
            data["summary"]["by_reviewer_confidence"].get(grade, 0) + 1
        )
        tier = reviewer_confidence.get("tier", "unknown")
        data["summary"]["by_reviewer_tier"][tier] = (
            data["summary"]["by_reviewer_tier"].get(tier, 0) + 1
        )

    try:
        from .confirmation import dynamic_confirmation_summary
    except ImportError:
        try:
            from confirmation import dynamic_confirmation_summary
        except ImportError:
            dynamic_confirmation_summary = None
    if dynamic_confirmation_summary is not None:
        dynamic = dynamic_confirmation_summary(findings)
        if dynamic:
            data["summary"]["dynamic_confirmation"] = dynamic

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2))


# ──────────────────────────────────────────────────────────────
# Legacy command routing
# ──────────────────────────────────────────────────────────────



# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr watch
# ──────────────────────────────────────────────────────────────

def cmd_watch(args):
    """Dev-time security linter.

    Polls the target path for Solidity / Noir source changes and re-runs
    ``chainedr scan`` on every change. Defaults to ``--format compact`` so
    the output is one finding per line, IDE / grep friendly. Press Ctrl-C
    to stop.

    Deliberately uses mtime polling rather than an OS watcher so it works on
    every platform without an extra dependency. The polling interval defaults
    to 1.5s — fast enough to feel live without burning CPU.
    """
    import time as _time

    target = Path(args.target).resolve()
    if not target.exists():
        fail(f"Watch target not found: {target}")
        return 2

    interval = max(0.25, float(getattr(args, "interval", 1.5)))
    sol_exts = (".sol", ".nr")

    def _snapshot() -> dict:
        snap: dict = {}
        if target.is_file():
            try:
                snap[str(target)] = target.stat().st_mtime
            except OSError:
                pass
            return snap
        for root, _dirs, files in os.walk(target):
            # Skip noisy dependency dirs so saves in node_modules / lib don't
            # constantly re-trigger.
            if any(seg in root for seg in (
                "node_modules", ".git", "out", "cache",
                "broadcast", "artifacts", "__pycache__",
            )):
                continue
            for name in files:
                if name.endswith(sol_exts):
                    fpath = os.path.join(root, name)
                    try:
                        snap[fpath] = os.path.getmtime(fpath)
                    except OSError:
                        continue
        return snap

    def _run_scan() -> int:
        scan_ns = argparse.Namespace(
            target=str(target),
            no_external=bool(getattr(args, "no_external", False)),
            no_ast=bool(getattr(args, "no_ast", False)),
            deep=bool(getattr(args, "deep", False)),
            extended=bool(getattr(args, "extended", False)),
            mythril=False,
            external_timeout=120,
            ignore=list(getattr(args, "ignore", []) or []),
            min_severity=str(getattr(args, "min_severity", "LOW")).upper(),
            format=str(getattr(args, "format", "compact")),
            sarif=None,
            json_out=None,
            fail_on=None,
            profile="default",
            output_dir=None,
            ai_triage=False,
        )
        return cmd_scan(scan_ns) or 0

    print(f"chainedr watch: {target} (interval={interval}s, format={args.format})")
    print("Initial scan ↓")
    _run_scan()
    print(f"\nWatching for changes — Ctrl-C to stop.")

    previous = _snapshot()
    try:
        while True:
            _time.sleep(interval)
            current = _snapshot()
            if current != previous:
                changed = sorted(
                    p for p, m in current.items()
                    if previous.get(p) != m
                )
                deleted = sorted(set(previous) - set(current))
                if changed:
                    print(f"\n[+] changed: {len(changed)} file(s) — re-scanning")
                if deleted:
                    print(f"[-] removed: {len(deleted)} file(s)")
                _run_scan()
                previous = current
    except KeyboardInterrupt:
        print(f"\n{C.DIM}watch stopped.{C.RESET}")
    return 0


# ──────────────────────────────────────────────────────────────
# COMMAND: chainedr bytecode
# ──────────────────────────────────────────────────────────────

def _load_bytecode_target(target: str, rpc_url: str | None) -> tuple[str, str]:
    """Resolve ``target`` into (bytecode_hex, display_label)."""
    hex_only = re.fullmatch(r"0x([0-9a-fA-F]+)", target) or re.fullmatch(
        r"[0-9a-fA-F]+", target
    )
    if hex_only:
        bytes_str = target[2:] if target.startswith("0x") else target
        return bytes_str, f"<hex:{len(bytes_str)//2}b>"
    addr = re.fullmatch(r"0x[0-9a-fA-F]{40}", target)
    if addr:
        try:
            from .bytecode_oracle import fetch_runtime_bytecode
        except ImportError:
            from bytecode_oracle import fetch_runtime_bytecode
        code = fetch_runtime_bytecode(target, rpc_url=rpc_url)
        return code.lstrip("0x"), target
    p = Path(target)
    if p.exists() and p.is_file():
        content = p.read_text(encoding="utf-8", errors="replace").strip()
        if content.startswith("0x"):
            content = content[2:]
        return content, str(p)
    raise ValueError(
        f"Could not interpret target {target!r} as hex, address, or file"
    )


def cmd_bytecode(args):
    """Run the AA7702 bytecode detector on hex / file / address."""
    try:
        from .bytecode_oracle import (
            detect_bytecode_aa7702,
            bytecode_findings_to_json,
        )
    except ImportError:
        from bytecode_oracle import (
            detect_bytecode_aa7702,
            bytecode_findings_to_json,
        )

    fmt = getattr(args, "format", "text")
    compact_mode = fmt == "compact"

    try:
        code_hex, label = _load_bytecode_target(args.target, args.rpc_url)
    except Exception as exc:
        fail(str(exc))
        return 2

    if not compact_mode and fmt != "json":
        banner()
        section(f"Bytecode AA7702 scan — {label}")

    findings = detect_bytecode_aa7702(
        code_hex,
        is_delegation_target_hint=bool(getattr(args, "delegation_target", False)),
    )

    if fmt == "json":
        print(bytecode_findings_to_json(findings))
    elif compact_mode:
        for f in findings:
            d = f.to_dict()
            loc = d["location"]
            print(
                f"{label}:{d['pc']}:1: [{d['severity']}/?] "
                f"{d['rule_id']} {d['title']}"
            )
    else:
        if not findings:
            ok("No AA7702-* signals in bytecode.")
        else:
            for f in findings:
                d = f.to_dict()
                sev_color = {
                    "CRITICAL": C.RED, "HIGH": C.RED,
                    "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.DIM,
                }.get(d["severity"], C.DIM)
                print(
                    f"\n  {sev_color}[{d['severity']}]{C.RESET} "
                    f"{C.BOLD}{d['rule_id']}{C.RESET} {d['title']}"
                )
                print(f"    {C.DIM}PC={d['pc']}  opcode={d['opcode_hex']}  "
                      f"selector={d['selector'] or 'shared'}{C.RESET}")
                print(f"    {C.DIM}{d['description'][:200]}{C.RESET}")

    if getattr(args, "json_out", None):
        Path(args.json_out).write_text(
            bytecode_findings_to_json(findings), encoding="utf-8"
        )
        if not compact_mode and fmt != "json":
            ok(f"JSON: {args.json_out}")

    fail_on = getattr(args, "fail_on", None)
    if fail_on:
        gate = _SEV_RANK.get(fail_on.upper(), 99)
        for f in findings:
            sev = f.to_dict()["severity"]
            if _SEV_RANK.get(sev.upper(), 99) <= gate:
                return 1
    return 0


# ──────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chainedr",
        description="ChainEDR Analyzer - static Pectra-era smart-account scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
{C.BOLD}Commands:{C.RESET}
  scan     Static analysis: Solidity, EIP-7702, ZK, Noir, Aztec
  ci       CI/CD wrapper with SARIF output and severity gates
  prove    Evidence mode: PoCs, reports, benchmarks
  live     Optional runtime/on-chain workflows
  doctor   Check tool installations

{C.BOLD}Examples:{C.RESET}
  chainedr scan ./contracts
  chainedr ci ./contracts --profile auditor --out-dir chainedr-report
  chainedr scan ./contracts --format sarif --fail-on high
  chainedr ci init                           # Generate GitHub Action
  chainedr ci --target . --sarif out.sarif --fail-on critical
  chainedr prove demo --out demo_out
  chainedr prove poc ./contracts
  chainedr live monitor 0xA0b8...
  chainedr doctor

{C.DIM}v{__version__} | https://github.com/icedracon/chainedr{C.RESET}
""",
    )
    parser.add_argument("--version", action="version", version=f"ChainEDR v{__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")

    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── scan ──────────────────────────────────────────────────
    p_scan = subs.add_parser("scan", help="Main scanner")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "compact"], default="text",
                        help="text=banner+detail, compact=one-line per finding (IDE/grep-friendly)")
    p_scan.add_argument("--prove", action="store_true",
                        help="Emit Foundry .t.sol PoC skeletons for supported findings")
    p_scan.add_argument("--prove-on-finding", action="append", default=[],
                        metavar="RULE_ID",
                        help="Emit skeletons only for findings of this rule ID "
                             "(repeatable; implies --prove)")
    p_scan.add_argument("--prove-out", default="chainedr-poc", metavar="DIR",
                        help="Output directory for generated skeletons "
                             "(default chainedr-poc/)")
    p_scan.add_argument("--sarif", metavar="PATH", help="Write SARIF output")
    p_scan.add_argument("--json", dest="json_out", metavar="PATH", help="Write JSON output")
    p_scan.add_argument("--profile", choices=["default", "auditor"], default="default",
                        help="Output profile; auditor writes a reviewer report directory")
    p_scan.add_argument("--out-dir", dest="output_dir", metavar="DIR",
                        help="Report directory for --profile auditor")
    p_scan.add_argument("--fail-on", choices=["none", "critical", "high", "medium"],
                        help="Exit 1 if findings at this severity or above")
    p_scan.add_argument("--min-severity", type=str.upper,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default="LOW")
    p_scan.add_argument("--ignore", action="append", default=[], metavar="RULE")
    p_scan.add_argument("--no-external", action="store_true",
                        help="Skip external tools (Slither, etc)")
    p_scan.add_argument("--no-ast", action="store_true", help="Skip solc AST bridge")
    p_scan.add_argument("--deep", action="store_true",
                        help="Enable semantic/AST precision gates inside scan")
    p_scan.add_argument("--extended", action="store_true",
                        help="Enable opt-in experimental checks not yet fully FP-gated")
    p_scan.add_argument("--mythril", action="store_true", help="Enable Mythril (slow)")
    p_scan.add_argument("--external-timeout", type=int, default=120)
    p_scan.add_argument("--confirm", action="store_true",
                        help="Run opt-in dynamic confirmation for supported findings")
    p_scan.add_argument("--confirm-rpc-url", default=os.getenv("RPC_URL"),
                        help="RPC URL used for fork-mode confirmation (default: RPC_URL)")
    p_scan.add_argument("--confirm-eoa", default=None,
                        help="EOA address used by EIP-7702 confirmation probes")
    p_scan.add_argument("--confirm-implementation", default=None,
                        help="Delegation implementation address used by EIP-7702 probes")
    p_scan.add_argument("--confirm-fork-block", type=int, default=None,
                        help="Optional fork block for dynamic confirmation")
    p_scan.add_argument("--confirm-strict", action="store_true",
                        help="Treat confirmation infrastructure failure as scan failure")

    # ── ci ────────────────────────────────────────────────────
    p_ci = subs.add_parser("ci", help="CI/CD wrapper (chainedr ci [target] or chainedr ci init)")
    p_ci.add_argument("target", nargs="?", default=None, help="Target to scan (default: .)")
    p_ci.add_argument("--target", dest="target_opt", default=None,
                      help="Target to scan; kept for GitHub Action compatibility")
    p_ci.add_argument("--sarif", metavar="PATH")
    p_ci.add_argument("--json", dest="json_out", metavar="PATH")
    p_ci.add_argument("--profile", choices=["default", "auditor"], default="default",
                      help="Output profile; auditor writes a reviewer report directory")
    p_ci.add_argument("--out-dir", dest="output_dir", metavar="DIR",
                      help="Report directory for --profile auditor")
    p_ci.add_argument("--fail-on", choices=["none", "critical", "high", "medium"], default="high")
    p_ci.add_argument("--baseline", metavar="PATH",
                      help="Previous scan JSON for diff (only new findings)")
    p_ci.add_argument("--no-external", action="store_true")
    p_ci.add_argument("--no-ast", action="store_true")
    p_ci.add_argument("--deep", action="store_true")
    p_ci.add_argument("--extended", action="store_true")
    p_ci.add_argument("--min-severity", type=str.upper,
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                      default="LOW")
    p_ci.add_argument("--ignore", action="append", default=[])
    p_ci.add_argument("--external-timeout", type=int, default=120)
    p_ci.add_argument("--hook", choices=["precommit", "prepush"],
                      help="With `ci init`, also install a git hook that "
                           "runs `chainedr scan --format compact --fail-on "
                           "high` on staged Solidity files.")

    # ── prove ─────────────────────────────────────────────────
    p_prove = subs.add_parser("prove", help="Evidence/report mode")
    prove_sub = p_prove.add_subparsers(dest="prove_command")

    pp_demo = prove_sub.add_parser("demo", help="Generate a reviewer demo pack")
    pp_demo.add_argument("--out", dest="output_dir", default="demo_out")
    pp_demo.add_argument("--skip-benchmark", action="store_true")

    pp_bundle = prove_sub.add_parser("bundle", help="Build evidence Markdown from scan JSON")
    pp_bundle.add_argument("--from-json", required=True, metavar="PATH")
    pp_bundle.add_argument("-o", "--output", default="evidence_bundle.md")
    pp_bundle.add_argument("--source-root", default=None)
    pp_bundle.add_argument("--max-findings", type=int, default=25)

    pp_poc = prove_sub.add_parser("poc", help="Generate Foundry PoC reproducers")
    pp_poc.add_argument("target", nargs="?")
    pp_poc.add_argument("--from-json", metavar="PATH")
    pp_poc.add_argument("--output-dir", default="pocs/")
    pp_poc.add_argument("--include-uncertain", action="store_true")
    pp_poc.add_argument("--no-external", action="store_true")
    pp_poc.add_argument("--external-timeout", type=int, default=120)

    # ── doctor ────────────────────────────────────────────────
    subs.add_parser("doctor", help="Check tool installations")

    # ── bytecode ──────────────────────────────────────────────
    p_byte = subs.add_parser(
        "bytecode",
        help="Bytecode-level AA7702 detector (offline; no decompiler dependency)",
    )
    p_byte.add_argument(
        "target",
        help="Runtime bytecode in hex (with or without 0x prefix), "
             "the path to a file containing it, or an Ethereum address "
             "(use --rpc-url for the latter)",
    )
    p_byte.add_argument("--rpc-url", default=None,
                        help="RPC URL for eth_getCode if target is an address. "
                             "Defaults to $RPC_URL.")
    p_byte.add_argument("--delegation-target", action="store_true",
                        help="Treat the bytecode as a known EIP-7702 "
                             "delegation target; upgrades the AA7702-006 "
                             "DELEGATECALL severity from MEDIUM to HIGH.")
    p_byte.add_argument("--format", choices=["text", "json", "compact"],
                        default="text")
    p_byte.add_argument("--json", dest="json_out", metavar="PATH",
                        help="Write findings as JSON to PATH")
    p_byte.add_argument("--fail-on", choices=["none", "critical", "high", "medium"],
                        help="Exit 1 if findings at this severity or above")

    # ── watch ─────────────────────────────────────────────────
    p_watch = subs.add_parser(
        "watch",
        help="Re-scan Solidity sources on change (dev-time security linter)",
    )
    p_watch.add_argument("target", help="File or directory to watch")
    p_watch.add_argument("--interval", type=float, default=1.5,
                         help="Polling interval in seconds (default 1.5)")
    p_watch.add_argument("--format", choices=["text", "compact"], default="compact",
                         help="Output format on each re-scan (default compact)")
    p_watch.add_argument("--min-severity", type=str.upper,
                         choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                         default="LOW")
    p_watch.add_argument("--extended", action="store_true",
                         help="Enable opt-in experimental checks")
    p_watch.add_argument("--no-external", action="store_true",
                         help="Skip external tools (Slither, etc)")
    p_watch.add_argument("--no-ast", action="store_true")
    p_watch.add_argument("--deep", action="store_true")
    p_watch.add_argument("--ignore", action="append", default=[], metavar="RULE")

    return parser


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

def main():
    """ChainEDR Analyzer CLI entry point."""
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "verbose", False):
        import logging
        logging.basicConfig(level=logging.DEBUG)

    if not args.command:
        banner()
        parser.print_help()
        return

    handlers = {
        "scan": cmd_scan,
        "ci": cmd_ci,
        "prove": cmd_prove,
        "doctor": cmd_doctor,
        "watch": cmd_watch,
        "bytecode": cmd_bytecode,
    }

    handler = handlers.get(args.command)
    if handler:
        try:
            result = handler(args)
            if isinstance(result, int) and result > 0:
                sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{C.DIM}Interrupted.{C.RESET}")
            sys.exit(2)
        except Exception as e:
            fail(str(e))
            import traceback
            traceback.print_exc()
            sys.exit(2)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
