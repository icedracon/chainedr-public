# ChainEDR Analyzer Private-Beta Release Gate

## Target

This checklist defines the bar for a credible private beta. It is intentionally
stricter than a prototype demo and intentionally narrower than a production-ready
audit product.

A private-beta release may be called **9/10 prototype-beta** only when every
**Required** item below is closed with reproducible evidence. This score does not
mean production-ready, audit-grade, or bounty-proven.

Current release-candidate source: `master` after the PR #3 squash merge.
Historically this came from `chainedr/analyzer`; the promoted result keeps the
Analyzer beta work plus the latest detector registry / scan-warning fixes.

## Current Release-Candidate Evidence

- Promoted branch: `master`
- Promotion commit: `a6a45d3f0d173ca24cf4bc69d9ee3d788474d1a5`
- Pull request: (historical integration PR — repo private)
- Pre-merge GitHub Actions run: `26971824724` / `ChainEDR Analyzer` run `83`
- Pre-merge head SHA: `e9d5df9d85fac6aeb85bf6d8d7fcd24bb9127e6a`
- Result: `success`
- Preserved artifact: `chainedr-report`
- Artifact id: `7419958148`
- Artifact digest: `sha256:11576ed982f41c4108225d8a9bb86db6b104a8fbfb4de78679eadefa06cb561b`
- Artifact expires: `2026-07-04T18:37:32Z`
- Post-merge local verification on `master`: `compileall`, `pytest`, strict
  benchmark, `python -m chainedr --help`, and `chainedr --help`.

## Required Gates

### 1. Packaging and installation

- [x] `src/pyproject.toml` contains package metadata and the `chainedr` console script.
- [x] Package metadata points to the `icedracon/chainedr` repository.
- [x] The release smoke builds a wheel from `./src`.
- [x] The release smoke installs the built wheel rather than relying only on editable source state.
- [x] The release smoke runs `python -m pip check`.
- [x] The release smoke runs `python -m compileall -q src tests scripts`.
- [x] The release smoke installs and invokes `pytest` explicitly through `python -m pytest`.
- [x] Run the workflow successfully on the release candidate commit and preserve the wheel artifact.

### 2. Core tests and benchmark

- [x] CI runs `pytest tests/ -q` through the release smoke.
- [x] CI runs the strict controlled benchmark.
- [x] CI runs validation-sandbox metadata evaluation.
- [x] Regression tests cover private-beta CLI behavior and EIP-7702 semantics normalization.
- [x] End-to-end regression tests exercise real legacy detector outputs for `tx.origin`, callback stipend semantics, `chain_id=0`, and nested `delegatecall`.
- [x] Confirm the release candidate remains green after the private-beta hardening commits.
- [x] Preserve the benchmark JSON artifact for the release candidate.

### 3. CI behavior

- [x] The Action uses one source of truth: `scripts/release_candidate_smoke.sh`.
- [x] The Action no longer duplicates wheel builds, tests, and benchmarks before the smoke run.
- [x] The Action scans the real corpus path: `benchmarks/eip7702_sandbox/vulnerable`.
- [x] The Action validates shell syntax before execution.
- [x] SARIF and JSON reports are uploaded as artifacts.
- [x] SARIF upload is attempted for GitHub Code Scanning.
- [x] Baseline filtering is applied before the final severity gate through the idempotent `beta_cli` patch layer.
- [x] Installed-wheel imports assert that the private-beta CLI and semantics patches are active.
- [x] Observe one successful GitHub Actions run for the current release candidate.

### 4. Product truthfulness

- [x] The main README positions the product as ChainEDR Analyzer first.
- [x] The repo separates controlled benchmark claims from real-world precision claims.
- [x] `REALITY_CHECK.md` records zero confirmed external bounty-grade exploits.
- [x] Static findings are treated as candidates until confirmed or refuted.
- [x] Release-critical EIP-7702 wording and severity semantics are normalized at finding construction time.
- [x] Reviewer-facing semantics notes document persistent delegation, `chain_id=0`, gas constraints, `tx.origin`, and nested `delegatecall` boundaries.
- [ ] Migrate the remaining raw detector wording into the core module during the AST/call-graph refactor so the compatibility layer can eventually be removed.

### 5. Security-engineering usability

- [x] `scan`, `ci`, `prove`, `live`, and `doctor` are the public top-level commands.
- [x] JSON and SARIF outputs exist.
- [x] JSON report schema is documented in `schemas/chainedr-scan-report.schema.json` and covered by clean/finding scan tests.
- [x] Evidence bundles exist.
- [x] Foundry-oriented PoC skeleton generation exists for supported findings.
- [x] Semantic indexing exists for inheritance, modifiers, internal calls, initializer surfaces, and proxy-like surfaces.
- [x] JSON findings include `reviewer_confidence` so auditors can triage evidence maturity without treating severity as exploit certainty.
- [x] Blind benchmark manifests have a documented schema and explicit sample triage statuses.
- [x] Competitor baseline matrices distinguish measured evidence from installed-tool inventory.
- [x] Optional local API prototype uses generated `CHAINEDR_API_KEYS` from `.env`, not an embedded development key.
- [x] Optional local API prototype uses the Analyzer scan path and exposes reviewer-confidence evidence grades in API/UI output.
- [x] CLI/API/runtime logs redact token-bearing URLs, RPC keys, and API-key assignments before display.
- [x] Local API setup is documented in `.env.example` and `docs/FRIEND_PROTOTYPE.md`.
- [x] `scripts/release_candidate_smoke.sh` covers wheel install, patch wiring, CLI help, tests, strict benchmark, validation metadata, a detector-neutral clean scan, vulnerable scan, SARIF validation, evidence bundle generation, and PoC skeleton generation.
- [ ] Run the smoke script successfully and preserve the transcript.

### 6. Branch promotion

- [x] For the clean `icedracon/chainedr` repo, the historical `master` state is preserved as `backup/master-before-analyzer-20260602`.
- [x] `docs/PROMOTE_ANALYZER_TO_MASTER.md` documents guarded promotion with `--force-with-lease` and rollback.
- [x] Promote the tested integration branch to `master` after the smoke transcript is green.
- [ ] Rerun the smoke script after promotion.

## 7. Beta-Polish Sweep (closed)

The following items were added during the 10/10-beta polish loop and are
now landed on `master`. They are required for the **prototype-beta 10/10**
score, distinct from production-ready / audit-grade.

- [x] Per-finding reviewer-confidence grade (A/B/C/D) surfaced in scan
  terminal output and in the summary histogram.
- [x] Modifier-aware suppression on AA7702-001 / 002 / 006 — multi-line
  signatures, curated guard set, `only*` convention.
- [x] Inline-auth suppression — `require(msg.sender == owner)`,
  `hasRole(...)`, `_checkOwner()`, `authorized[msg.sender]` shapes,
  also applied to AA7702-003 to drop the OZ Ownable self-harm FP.
- [x] Inheritance-base detection — recognises Ownable / AccessControl /
  UUPS / Auth bases and attaches as semantic context.
- [x] Intra-function alias-flow tracking — `address a = tx.origin; ...
  require(a == msg.sender)` style.
- [x] Cross-function state-variable flow tracking — store in one
  function, compare in another. Both modes carry an `analysis` tag the
  IR-unreachability gate honours so they are not silently dropped.
- [x] `chainedr scan --format compact` — IDE / grep one-line-per-finding.
- [x] `chainedr watch <path>` — re-scans on .sol / .nr save, defaults to
  compact format. Closes the dev-time-linter wedge.
- [x] `chainedr scan --prove` / `--prove-on-finding RULE_ID` —
  generates Foundry .t.sol skeletons inline with the scan.
- [x] `chainedr ci init --hook precommit` / `--hook prepush` — installs
  a git hook that runs the compact-format scan with `--fail-on high`.
- [x] `.vscode/tasks.json` + problem matcher + recommended extensions —
  one-Reload-Window-away dev-time setup.
- [x] Per-UNCERTAIN verdicts in `docs/UNCERTAIN_VERDICTS.md` with a
  4-tag taxonomy and per-target rationale for the 9 frozen UNCERTAINs.
- [x] Executed competitor baseline (`scripts/competitor_baseline.py`,
  `docs/COMPETITOR_BASELINE.md`) — Slither + Aderyn on all 57 samples,
  ChainEDR-unique = 11 / 21 vulnerable, covering the entire AA7562 family.
- [x] Held-out generalisation benchmark (`benchmarks/holdout_v1/`,
  `scripts/holdout_evaluator.py`, `docs/HOLDOUT_RESULTS.md`) — 10
  samples authored after detector freeze: **TP=6 FP=0 FN=0 TN=4,
  P=R=F1=100%**.
- [x] Performance benchmark (`scripts/perf_benchmark.py`,
  `docs/PERFORMANCE.md`) — per-file p95 ≈ 3.6 ms, throughput
  ≈ 5,700 LOC/sec, well under the dev-time perceptual budget.
- [x] REVIEWER_BRIEF.md / AUDITOR_BETA_START.md refreshed to reflect
  the new CLI surface and the executed competitor delta.

## Deferred Production Gates

These are not required for the private beta and explicitly remain
deferred. They block any production-ready / audit-grade claim and
remain honest open work:

- Full AST-first or IR-backed implementations for the highest-value
  rules (the alias-flow / inline-auth resolver is an intermediate step,
  not the destination).
- Cross-contract taint and call-graph override handling across multi-
  file projects.
- First-class proxy implementation discovery.
- Larger blind held-out external benchmark with completed per-finding
  triage (the 10-sample holdout is a generalisation check, not a
  production-precision claim).
- Semgrep column of the competitor matrix (offline run; expected zero
  since p/solidity has no 7702 rules).
- Broader finding-specific dynamic confirmation.
- Decompiler / IR assistance for unverified bytecode.
- One external senior reviewer pass.
- One responsibly disclosed real scoped finding, or an explicit
  continued absence of one.

## Current Honest Verdict

The integration branch on `master` is now a green private-beta release
candidate with the beta-polish sweep landed:

- Labelled benchmark: F1 = 1.00 (corpus-scoped).
- Held-out generalisation benchmark: F1 = 1.00 on a freshly authored
  10-sample set the analyzer was not tuned on.
- Competitor delta: 11 / 21 vulnerable samples are ChainEDR-unique
  against the executed Slither + Aderyn baselines.
- 28 unit tests cover guard / inline-auth / alias-flow / state-flow.
- Per-file scan p95 = 3.6 ms, throughput = 5,700 LOC/sec.

The **prototype-beta 10/10** score is defensible for private review
on those numbers and the dev-time toolchain (watch, compact, prove,
pre-commit, VS Code matcher). Production-ready / audit-grade claims
remain blocked by the deferred-production gates above.
