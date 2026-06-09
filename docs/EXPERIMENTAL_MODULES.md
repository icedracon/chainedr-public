# Experimental vs. Beta Surface

This doc draws an explicit line between the **ChainEDR Analyzer beta
surface** — the modules a reviewer should evaluate — and the
**experimental research surface** — modules kept in-tree because they
informed the analyzer's design but that are not part of the beta
contract. Treat experimental modules as research scratch that may
break, get rewritten, or be removed without notice.

This separation lets the next round of polish delete or extract the
experimental surface without breaking the beta CLI.

---

## Beta surface (supported)

These modules implement the `chainedr` CLI and the Pectra-era checks
the beta is judged on. They are covered by tests, the labelled
benchmark, and the 25-sample held-out corpus.

### CLI / wiring

- `cli.py` — `chainedr scan` / `ci` / `prove` / `live` / `doctor` /
  `watch`.
- `__main__.py` — legacy commands routed through the new CLI.
- `beta_cli.py` / `beta_semantics.py` — release-candidate CLI shims.
- `detector_plugin.py` — `Detector` / `Finding` plugin contract.
- `project_context.py` — file discovery / project-type classification.
- `config.py` / `logger.py` / `utils.py` — common infrastructure.

### EIP-7702 / ERC-4337 / ERC-7562 static core

- `eip7702_detector.py` — the 21 AA7702-* checks + alias / state-flow
  passes + access-gating helpers.
- `eip7702_extensions.py` — extended AA7702-022..026 checks.
- `eip7702_validation.py` — AA7562-* validation-sandbox checks.
- `eip7702_sandbox.py` — pre-behavior trace / sandbox policy
  metadata attached to every finding.
- `eip7702_reporting_hardening.py` — finding-construction
  normalisation (severity / wording).
- `erc4337_checker.py` / `erc7821_checker.py` /
  `mev_and_erc6900_checker.py` — adjacent module families.

### Proof / evidence

- `evidence.py` — demo packs + reviewer-facing evidence bundles.
- `poc_skeletons.py` — Foundry `.t.sol` skeleton generator.
- `proof_adapters.py` — proof-recipe attachment.
- `reviewer_confidence.py` — A/B/C/D evidence grading.
- `confirmation.py` — opt-in dynamic confirmation entry point.
- `fork_oracle.py` / `differential_oracle.py` — fork-mode oracles.
- `bytecode_oracle.py` — bytecode-reach prober.

### Output / CI

- `sarif_output.py` — SARIF 2.1 emitter for GitHub Code Scanning.
- `reporter.py` — Markdown / JSON / executive-summary writer.
- `static_analyzer.py` — generic Solidity static analyzer used by
  the legacy entry points.

### Detector plugins / external tool bridges

- `detectors_builtin.py` — registers the EIP-7702 and Extended Pectra
  detectors with the plugin registry.
- `slither_bridge.py` / `mythril_bridge.py` / `semgrep_bridge.py` /
  `wake_bridge.py` / `halmos_bridge.py` / `echidna_bridge.py` /
  `pyrometer_bridge.py` / `ast_bridge.py` — competitor / external
  tool integrations. Used as optional inputs, never required for the
  beta CLI.
- `semantic_index.py` / `semantic_ir.py` / `ast_scope.py` /
  `ast_utils.py` / `call_graph.py` / `compiler_correlator.py` /
  `solidity_project_model.py` — semantic precision layer.

### FP filtering / cross-tool

- `fp_filter.py` / `fp_suppressor.py` / `cross_tool_dedup.py` /
  `prior_audit_dedup.py` — universal suppression primitives.
- `bridge_detectors.py` — bridge-aware checks used by the plugin path.
- `owasp_2026.py` — additional OWASP-2026 advisory checks.

### Tests / data

- `tests/` (repo-root) + `test_*.py` (under `src/`) — pytest suite.
- `benchmarks/eip7702_sandbox/` — labelled 57-sample corpus.
- `benchmarks/holdout_v1/` — 25-sample generalisation corpus.
- `scripts/benchmark_evaluator.py` —
  `scripts/holdout_evaluator.py` —
  `scripts/competitor_baseline.py` —
  `scripts/perf_benchmark.py`.
- `schemas/chainedr-scan-report.schema.json`.

---

## Experimental surface — removed

In the **10/10-beta cleanup sweep** every module in this section was
deleted from the tree. They are listed here for historical record only;
recovering them means `git checkout` of a pre-cleanup commit.

- `brain.py` — fuzzing PoC engine.
- `anomaly_engine.py` — runtime anomaly detection (the original "EDR"
  framing). Out of scope; ChainEDR is positioned Analyzer-first.
- `classifier.py` / `_classifier_core.py` / `classifier/` — ML
  classifier prototypes.
- `monitor.py` / `live_7702_hunt.py` / `bytecode_analyzer.py` —
  on-chain monitoring and harvest.
- `attack_graph.py` / `exploitability_graph.py` /
  `attack_vectors.py` — research-grade exploitability modelling.
- `fuzzer.py` / `invariant_fuzzer.py` / `invariants.py` /
  `invariants/` — fuzzing infrastructure.
- `protocol_invariants.py` / `protocol_checker.py` /
  `protocol_classifier.py` — broad DeFi protocol classifiers.
- `audit_orchestrator.py` / `audit_db_scraper.py` /
  `defihacklabs_similarity.py` — audit-DB scrape and similarity work.
- `commercial_detectors.py` — placeholder for commercial detector
  extensions.
- `competitive_gap.py` — competitive-analysis scratch.
- `euler_empirical.py` / `mixer_detector.py` / `bounty_verdict.py` /
  `infinifi_extract.py` / `eval_hacks.py` — bounty-hunt scratch.
- `ripio_batch_scan.py` / `ripio_deep_audit.py` — one-off audit
  scripts.
- `poc_generator.py` / `poc_verifier.py` — older PoC generation
  paths superseded by `poc_skeletons.py`.
- `minimizer.py` / `verifier.py` / `taint.py` — early prototypes.
- `models.py` / `database.py` / `pipeline.py` / `explorer.py` /
  `profiler.py` / `exploit.py` / `calibrator.py` / `hunter.py` /
  `batch_scan.py` / `bench_runner.py` / `upgrade_diff.py` /
  `abi_discovery.py` / `evm_tracer.py` / `evm_tracer/` /
  `oracle/` / `flashloan/` / `tracer/` / `eip_parser/` /
  `compiler/` / `references/` / `data/` / `archive/` /
  `generated/` / `benchmark/` / `templates/` / `foundry/` /
  `universal_features.py` / `reporter.py` / `foundry_gen.py` —
  legacy command stack and unrelated scratch.
- `erc721_checker.py` — pre-7702 ERC-721 specific checker.
- `proxy_checker.py` — superseded by AA7702-009.
- `llm_triage.py` — LLM triage prototype.

`__main__.py` is now a 13-line shim that re-exports `cli.main` so
`python -m chainedr` still works. The 4,500-line legacy command
stack it used to host is gone.

---

## Beta contract

A change to the beta-surface list above needs a CHANGELOG entry, a
passing benchmark + holdout run, and a green test suite. If you find
yourself adding an experimental module back, push it into a separate
research repository or branch instead — the cleanup contract is one of
the things the 10/10 beta is judged on.
