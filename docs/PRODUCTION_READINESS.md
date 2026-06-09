# Production Readiness

## Current Verdict

ChainEDR Analyzer is not yet a full production audit product.

It is ready for private production-prep work in the `chainedr` private repo,
especially CI dry-runs, benchmark work, reviewer demos, and controlled scans on
authorized repositories.

It should not yet be marketed as production-ready until the release gates below
are satisfied.

## What Is Now Safe To Use

- `chainedr scan` for static candidate discovery.
- `chainedr ci` for report-only or severity-gated CI.
- JSON and SARIF output for GitHub artifacts and Code Scanning.
- Documented JSON report schema at
  [`schemas/chainedr-scan-report.schema.json`](../schemas/chainedr-scan-report.schema.json);
  SARIF uses SARIF 2.1.0.
- Documented held-out benchmark manifest schema at
  [`schemas/chainedr-blind-benchmark-manifest.schema.json`](../schemas/chainedr-blind-benchmark-manifest.schema.json).
- Documented competitor baseline matrix schema at
  [`schemas/chainedr-competitor-baseline-matrix.schema.json`](../schemas/chainedr-competitor-baseline-matrix.schema.json).
- `--deep` for slower AST-assisted precision gates.
- `--extended` for explicitly opt-in experimental checks.
- Proof metadata that marks findings as candidates unless confirmed.

## Production Release Gates

Implementation sequencing lives in
[`docs/PRODUCT_IMPLEMENTATION_PLAN.md`](PRODUCT_IMPLEMENTATION_PLAN.md).
The research-backed 10/10 upgrade path lives in
[`docs/CHAINEDR_10_10_RESEARCH_PLAN.md`](CHAINEDR_10_10_RESEARCH_PLAN.md).

Before calling ChainEDR Analyzer production-ready, require:

1. CI green on the private `analyzer` branch.
2. Full test suite passing locally and in GitHub Actions.
3. Strict benchmark unchanged or improved: `TP=21 FP=0 TN=36 FN=0`.
4. Stable JSON/SARIF schema documented and covered by tests.
5. GitHub Action smoke test with `--deep` and optional `--extended`.
6. AST-aware handling for the highest-value rules.
7. Call graph support for internal function reachability.
8. Modifier resolution for access-control checks.
9. Inheritance and override tracking.
10. Proxy-aware scanning for implementation and initializer surfaces.
11. Blind external benchmark against real public account-abstraction code,
    using the documented manifest schema and preserved triage statuses.
12. Competitor baseline against Slither, Semgrep, CodeQL, Aderyn, Mythril-style
    symbolic analysis, and ERC-4337 validation checkers, with measured outputs
    separated from installed-tool inventory.
13. Foundry PoC skeleton generation for critical confirmable findings.
14. One external reviewer pass on claims, docs, and false-positive behavior.

## Paper Gates

For the paper track, require:

1. Clear research question: what old assumptions become unsafe after an EOA can
   execute delegated code?
2. Taxonomy covering EIP-7702, ERC-4337, and ERC-7562 assumptions.
3. Labeled benchmark with vulnerable, fixed, and negative-control samples.
4. Blind held-out benchmark.
5. Baseline comparison against competing tools.
6. Metrics for precision, recall, specificity, runtime, and rule coverage.
7. Case studies that separate local-forced mechanics from live bounty findings.
8. Limitations section that says no confirmed external bounty-grade bug exists
   unless one is actually found and responsibly disclosed.

## Forbidden Production Claims

Do not claim:

- finished Web3 EDR;
- production runtime monitor;
- confirmed bounty-grade finding;
- exploit confirmation from static findings alone;
- replacement for Slither, CodeQL, or human audit review.

Allowed claim:

> ChainEDR Analyzer is a focused EIP-7702 / ERC-4337 / ERC-7562 research
> prototype that finds delegated-account risk candidates, generates proof
> guidance, and uses fork PoCs where possible to confirm or refute impact.
