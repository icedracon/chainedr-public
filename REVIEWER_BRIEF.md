# ChainEDR - Reviewer Brief

This is the short, honest path for a senior Web3 security reviewer.

## One-sentence framing

ChainEDR Analyzer is a research prototype for Pectra-era static security
analysis: it asks what old Solidity/account-abstraction assumptions become
unsafe after an EOA can execute delegated code, then attaches proof guidance so
selected findings can be confirmed or refuted.

## What to look at first

1. `REALITY_CHECK.md`
   - Honest metrics, false-positive history, and trophy count.
   - Current trophy count is still zero.

2. `src/eip7702_detector.py`
   - Core EIP-7702 static detector surface.
   - This is still partly pattern-based; it is not a full semantic analyzer.

3. `docs/ANALYZER_POSITIONING.md`
   - The corrected product boundary: Analyzer first, Monitor optional.
   - The milestone checklist: AST, call graph, modifiers, inheritance, proxies,
     blind benchmarks, and Foundry skeletons.

4. `src/fork_oracle.py`, `src/bytecode_oracle.py`
   - The interesting differentiator: dynamic and bytecode-native confirmation.
   - Bytecode profile is prioritization only; dynamic trace evidence is the proof step.

5. `poc/woofi_stale_oracle/RUN_LOG.md`
   - A concrete Foundry fork proof harness that proves mechanics locally and
     records why the live target path is not submit-ready.

6. `docs/PATH_A_SCOPE.md`
   - Current reach roadmap for unverified deployed delegators.

## Suggested 10-minute demo

Install:

```bash
python -m pip install -e ./src
```

Run core tests and benchmark:

```bash
pytest tests/ -q
python scripts/benchmark_evaluator.py --strict
```

Run a local static scan:

```bash
chainedr scan benchmarks/eip7702_sandbox/vulnerable --no-external --deep --json chainedr.json
```

Open one `AA7702-*` JSON finding and point at `proof_recipe` /
`proof_adapters` plus the new `reviewer_confidence.grade` (A/B/C/D).

One-line-per-finding output for IDE / grep pipelines:

```bash
chainedr scan benchmarks/eip7702_sandbox/vulnerable --format compact
```

Dev-time security linter (re-scans on every `.sol` save, compact output):

```bash
chainedr watch . --extended
```

Scan and emit Foundry PoC skeletons for matched findings inline:

```bash
chainedr scan src/ --format compact --prove --prove-on-finding AA7702-001
```

Reproduce the executed Slither delta on the 57-sample corpus:

```bash
python scripts/competitor_baseline.py --skip-aderyn --skip-semgrep
cat docs/COMPETITOR_BASELINE.md
```

Profile deployed bytecode without source:

```bash
chainedr live bytecode 0x27dbd0e71b85700e29994d6d3a51f2e32442aa61 --format json
```

Generate reviewer evidence from a JSON scan:

```bash
chainedr prove bundle --from-json chainedr.json -o evidence_bundle.md --source-root .
```

Optional proof-discipline demo:

```bash
cd poc/woofi_stale_oracle
bash scripts/run_fork_test.sh base 26797218 testLocal_forcedCloPreferredStalePriceTransfersExcessBase
```

This proves stale-oracle mechanics after locally forcing a blocked config. It is
not a live bounty finding.

## Strongest parts

- Narrow, relevant niche: EIP-7702 delegated EOAs and account-abstraction validation boundaries.
- Correct competitor frame: Slither, Semgrep, CodeQL, Aderyn, Mythril-style
  symbolic analysis, custom audit scripts, and ERC-4337 validation checkers.
- Benchmark and CI are real, not just a one-off script.
- **Executed competitor delta** (`docs/COMPETITOR_BASELINE.md`): on the labelled
  57-sample corpus, ChainEDR fires on 21/21 vulnerable samples, Slither on 5/21;
  16 vulnerable samples have a ChainEDR rule fire with no competitor finding.
- Modifier-aware + inline-auth + cross-function-state-flow suppression on
  AA7702-001/002/006 — the three highest-volume detectors no longer fire on
  functions guarded by `onlyOwner`, `onlyRole`, `require(msg.sender == owner)`,
  `hasRole(...)`, `_checkOwner()`, or `authorized[msg.sender]` style gates.
- Dev-time security linter (`chainedr watch`, `--format compact`, VS Code
  problem matcher, `chainedr ci init --hook precommit`) — this is the wedge
  over audit-phase scanners; ChainEDR is the first tool you run in the
  Foundry/Hardhat dev loop, not just the last.
- Per-finding **evidence grade** A/B/C/D surfaced in the terminal and JSON so
  severity ("how bad") and confidence ("how proven") are read separately.
- `chainedr scan --prove` / `--prove-on-finding RULE_ID` writes Foundry
  `.t.sol` PoC skeletons inline with the scan.
- Dynamic confirmation exists and is intentionally separated from static suspicion.
- A real Foundry fork PoC harness exists and fails closed when live preconditions
  are not satisfied.
- Findings now carry proof plans for behavior flips, signature/domain replay,
  ERC-1271/6492, ERC-4337 UserOp validation, and bytecode reach.
- The project documents false positives and null results instead of hiding them.
- The 9 frozen UNCERTAINs are individually documented in
  [`docs/UNCERTAIN_VERDICTS.md`](docs/UNCERTAIN_VERDICTS.md) with a 4-tag
  taxonomy and per-target rationale.
- Bytecode reach is the right direction because many live 7702 implementations are unverified.

## Weakest parts

- Static core is partly regex with an alias-flow / inline-auth resolver bolted
  on; not yet Slither-IR/AST-first.
- Internal-call following and cross-contract taint are still missing — the
  cross-function pass handles state-variable aliases within one file only.
- Benchmark F1=1.00 is corpus-scoped, not production precision.
- Dynamic confirmation supports only a limited set of bug classes.
- Bytecode analysis is still early; no decompiler-backed path yet.
- Aderyn and Semgrep columns of the competitor matrix are still pending the
  offline full run.
- The repo has research sprawl: ML, replay, invariant hunt, and broad DeFi
  modules should be treated as experimental.
- No confirmed live bounty-grade exploit has been found.

## What would make it audit-grade

1. Replace the highest-value regex checks with AST/call-graph-backed rules.
2. Lift the alias-flow pass into a full intra-contract taint analysis with
   overridden-function handling and internal-call following.
3. Make proxy-aware scanning first class.
4. Expand dynamic confirmation from class probes to finding-specific probes.
5. Add a decompiler/IR layer for unverified bytecode.
6. Complete the Aderyn + Semgrep columns of the competitor matrix and add a
   blind held-out labeled dataset to back the precision claim.
7. Find and responsibly disclose one real scoped issue.

## Claims not being made

- Not production-ready.
- Not a replacement for manual audit.
- Not proven to find live bounty bugs.
- Not 100% accurate outside the labeled benchmark.
- Not a general Solidity vulnerability scanner.

## Recommended reviewer question

"Is ChainEDR Analyzer useful as a Pectra-era static analyzer, and which static
semantic layer matters most next: AST, call graph, modifiers, inheritance,
proxy awareness, or Foundry skeleton generation?"
