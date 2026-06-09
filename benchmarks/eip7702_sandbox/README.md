# EIP7702-Bench

This corpus is the reproducible benchmark set for ChainEDR's EIP-7702
delegation and ERC-7562 validation-sandbox detectors.

The goal is to support the paper claim:

```text
ChainEDR performs pre-execution behavioral analysis of EIP-7702 delegated
accounts by mapping code patterns to explicit sandbox boundaries.
```

## Current Scope

Version: `1.1.0`

Current sample count:

```text
57 total samples
21 vulnerable samples
21 fixed controls
15 benign controls
```

The 21 positive samples cover 12 EIP-7702 delegation checks and 9 ERC-7562
validation checks. ChainEDR implements more EIP-7702 checks than are currently
represented in this corpus, so this benchmark should be described as a
target-rule regression corpus, not complete proof of all 30 checks.

## Files

```text
labels.json      Full 57-sample benchmark source of truth.
manifest.json    21-sample AA7562 validation-metadata subset.
eval_results.json
                 Generated full benchmark result from scripts/benchmark_evaluator.py.
statistical_results.json
                 Generated statistical summary from scripts/statistical_tests.py.
vulnerable/      Positive samples; each should trigger the expected rule.
fixed/           Fixed controls; each should not trigger the rule under test.
benign/          Benign controls; each should not trigger the rule under test.
```

`labels.json` uses two separate fields:

- `expected_rule`: the rule that must fire. This is set only for vulnerable samples.
- `rule_under_test`: the rule being regression-tested by a fixed or benign sample.

This avoids the earlier ambiguity where fixed/benign controls looked like they
were expected to trigger findings.

## Run Evaluation

From the repository root:

```powershell
python scripts\benchmark_evaluator.py --strict
```

Write paper/research results:

```powershell
python scripts\benchmark_evaluator.py --strict -o results\eip7702_benchmark_eval.json
```

Run the validation-sandbox metadata subset:

```powershell
python scripts\evaluate_eip7702_sandbox.py --strict -o results\eip7702_validation_eval.json
```

Expected full benchmark result for version `1.1.0`:

```text
Samples: 57
TP=21 FP=0 TN=36 FN=0 WRONG=0
precision=1.0000 recall=1.0000 f1=1.0000 specificity=1.0000
```

Expected validation-metadata subset result:

```text
Samples: 21
TP=9 FP=0 TN=12 FN=0 WRONG=0
boundary_accuracy=1.0000 trace_coverage=1.0000
```

These numbers are useful as regression checks. They are not enough by
themselves for final IEEE-level claims because the corpus is still synthetic
and has roughly one vulnerable sample per benchmarked detector.

## Growth Target

For a credible IEEE-style evaluation, grow this corpus to:

```text
300+ labeled samples
10+ vulnerable variants per detector family
10+ fixed or benign controls per detector family
realistic account, paymaster, bundler, and EntryPoint patterns
manual label-review notes
comparison outputs from Slither, Semgrep, Mythril, and Foundry where applicable
```

The final benchmark should report per-rule precision, recall, F1,
false-positive rate, runtime, sandbox-boundary accuracy, pre-behavior trace
coverage, and manually reviewed false-positive examples.
