# ChainEDR External Blind Benchmark

This folder is a template for third-party or held-out validation corpora.

Recommended workflow:

1. Copy external Solidity samples into a separate corpus directory.
2. Create a manifest using `manifest.example.json`.
   The input contract is documented in
   `schemas/chainedr-blind-benchmark-manifest.schema.json`.
3. Run unlabeled first:

```bash
python scripts/evaluate_blind_benchmark.py --corpus <corpus> --manifest <manifest> -o results/blind.json
```

4. Freeze the result JSON with sample hashes.
5. Reveal labels in the manifest and rerun with `--strict --require-labels`.

This separates discovery from scoring and helps prevent benchmark overfitting.
Vulnerable labels must include `expected_rule`. Negative/control labels
(`benign`, `safe`, `fixed`, or `negative`) should keep the evaluated rule in
`rule_under_test` and leave `expected_rule` as `null`.

The output includes:

- overall precision, recall, specificity, accuracy, and F1;
- per-rule counts and per-rule metrics;
- an expected-vs-detected `confusion_matrix`;
- `detected_rule_counts`, label inventory, content hashes, and runtime summary.

Result triage statuses:

- `needs_label_reveal`: unlabeled sample produced a detection; freeze the hash
  and label independently before scoring.
- `needs_negative_control_review`: unlabeled sample was clean; confirm it is a
  negative/control sample before treating it as true negative evidence.
- `needs_investigation`: labeled sample produced FP/FN/wrong-class behavior.
- `scored`: labeled sample scored as TP or TN.
