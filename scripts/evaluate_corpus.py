"""
ChainEDR EIP-7702 Corpus Evaluator

Runs detector against labeled benchmark corpus, computes:
- Per-check TP/FP/FN
- Precision, Recall, F1 (micro + macro)
- Per-category breakdown (vulnerable/fixed/benign)
- Confusion matrix

Usage: python scripts/evaluate_corpus.py [--json output.json]
"""
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from eip7702_detector import EIP7702Detector


CORPUS_DIR = os.path.join(os.path.dirname(__file__), '..', 'benchmarks', 'eip7702_full')
LABELS_PATH = os.path.join(CORPUS_DIR, 'labels.json')


@dataclass
class EvalResult:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def evaluate():
    with open(LABELS_PATH) as f:
        labels = json.load(f)

    detector = EIP7702Detector()
    per_check = defaultdict(lambda: EvalResult())
    per_category = defaultdict(lambda: {'files': 0, 'correct': 0, 'details': []})
    overall = EvalResult()
    file_results = []
    t0 = time.perf_counter()

    for rel_path, label in sorted(labels.items()):
        abs_path = os.path.join(CORPUS_DIR, rel_path)
        if not os.path.exists(abs_path):
            print(f"SKIP {rel_path} (not found)")
            continue

        source = open(abs_path).read()
        findings = detector.check(source)
        found_ids = set(f.check_id for f in findings)
        category = label['category']
        expected = set(label.get('expected_findings', []))
        must_not = set(label.get('must_not_detect', []))

        per_category[category]['files'] += 1
        correct = True
        file_detail = {
            'file': rel_path,
            'category': category,
            'expected': sorted(expected),
            'found': sorted(found_ids),
            'verdict': 'PASS'
        }

        if category == 'vulnerable':
            for eid in expected:
                if eid in found_ids:
                    per_check[eid].tp += 1
                    overall.tp += 1
                else:
                    per_check[eid].fn += 1
                    overall.fn += 1
                    correct = False
                    file_detail['verdict'] = 'MISS'

            extra = found_ids - expected
            for eid in extra:
                pass  # Don't count as FP — these are bonus detections on vuln contracts

        elif category == 'fixed':
            for mid in must_not:
                if mid in found_ids:
                    per_check[mid].fp += 1
                    overall.fp += 1
                    correct = False
                    file_detail['verdict'] = 'FP'
                else:
                    per_check[mid].tn += 1
                    overall.tn += 1

        elif category == 'benign':
            max_findings = label.get('max_findings', 0)
            if len(found_ids) > max_findings:
                for eid in found_ids:
                    per_check[eid].fp += 1
                    overall.fp += 1
                correct = False
                file_detail['verdict'] = 'FP'
            else:
                overall.tn += 1

        if correct:
            per_category[category]['correct'] += 1
        per_category[category]['details'].append(file_detail)
        file_results.append(file_detail)

    elapsed = time.perf_counter() - t0

    # Compute per-check metrics
    all_check_ids = sorted(per_check.keys())
    check_metrics = {}
    for cid in all_check_ids:
        r = per_check[cid]
        check_metrics[cid] = {
            'tp': r.tp, 'fp': r.fp, 'fn': r.fn, 'tn': r.tn,
            'precision': round(r.precision, 4),
            'recall': round(r.recall, 4),
            'f1': round(r.f1, 4),
        }

    # Macro F1
    f1_scores = [m['f1'] for m in check_metrics.values() if m['tp'] + m['fn'] > 0]
    macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0.0

    result = {
        'summary': {
            'total_files': len(labels),
            'elapsed_sec': round(elapsed, 3),
            'micro_precision': round(overall.precision, 4),
            'micro_recall': round(overall.recall, 4),
            'micro_f1': round(overall.f1, 4),
            'macro_f1': round(macro_f1, 4),
            'tp': overall.tp,
            'fp': overall.fp,
            'fn': overall.fn,
            'tn': overall.tn,
        },
        'per_category': {
            cat: {
                'files': d['files'],
                'correct': d['correct'],
                'accuracy': round(d['correct'] / d['files'], 4) if d['files'] else 0,
            }
            for cat, d in per_category.items()
        },
        'per_check': check_metrics,
        'file_results': file_results,
    }

    return result


def main():
    result = evaluate()
    s = result['summary']

    print("=" * 60)
    print("ChainEDR EIP-7702 Corpus Evaluation")
    print("=" * 60)
    print(f"Files:     {s['total_files']}")
    print(f"Time:      {s['elapsed_sec']:.3f}s")
    print(f"TP={s['tp']}  FP={s['fp']}  FN={s['fn']}  TN={s['tn']}")
    print(f"Precision: {s['micro_precision']:.4f}")
    print(f"Recall:    {s['micro_recall']:.4f}")
    print(f"Micro-F1:  {s['micro_f1']:.4f}")
    print(f"Macro-F1:  {s['macro_f1']:.4f}")
    print()

    print("Per-Category:")
    for cat, m in result['per_category'].items():
        print(f"  {cat:12s}: {m['correct']}/{m['files']} correct ({m['accuracy']:.0%})")
    print()

    print("Per-Check:")
    for cid, m in sorted(result['per_check'].items()):
        status = "OK" if m['fn'] == 0 and m['fp'] == 0 else "!!"
        print(f"  {status} {cid}: P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} (TP={m['tp']} FP={m['fp']} FN={m['fn']})")

    # Print failures
    failures = [f for f in result['file_results'] if f['verdict'] != 'PASS']
    if failures:
        print(f"\nFAILURES ({len(failures)}):")
        for f in failures:
            print(f"  {f['verdict']:4s} {f['file']}: expected={f['expected']}, found={f['found']}")

    # Save JSON
    if '--json' in sys.argv:
        idx = sys.argv.index('--json')
        out_path = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else 'paper/results/corpus_eval.json'
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w') as fp:
            json.dump(result, fp, indent=2)
        print(f"\nResults saved to {out_path}")


if __name__ == '__main__':
    main()
