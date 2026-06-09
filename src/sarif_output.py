"""
ChainEDR — SARIF (Static Analysis Results Interchange Format) Output

GitHub Code Scanning / Azure DevOps / VS Code consume SARIF.
Converting ChainEDR findings → SARIF makes us first-class in CI pipelines.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Usage:
    from src.sarif_output import to_sarif_v2_1_0

    sarif = to_sarif_v2_1_0(findings, repo_url='https://github.com/foo/bar')
    Path('chainedr.sarif').write_text(json.dumps(sarif, indent=2))

    # Then in GitHub Actions:
    # - uses: github/codeql-action/upload-sarif@v3
    #   with:
    #     sarif_file: chainedr.sarif
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


_DIGITS_RE = re.compile(r"\d+")


def finding_fingerprint(f: Dict) -> str:
    """Stable cross-run identity for a finding, used for SARIF partialFingerprints
    and CI baseline diffing.

    Built from check class + file basename + function + a digit-normalized slice of
    the description. Deliberately excludes the line number and absolute path so the
    fingerprint survives line drift and machine/CI path differences — two scans of
    the same issue produce the same id, a genuinely new issue produces a new one.
    """
    check = str(f.get("check", "unknown"))
    raw_file = str(f.get("file", "") or "")
    base = raw_file.replace("\\", "/").rsplit("/", 1)[-1]
    func = str(f.get("function", "") or "")
    # Normalize the description: drop digits (line refs, counts, addresses) and
    # collapse whitespace so cosmetic wording-with-numbers changes don't churn ids.
    desc = _DIGITS_RE.sub("#", str(f.get("description", "") or ""))
    desc = " ".join(desc.split())[:160]
    key = "|".join((check, base, func, desc))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _is_suppressed(f: Dict) -> Optional[str]:
    """Return a suppression justification if this finding should render as
    suppressed in SARIF (GitHub greys it out), else None."""
    if f.get("advisory"):
        return "informational advisory (fires on correct code; not a vulnerability)"
    verdict = str(f.get("verdict", "")).upper()
    fp_verdict = str((f.get("fp_analysis") or {}).get("verdict", "")).upper()
    if verdict == "FALSE_POSITIVE" or fp_verdict in ("FALSE_POSITIVE", "LIKELY_FP"):
        reason = (f.get("fp_analysis") or {}).get("reason") or "triaged as false positive"
        return str(reason)[:300]
    return None


# SARIF severity is "error" | "warning" | "note" | "none"
_SARIF_LEVEL = {
    'CRITICAL': 'error',
    'HIGH':     'error',
    'MEDIUM':   'warning',
    'LOW':      'note',
    'INFORMATIONAL': 'note',
    'INFO':     'note',
}


def to_sarif_v2_1_0(findings: List[Dict],
                      tool_version: str = '2.0.0',
                      repo_url: Optional[str] = None) -> Dict:
    """
    Convert ChainEDR findings to SARIF v2.1.0.
    Returns dict suitable for json.dumps + upload to GitHub Code Scanning.
    """
    # Build rule registry from unique check classes
    rules_seen: Dict[str, Dict] = {}
    for f in findings:
        check = f.get('check', 'unknown')
        if check not in rules_seen:
            rules_seen[check] = {
                'id':              check,
                'name':            check.replace('_', ' ').title(),
                'shortDescription': {
                    'text': (f.get('description', '') or check)[:120],
                },
                'fullDescription': {
                    'text': (f.get('description', '') or '')[:600],
                },
                'helpUri':         f"https://github.com/icedracon/chainedr/wiki/{check}",
                'properties': {
                    'tags': [
                        'security',
                        f"owasp-{f.get('owasp_2026', 'unclassified')}",
                    ],
                    'precision': 'medium',
                },
                'defaultConfiguration': {
                    'level': _SARIF_LEVEL.get(f.get('severity', 'MEDIUM'), 'warning'),
                },
            }

    rules = list(rules_seen.values())

    # Build results
    results = []
    for f in findings:
        check = f.get('check', 'unknown')
        attack_vectors = f.get('attack_vectors', [])
        primary_vector = attack_vectors[0] if attack_vectors else {}
        fp_analysis = f.get('fp_analysis', {})

        # Build message with key context
        msg_parts = [f.get('description', '') or check]
        if primary_vector.get('verdict'):
            msg_parts.append(
                f"\n[ChainEDR verdict: {primary_vector['verdict']}, "
                f"confidence: {primary_vector.get('verdict_confidence', 0):.0%}]"
            )
        if primary_vector.get('verdict_reason'):
            msg_parts.append(f"\nReason: {primary_vector['verdict_reason'][:300]}")
        if fp_analysis.get('rule'):
            msg_parts.append(f"\nFP-Rule: {fp_analysis['rule']}")

        # Location
        file_path = f.get('file', '') or 'unknown'
        line = f.get('line', 1) or 1

        fpr = finding_fingerprint(f)
        result = {
            'ruleId':  check,
            'level':   _SARIF_LEVEL.get(f.get('severity', 'MEDIUM'), 'warning'),
            'message': {
                'text': ' '.join(msg_parts)[:2000],
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri':       file_path,
                    },
                    'region': {
                        'startLine': max(1, int(line)),
                    },
                },
            }],
            # Stable identity so GitHub Code Scanning tracks a finding across runs
            # instead of re-opening it on every push.
            'partialFingerprints': {
                'chainedrFingerprint/v1': fpr,
            },
            'properties': {
                'severity':            f.get('severity', 'MEDIUM'),
                'confidence':          f.get('confidence', 0.5),
                'check_class':         check,
                'function':            f.get('function', ''),
                'source_tool':         f.get('source_tool', 'chainedr'),
                'owasp_2026':          f.get('owasp_2026', ''),
                'attack_verdict':      primary_vector.get('verdict', ''),
                'verdict_confidence':  primary_vector.get('verdict_confidence', 0.0),
                'fp_label':            fp_analysis.get('verdict', ''),
                'fp_reason':           fp_analysis.get('reason', ''),
                'is_novel':            f.get('is_novel', True),
            },
        }
        # Emit SARIF suppression metadata for advisories / triaged FPs so they are
        # auditable but greyed out in GitHub rather than failing review.
        supp = _is_suppressed(f)
        if supp:
            result['suppressions'] = [{
                'kind': 'inSource' if f.get('advisory') else 'external',
                'justification': supp,
            }]
        results.append(result)

    sarif = {
        '$schema': 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name':    'ChainEDR',
                    'version': tool_version,
                    'semanticVersion': tool_version,
                    'informationUri': repo_url or 'https://github.com/icedracon/chainedr',
                    'rules':   rules,
                    'shortDescription': {
                        'text': 'Bounty-grade exploitability triage for EVM smart contracts',
                    },
                },
            },
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': datetime.now(timezone.utc).isoformat(),
            }],
            'results': results,
            'properties': {
                'finding_count':    len(findings),
                'rule_count':       len(rules),
            },
        }],
    }
    return sarif


def write_sarif(findings: List[Dict], output_path: str,
                tool_version: str = '2.0.0', repo_url: Optional[str] = None) -> None:
    """Write findings to a SARIF file."""
    sarif = to_sarif_v2_1_0(findings, tool_version=tool_version, repo_url=repo_url)
    Path(output_path).write_text(json.dumps(sarif, indent=2))
