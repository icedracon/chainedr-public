# Auditor Beta Start

This is the shortest serious path for a senior reviewer evaluating ChainEDR
Analyzer as a private beta.

## Product Claim

ChainEDR Analyzer is a focused static analyzer for Pectra-era account-security
assumptions:

- EIP-7702 delegated EOAs;
- ERC-4337 smart-account validation;
- ERC-7562 validation-sandbox boundaries;
- related proxy, initializer, callback, and signature assumptions.

It is not a general Solidity audit replacement. Static findings are candidates
until a human review, fork proof, or target-specific reproduction confirms
impact.

## Install From The Repository

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ./src
```

For optional live RPC workflows:

```bash
python -m pip install -e "./src[live]"
```

For the optional local API prototype:

```bash
python -m pip install -e "./src[api]"
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the generated value into `CHAINEDR_API_KEYS` in `.env`. The repository does
not ship an embedded API key, and logs redact token-bearing URLs before display.
See `docs/FRIEND_PROTOTYPE.md` for the full local prototype flow.

## First Commands

Run these in order:

```bash
chainedr --help
chainedr doctor
chainedr ci ./contracts --profile auditor --out-dir chainedr-report --no-external --fail-on none
ls chainedr-report
cat chainedr-report/executive_summary.md
cat chainedr-report/evidence_bundle.md
```

The auditor profile writes one review folder:

```text
chainedr-report/
  scan.json
  chainedr.sarif
  evidence_bundle.md
  executive_summary.md
  manifest.json
```

For explicit loose artifacts, use:

```bash
chainedr scan ./contracts --no-external --json chainedr.json --sarif chainedr.sarif
chainedr ci --target ./contracts --fail-on high --sarif chainedr.sarif --json chainedr.json
chainedr prove bundle --from-json chainedr.json --source-root . --output evidence_bundle.md
chainedr prove poc --from-json chainedr.json --output-dir pocs --include-uncertain
```

Use `--deep` when the project can resolve Solidity compiler/import context:

```bash
chainedr scan ./contracts --deep --json chainedr.deep.json --sarif chainedr.deep.sarif
```

Use `--extended` only for experimental coverage review:

```bash
chainedr scan ./contracts --extended --json chainedr.extended.json
```

### Dev-time security linter

Re-scans on every `.sol` save and writes one line per finding so an IDE
problem matcher (the bundled `.vscode/tasks.json`) can pick them up:

```bash
chainedr watch ./contracts --format compact
```

### Inline PoC skeletons

Generates Foundry `.t.sol` skeletons during the scan so you don't need a
separate `prove poc --from-json` step:

```bash
chainedr scan ./contracts --format compact --prove --prove-out chainedr-poc/
```

`--prove-on-finding AA7702-001` (repeatable) filters to one rule.

### Pre-commit gate

Installs `.git/hooks/pre-commit` that runs `chainedr scan --format
compact --fail-on high` on staged Solidity files:

```bash
chainedr ci init --hook precommit
```

### Competitor delta

Reproduces the Slither / Aderyn / Semgrep matrix against the labelled
sandbox; the latest run is captured in `docs/COMPETITOR_BASELINE.md`:

```bash
python scripts/competitor_baseline.py
```

## Output Contract

The machine-readable JSON contract is versioned in
`schemas/chainedr-scan-report.schema.json`. JSON output is an object with:

```json
{
  "chainedr_version": "3.0.0",
  "timestamp": "ISO-8601 UTC timestamp",
  "elapsed_s": 0.0,
  "project": {
    "types": ["solidity_bare"],
    "files": 1
  },
  "summary": {
    "total": 0,
    "by_severity": {},
    "by_detector": {},
    "by_reviewer_confidence": {}
  },
  "findings": []
}
```

Each finding should be judged by:

- `rule_id`: the detector rule, for example `AA7702-001`;
- `severity`: triage priority, not proof of exploitability;
- `confidence`: static confidence score;
- `analysis_depth`: how the finding was produced, such as `regex`,
  `standard_json_ast`, `semantic_index`, `deep_ast`, `deep_fallback`,
  `external_tool`, `experimental`, `dynamic_confirmation`, or
  `static_heuristic`;
- `reviewer_confidence`: evidence maturity score and A/B/C/D grade. This
  grades proof quality, not exploit certainty;
- `metadata.proof_recipe`: how to confirm or refute the candidate;
- `metadata.semantic_context`: relevant signature, UserOp, delegation, proxy,
  modifier, or call-graph context when available;
- `metadata.proof_adapters`: available proof paths.

SARIF output is intended for GitHub Code Scanning and CI artifact review.
SARIF follows SARIF 2.1.0; the report schema above covers ChainEDR's JSON
artifact, which is the source of truth for automation and paper evaluation.

## What A Good Review Should Check

1. Public CLI surface is limited to `scan`, `ci`, `prove`, `live`, and `doctor`.
2. `scan` produces stable JSON and SARIF on a clean repository.
3. `ci --fail-on high` exits non-zero only for findings at or above the gate.
4. `--baseline` suppresses accepted historical findings before final CI gating.
5. `--deep` improves precision when compiler context exists and falls back
   safely when it does not.
6. `prove bundle` creates readable source-context evidence.
7. `prove poc` creates proof skeletons without claiming exploit confirmation.
8. The controlled benchmark remains unchanged or improves:
   `TP=21 FP=0 TN=36 FN=0`.

## How To Interpret Findings

Treat a ChainEDR result as one of three states:

- **Candidate**: static signal exists; needs review.
- **Refuted**: target-specific context proves the assumption is harmless.
- **Confirmed**: reproduction, fork test, or source-level proof shows impact.

Do not submit or market a finding as confirmed from static output alone.

## Strongest Novel Surface

The core novelty is this question:

> What old EOA assumptions become unsafe when an EOA can execute delegated code?

Review the tool against that question, not against broad scanners that target
classic Solidity bug classes.

Highest-value review surfaces:

- `tx.origin == msg.sender` and EOA identity gates;
- `address.code.length`, `isContract`, and extcodesize checks;
- delegated receive/fallback callback assumptions;
- universal `chain_id=0` authorization policy;
- nonce, replay, and revocation scope;
- ERC-1271 and EntryPoint validation boundaries;
- proxy implementation and initializer paths;
- internal calls hidden behind modifiers or inheritance.

## Required Evidence Before A Serious Beta Demo

Use these files as the truth set:

- `README.md`: product boundary and main workflow;
- `docs/BETA_RELEASE_GATE.md`: current beta gate and CI evidence;
- `docs/PRODUCTION_READINESS.md`: what is not production-ready yet;
- `docs/PRODUCT_BETA_CONSOLIDATION.md`: why `chainedr` is canonical;
- `docs/FRIEND_PROTOTYPE.md`: safe local API setup and token handling;
- `docs/EIP7702_SEMANTICS_NOTES.md`: wording and semantic constraints;
- `REALITY_CHECK.md`: no hidden claim of confirmed bounty-grade external bugs.

For competitor claims, use `scripts/competitor_baseline_matrix.py` and require
`measured=true` plus preserved raw/scored outputs before citing a tool as a
measured baseline. `ready_to_run` only means the binary was found locally.

## Reviewer Questions To Ask

Ask these directly:

1. Which finding types are benchmark-gated and which are experimental?
2. What does the tool do when solc, imports, or external tools are unavailable?
3. Which findings can generate proof skeletons today?
4. Which claims depend on static analysis only?
5. Where can a false positive enter the pipeline?
6. How does baseline filtering affect CI failure behavior?
7. What evidence would upgrade a candidate into a confirmed bug?

If these questions cannot be answered from the output plus the docs above, the
beta is not ready for that audience.
