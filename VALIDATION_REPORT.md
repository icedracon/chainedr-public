# ChainEDR Validation Report

**Tool version:** 3.0.0
**Last updated:** 2026-06-01
**Scope:** ChainEDR Analyzer validation for EIP-7702 / ERC-4337 / ERC-7562 assumptions

This report is intentionally conservative. ChainEDR is a working prototype for
finding and triaging account-abstraction risk patterns. The current product is
best framed as **ChainEDR Analyzer**: static Pectra-era analysis plus proof
discipline. It is not a production audit replacement, not a finished runtime
EDR, and no bounty-grade EIP-7702 vulnerability has been confirmed yet.

## Current Bottom Line

| Area | Current result |
|------|----------------|
| Controlled EIP-7702 benchmark | TP=21 FP=0 TN=36 FN=0, F1=1.00 |
| Benchmark interpretation | Corpus-scoped regression result, not production precision |
| Confirmed bounty-grade EIP-7702 bugs | 0 |
| Agglayer candidate | Local anti-pattern PoC only; live deployments initialized safely |
| Kiln V1/V2/OmniVault hunt | No confirmed bounty finding |
| Real-world value today | Precision triage, proof planning, and dynamic/fork confirmation helpers |
| Main next milestone | AST/call-graph semantics, modifier/inheritance/proxy awareness, blind benchmark, Foundry skeletons |

## Controlled Corpus

The committed benchmark is useful as a regression gate:

```text
python scripts/benchmark_evaluator.py
TP=21 FP=0 TN=36 FN=0
precision=100%, recall=100%, F1=100%
```

Do not present this as broad production accuracy. The benchmark is small and
rule-aligned: many cases were written to exercise specific ChainEDR checks. Its
proper use is to prevent regressions while the tool is hardened on independent
targets.

## Real-World Hunt Results

The current real-world hunt log is maintained in `docs/CANTINA_HUNT_LOG.md`.
The short version:

- Alchemy Modular Account V2: no confirmed bounty finding.
- Stackup Keystore: no confirmed bounty finding.
- Agglayer Vault Bridge: local reinitialize anti-pattern PoC, but live evidence
  shows initialized deployments and `InvalidInitialization()` on attacker calls.
- Whetstone Doppler: no confirmed bounty finding.
- Kiln V1 staking contracts: callback candidates survived static scan, but the
  Foundry PoC reverted/no fee theft.
- Kiln V2 / OmniVault: 60 raw static findings reduced to 0 after source-backed
  precision gates; no survivor warranted a PoC.
- Recent type-4 delegates: no confirmed live-impact proof.

## What Improved

Recent precision work added or tightened:

- ERC-7201 / EntryPoint / complete-signature-model suppressions.
- EIP-7702 `code.length` gates for initializer, factory, deterministic clone,
  implementation, registry, connector, and beacon configuration checks.
- ERC-4626 checks scoped to concrete vaults instead of connectors or vendored
  interfaces.
- Standard ERC-4626 redeem floor rounding recognized as expected behavior.
- Generic unchecked-call handling for reused `(status, data)` tuple checks.
- Zero-min-amount checks scoped to actual external calls after comments are
  stripped.

## Competitor Comparison

No fair competitor comparison is currently claimed.

Earlier draft tables that said Slither/Aderyn/Mythril/Semgrep had zero recall
were not acceptable as validation unless those tools were actually installed,
run on the same inputs, and mapped to the same labels. The correct current
statement is:

> ChainEDR targets an EIP-7702-specific niche that generic tools may not model
> directly, but a reproducible head-to-head comparison is still pending.

## External Validation Still Needed

Before using this report in a paper or serious external pitch, ChainEDR needs:

1. An externally labeled benchmark, preferably from public findings such as
   audit contest reports or disclosed bounty cases.
2. A fair tool-comparison harness that actually runs Slither, Aderyn, Mythril,
   Semgrep, Wake, and/or CodeQL.
3. A real confirmed EIP-7702 or account-abstraction vulnerability, or an honest
   statement that recall on real bugs is still unknown.
4. More production-code measurements after each precision change.

## Approved External Wording

Use:

> ChainEDR is a research prototype for EIP-7702 / ERC-4337 security triage. It
> has a perfect regression result on its controlled benchmark, but that result
> is corpus-scoped. On real audited targets, the main progress so far is false
> positive reduction and dynamic proof tooling, not a confirmed bounty finding.

Even cleaner:

> ChainEDR Analyzer is a static Pectra-era security analyzer for assumptions
> broken by delegated EOA code. Runtime monitoring is optional research, not the
> current product claim.

Do not use:

- "production-ready"
- "finished Web3 EDR"
- "best scanner"
- "replaces Slither/Mythril/auditors"
- "F1=1.00 production precision"
- "found real EIP-7702 bugs"
