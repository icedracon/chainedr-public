# ChainEDR - Reality Check

**Date:** 2026-06-02
**Tool version:** 3.0.0
**Scope:** static scan with `--no-external`, core checks only unless noted.

This file is the honesty anchor. The benchmark number is corpus-scoped; the frozen-target number is the current real-world precision proxy; the trophy count is still zero.

---

## Current Headline

| Metric | Current value |
|---|---:|
| Controlled EIP7702-Bench | **TP=21 FP=0 TN=36 FN=0, F1=1.00** |
| Frozen audited targets | **11 findings** |
| Frozen target TP / FP / UNCERTAIN | **TP=2 FP=0 UNC=9** |
| Frozen hard-FP-free rate, `(TP+UNC)/total` | **100.0%** |
| Frozen confirmed / non-uncertain share, `TP/total` | **18.2%** |
| Frozen false-positive rate, `FP/total` | **0.0%** |
| Frozen EIP-7702 triaged hard FP | **0** |
| Held-out validation | **18 repos, 149 findings** |
| Fresh Immunefi priority batch | **12 targets, 0 surviving findings after triage/gates** |
| Immunefi TOP-20 bounty scan | **19 targets, 16 residual signals, 0 confirmed bounty findings** |
| WooFi fork PoC | **strict live proof blocked; local-forced mechanics proven** |
| Confirmed exploitable bugs found | **0** |

**Honest read:** ChainEDR is now a much cleaner research prototype for locating EIP-7702 / account-abstraction risk patterns and driving selected candidates into fork PoCs. It is not production-ready and has not found a real exploitable bounty bug. The controlled benchmark remains perfect, but that is a small labeled corpus and must not be quoted as production precision. On frozen audited targets the hard-FP rate is now low, but only 2 of 11 findings are non-uncertain, so the tool is still a triage assistant, not an audit oracle.

---

## Frozen Audited Targets

Six professionally audited EIP-7702 / AA-aware targets were rescanned after the latest FP gates:

| Target | Findings | TP | UNCERTAIN | FP |
|---|---:|---:|---:|---:|
| ZeroDev Kernel | 5 | 0 | 5 | 0 |
| Alchemy LightAccount | 1 | 1 | 0 | 0 |
| Biconomy Nexus | 2 | 1 | 1 | 0 |
| Safe EIP-7702 | 1 | 0 | 1 | 0 |
| Ithaca Account / Porto | 2 | 0 | 2 | 0 |
| Rhinestone ModuleKit | 0 | 0 | 0 | 0 |
| **Total** | **11** | **2** | **9** | **0** |

There are currently **0 strict FPs** under this frozen-target triage. The EIP-7702 detector also has **0 hard FPs**, with remaining EIP findings classified as true informational or uncertain/by-design patterns. This is a small audited-target proxy, not a production precision claim.

### The 2 True Positives

| Check | File | Why it is real |
|---|---|---|
| AA7702-002 | `nexus/.../ProxyLib.sol` | `account.code.length > 0` can misclassify delegated EOAs. Informational, not a proven exploit. |
| AA7702-002 | `light-account/.../CustomSlotInitializable.sol` | `address(this).code.length == 0` construction detection changes under 7702. Informational, not a proven exploit. |

### Remaining Uncertain Classes

The remaining uncertain findings are mostly intentional 7702-aware proxies, ecrecover-only validators, and context-dependent generic patterns. They are not being counted as bugs.

Per-finding verdicts and class labels for all 9 UNCERTAINs are recorded in
[`docs/UNCERTAIN_VERDICTS.md`](docs/UNCERTAIN_VERDICTS.md). Each one is tagged
as `BY_DESIGN_PROXY_7702`, `SIGNATURE_VALIDATOR_BY_DESIGN`,
`INFO_ONLY_HARDENING_HINT`, or `STORAGE_HYGIENE_ADVISORY`, with a rationale a
reviewer can audit against the source.

---

## Progression

| Stage | Frozen findings | FP rate | Notes |
|---|---:|---:|---|
| Stage 1 baseline | 105 | 92.4% | Pattern locator, heavy interface/mock/cross-file noise. |
| Stage 2 generic gating | 30 | 57% | Windows path noise, interfaces, EntryPoint, EIP-712, lossless casts. |
| Generic detector gating | 25 | ~40% | Broader project/context suppression. |
| Generic gating + AST `--deep` | 13 | 0.0% | EIP and generic hard FPs eliminated under the frozen-target triage. |
| Current | 11 | 0.0% | Per-file/comment-aware generic DeFi gates remove the last cross-file/interface artifacts (rounding/slippage/flash-loan). All 9 UNCERTAINs individually justified — no unclassified fallback. |

The current improvement came from universal structure-based gates, not target or repo-name exceptions:

- Broader ERC-7201 / hand-rolled namespaced-storage recognition.
- Factory suppression for deploy-status `code.length` checks.
- ERC-1967 proxy suppression unless `delegatecall`/`fallback` indicate an actual proxy.
- Gas-griefing now requires real delegated execution and respects gas metering.
- `approve` detection now distinguishes declarations from implemented/called approval flows.
- Raw storage namespace check handles delegate-account-shaped targets while excluding factories.
- Generic stale-oracle skips interface/abstract stubs.
- EIP-2098 `uint8(v)` and EIP-712 guarded `ecrecover` are suppressed.
- Flash-loan callback detector skips interface/abstract/module-base declarations.
- Permit-surface generic alerts require an implemented permit-like function, not just an interface stub.
- Generic DeFi checks (`rounding_direction`, `missing_slippage_protection`, `oracle_manipulation`) are now per-file and comment-aware: they require the markers in the SAME file, match real withdraw/redeem functions (not filenames like `IMerkleRedeem.sol`), strip `//`/SPDX so comments aren't read as division, and skip interface-only files. Eliminates the last cross-file marker-combination FPs.
- Generic Uniswap/MEV checks also skip declaration-only abstract interfaces and standalone calldata-builder libraries; the default scan needs a live protocol surface, not just helper code.
- Clean scans now overwrite requested JSON output with `[]`, preventing stale reports from poisoning FP measurements.
- `permit_frontrun_advisory` reclassified informational/advisory: out of the default scan (it fires on correct OZ permit too), surfaced only under `--extended`.
- `raw_ecrecover` additionally suppressed when OZ `SignatureChecker`/`isValidSignatureNow` is used, or an EIP-712 domain separator pairs with an explicit zero-address signer revert.

---

## Held-Out Validation

Held-out scan was regenerated after the current gates:

| Scope | Value |
|---|---:|
| Repos scanned | **18** |
| Findings | **149** |
| EIP-7702 findings | **70** |
| Generic findings | **79** |
| Severity | **3 CRIT / 74 HIGH / 68 MED / 4 LOW** |

This is a count summary, not a full precision claim. The held-out set was used to check that the gates do not explode on unseen code. Full per-finding triage remains future work.

---

## Trophy Status

No externally valid exploitable bounty bug has been confirmed across the hunted set: **80+ codebases/contracts plus the 12-target fresh Immunefi batch and the 19-target Immunefi TOP-20 pass** from frozen targets, held-out bounty repos, on-chain bounty targets, unverified delegates, and newly scoped bounty targets.

The realistic trophy path remains:

- Newly deployed / lightly audited 7702 delegators and wallets.
- Small active contest codebases rather than flagship audited accounts.
- Pre-Pectra contracts now reachable through delegated EOAs.
- Static finding -> manual triage -> dynamic confirmation with the fork oracle.

Only a confirmed real bug changes the rating ceiling. Until then: research prototype, cleaner than before, still not a production bug oracle.

---

## Reproduce

```bash
python scripts/benchmark_evaluator.py

cd test_targets/reality_check/_results_v2
python triage.py

cd ../../holdout
python scan_holdout.py

cd ../..
pytest tests/ -q
python scripts/reproduce.py --json results/metrics.json --md results/reproduce_report.md
```

Latest verification:

- `benchmark_evaluator.py`: **TP=21 FP=0 TN=36 FN=0 F1=1.00** (corpus-scoped; 22/22 rules still below the n>=10 growth target — tracked in `reproduce.py`)
- Frozen triage: **11 findings, TP=2 FP=0 UNC=9, FP rate 0.0%** (all UNCERTAINs individually justified)
- Held-out scan: **18 repos, 149 findings**
- Fresh Immunefi priority batch: **12 targets, 0 final findings** after false-positive gates and manual triage
- Immunefi TOP-20 pass: **19 scanned targets, 16 residual signals, 0 confirmed bounty findings**
- WooFi Foundry fork PoC:
  - strict live proof: **blocked** (`pool paused` on latest Base/Arbitrum; historical Base unpaused but `cloPreferred=false`)
  - local-forced mechanics proof: **passed** on Base block `26797218` after impersonating oracle owner and setting `cloPreferred=true`
  - result: 10 USDC fresh baseline `3666810750167082` wei WETH vs stale output `3985663858881079` wei WETH, stale age `7200` seconds
- `pytest tests/ -q`: **green** (full suite passed; one third-party `websockets.legacy` deprecation warning)

## Dynamic confirmation methodology

One illustrative case was tracked through the dynamic path:

- **Code vuln CONFIRMED** under real EIP-7702 (`vm.signAndAttachDelegation`):
  the candidate's `initialize()` was unauthenticated and re-callable, and under
  7702 the stored `destination` lives in the delegated EOA's storage, so any
  third party could re-point it and steal inbound ETH via `receive()`. PoC:
  2/2 pass (positive control + exploit).
- **Live impact: NONE found.** On-chain triage scanned 900 recent blocks /
  **2,526 active delegations**, zero pointing at the candidate implementation;
  not in any top-15 type-4 indexer.
- **Verdict: confirmed-vulnerable but unused → not a submittable finding.** The
  dynamic path works; the target just had no funds at risk.

The point is the *pipeline shape*: regex/AST candidate → dynamic confirmation
under `vm.signAndAttachDelegation` → on-chain triage for impact. The trophy
count stays at zero because impact closes the chain, not severity.

## Path A live hunt — real unverified delegators (bytecode prover)

First run of the Phase-2 bytecode prover (`poc/path_a_hunt.py`) against real on-chain
7702 delegators, fully sandboxed (test victim on local anvil, no real account touched).

- **Input-data caveat:** the supplied "BundleBear top-5 / millions of users" addresses
  were **fabricated** — BB1/2/4/5/7 have `code=0, nonce=0, balance=0` (never transacted).
  Only BB9 (`0x27dbd0e7…`, 1511 live delegations) was real. Always verify targets with
  `eth_getCode` before claiming impact.
- **Real targets:** harvested the 11 most-delegated implementations from the live type-4
  stream (400 blocks). Result: **9 clean, 0 confirmed vulns.** 2 (`0x545940F5…`,
  `0x1f760b5D…`) auto-forward inbound ETH, but triage shows a baked-in immutable
  destination (not in mutable storage; state-write probe found no unauthorized setter) —
  **by-design fixed-destination sweepers, not exploitable.**
- **Prover behaved correctly:** reached unverified bytecode the source pipeline can't,
  zero unauthorized-state-write false positives on hardened accounts, flagged 2 for
  review that were cleared by hand. Cumulative tally ~83 codebases/contracts, still
  **0 exploited**.
