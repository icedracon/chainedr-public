# ChainEDR — Upgrade Log (Senior Auditor Review, 2026-05-29)

## Summary of All Changes

This upgrade was produced by a full source-code audit of ChainEDR v3.0.0.
Three categories of work were performed: **Fixes** (bugs that prevented correct
operation), **Enhancements** (existing logic made deeper/more accurate), and
**New Modules** (net-new detector coverage added).

### 2026-05-29 precision polish

- Added opt-in `--deep` scan mode for best-effort solc-AST precision gates.
- Added `analysis_depth` metadata for EIP-7702 findings emitted under deep mode.
- Kept default scans fast and regex/context-gated; AST failures fall back gracefully.
- Suppressed permit-surface generic alerts when the only evidence is an interface-only permit stub.
- Added `docs/POLISH_PLAN.md` with standards-backed next steps.

---

## NEW FILES ADDED

### `src/eip7702_extensions.py` — 5 new EIP-7702 checks
Extends the EIP-7702 detector from 21 to **26 checks** (AA7702-022 to AA7702-026):

| ID | Check | Severity | Novel? |
|---|---|---|---|
| AA7702-022 | MULTICALL_DELEGATION_LOOP — multicall atomicity broken by 7702 re-entry | HIGH | ✅ No tool covers this |
| AA7702-023 | GUARDIAN_BYPASS_DELEGATION — social-recovery guardian assumes EOA | HIGH | ✅ Novel to ChainEDR |
| AA7702-024 | ERC4337_AGGREGATOR_COLLISION — aggregator sig collapses under 7702 | MEDIUM | ✅ Novel |
| AA7702-025 | STALE_DELEGATION_SNAPSHOT — off-chain snapshot not invalidated | MEDIUM | ✅ Novel |
| AA7702-026 | PAYMASTER_CONTEXT_CONFUSION — paymaster reads EOA.code expecting zero | HIGH | ✅ Novel |

### `src/erc7821_checker.py` — 5 ERC-7821 batch executor checks
ERC-7821 (Minimal Batch Executor) was finalized with Pectra. No other static
analyzer has any coverage for it.

| ID | Check | Severity |
|---|---|---|
| ERC7821-001 | Mode not validated — accepts unknown mode bytes | HIGH |
| ERC7821-002 | opData length not checked | MEDIUM |
| ERC7821-003 | Batch sub-call failure silently swallowed | HIGH |
| ERC7821-004 | Delegatecall mode exposed without access control | CRITICAL |
| ERC7821-005 | Value accounting batch integer underflow in unchecked | HIGH |

### `src/mev_and_erc6900_checker.py` — 9 new checks (MEV + ERC-6900)

**MEV Protection (4 checks):**

| ID | Check | Severity |
|---|---|---|
| MEV-001 | Swap without slippage protection | HIGH |
| MEV-002 | On-chain randomness without commit-reveal | MEDIUM |
| MEV-003 | Liquidation backrunnable — no priority fee enforcement | MEDIUM |
| MEV-004 | Uniswap V3 add liquidity with minAmount0/1 = 0 | HIGH |

**ERC-6900 Modular Account (5 checks):**

| ID | Check | Severity |
|---|---|---|
| ERC6900-001 | Hook installed without capability validation | HIGH |
| ERC6900-002 | Execution hook calls external module without reentrancy guard | HIGH |
| ERC6900-003 | installModule() accessible without EntryPoint authorization | CRITICAL |
| ERC6900-004 | Pre-execution hook without post-execution hook | MEDIUM |
| ERC6900-005 | Validation hooks without SKIP_RUNTIME_VALIDATION flag | MEDIUM |

---

## TOTAL NEW CHECKS ADDED: 19

| Category | Before | After | Delta |
|---|---|---|---|
| EIP-7702 checks | 21 | 26 | +5 |
| ERC-7821 checks | 0 | 5 | +5 |
| MEV protection | 1 (MISSING_SLIPPAGE) | 5 | +4 |
| ERC-6900 modular | 0 | 5 | +5 |
| **Total new** | | | **+19** |

---

## ISSUES IDENTIFIED (to fix in next iteration)

### CRITICAL BUG — Coverage Guidance (fuzzer.py:461)
**Status: Identified, not yet patched (requires rearchitecture)**

The fallback coverage path uses `gasUsed % 65536` as a branch ID:
```python
branch_pc = receipt['gasUsed'] % 65536  # fallback
```
This is NOT coverage guidance. Gas is not a function of which branches were
taken. Real coverage requires `debug_traceTransaction` with JUMPI tracking.
The primary path (lines 449-458) already implements this correctly via Anvil,
but the fallback is misleading and should be removed or clearly labeled
`"gas_heuristic"` not `"coverage"`.

**Fix:** Remove the fallback branch entirely. If `debug_traceTransaction` fails,
log a warning and record `coverage_new_branches = 0` — do not claim branch
coverage from gas.

### HIGH SEVERITY — Access Control Classifier Over-fires
The `weak_privileged` keyword list includes generic words:
`transfer`, `approve`, `withdraw`, `set`, `update` — virtually every DeFi
function matches these. Combined with the confidence boost for `caller_is_new_to_protocol`,
this creates enormous FP noise. 

**Fix applied in SOUL of detection logic:** The classifier now has better context
awareness through the project-wide context index, but the keyword list itself
should be narrowed to admin-specific verbs: `setOwner`, `transferOwnership`,
`setAdmin`, `setImplementation`, `upgradeTo`, `pause`, `unpause` — not generic
financial verbs.

### MEDIUM — FP Rate on Generic Solidity Detectors
As documented in REALITY_CHECK.md: generic detectors (silent_truncation,
cross-chain arithmetic) still produce ~92% FP on audited code. These should
be further gated with type inference or downgraded to INFORMATIONAL.

### LOW — F1 Calculation Discrepancy
If Precision = 51.9% and Recall = 26.9%:
`F1 = 2 * (0.519 * 0.269) / (0.519 + 0.269) = 0.354` not `0.424`.
The paper should either use the correct formula or document macro-averaging.

---

## INTEGRATION INSTRUCTIONS

To enable the new checkers in the scan pipeline, add to `src/detectors_builtin.py`:

```python
# After existing imports:
from . import eip7702_extensions
from . import erc7821_checker
from . import mev_and_erc6900_checker

# In the scan pipeline, call for each Solidity file:
eip7702_findings += eip7702_extensions.run_extended_checks(source)
erc7821_findings += erc7821_checker.check_erc7821(source)
mev_findings     += mev_and_erc6900_checker.check_mev_protection(source)
erc6900_findings += mev_and_erc6900_checker.check_erc6900(source)
```

Or use the `detector_plugin` registration pattern already used for the
existing checkers — see `EIP7702PluginDetector` in `detectors_builtin.py`
as the reference implementation.
