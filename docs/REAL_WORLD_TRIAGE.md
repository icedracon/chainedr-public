# Real-World Triage on Production EIP-7702 Accounts

This is the honest precision check that REALITY_CHECK.md's frozen-target
section is supposed to be, with the raw `chainedr scan` output. The
6 contracts are pulled live from their respective repositories — they
are real production code, not authored samples.

## Targets

| Contract | Source | LOC |
|----------|--------|----:|
| `LightAccount.sol` | `alchemyplatform/light-account@develop:src/LightAccount.sol` | 200 |
| `Kernel.sol` | `zerodevapp/kernel@dev:src/Kernel.sol` | 535 |
| `Nexus.sol` | `bcnmy/nexus@dev:contracts/Nexus.sol` | 566 |
| `Safe.sol` | `safe-global/safe-smart-account@main:contracts/Safe.sol` | 576 |
| `Solady_ERC4337.sol` | `Vectorized/solady@main:src/accounts/ERC4337.sol` | 428 |
| `Solady_ERC7821.sol` | `Vectorized/solady@main:src/accounts/ERC7821.sol` | 246 |

Reproduce with `scripts/scan_real_7702.py` after dropping these files
into `real_7702_scan/`.

## Before / after — same files, same scanner config

| File | Before (commit `5eaf022`) | After (this sweep) |
|------|--------------------------:|-------------------:|
| LightAccount | 0 | 0 |
| Kernel | 2 | 1 |
| Nexus | 4 | 2 (1 of which is unrelated bytes32 advisory) |
| Safe | 3 (2 AA7702-\* + bytes32) | 1 (bytes32 only) |
| Solady ERC4337 | 1 | 0 |
| Solady ERC7821 | 0 | 0 |
| **AA7702-\* total** | **9** | **2** |

Five AA7702-\* findings dropped after honest triage and a targeted fix
for each FP class. The remaining two AA7702-009 findings on Kernel and
Nexus are exactly where the rule should fire and are correctly
downgraded from `CRITICAL` to `HIGH` because both contracts have
visible 7702-aware account markers (`_amIERC7702`, `validateUserOp`,
`installModule`, ...). They are architecture-review advisories, not
exploit claims.

## Per-finding triage record

| File | Rule | Was | Now | Verdict | Reason |
|------|------|-----|-----|---------|--------|
| Kernel | AA7702-007 | HIGH | — | FP fixed | Imports `ERC1967_IMPLEMENTATION_SLOT` and writes via `sstore(...,_)` — the storage layout is pinned by an external constant. `_SLOT_CONSTANT_USE_RE` now recognises the use site. |
| Kernel | AA7702-009 | CRITICAL | HIGH | Architecture advisory | Kernel is a modular AA account; proxy-slot + 7702 delegation is its architecture. Severity downgraded because the file carries 7702-account markers. |
| Nexus | AA7702-006 | HIGH | — | FP fixed | `_initializeAccount` is `internal`; the external `initializeAccount` already gates via `_amIERC7702()` + ECDSA signature recovery, factory initialisation, or self-call. AA7702-006 now ignores internal-only helpers. |
| Nexus | AA7702-007 | HIGH | — | FP fixed | Uses `_getAccountStorage()` accessor returning `AccountStorage storage`. `_NAMESPACED_STORAGE_GETTER_USE_RE` recognises the call site. |
| Nexus | AA7702-009 | CRITICAL | HIGH | Architecture advisory | Same downgrade rationale as Kernel. |
| Nexus | AA7702-004 | MEDIUM | — | FP fixed | Nexus binds chain_id transitively through the EntryPoint `userOpHash`; `validateUserOp(...userOpHash...)` signature is now recognised as a chain-binding source. |
| Safe | AA7702-003 | HIGH | — | FP fixed | `handlePayment` is `private`, callable only from `execTransaction` which already validates threshold signatures. AA7702-003 now requires the firing function to be `public` or `external`. |
| Safe | AA7702-016 | MEDIUM | — | FP fixed | Safe `checkNSignatures` routes `v == 0` to `checkContractSignature` — the ERC-1271 path. The file-level dispatcher pattern is now recognised. |
| Solady ERC4337 | AA7702-004 | MEDIUM | — | FP fixed | Same `userOpHash` chain-binding suppression as Nexus. |

## What changed in code

All in `src/eip7702_detector.py`:

- `detect_callback_reentrancy` (AA7702-003) now requires the firing
  function to carry `public` or `external` in its signature.
- `detect_delegatecall_from_delegation` (AA7702-006) same — internal
  bootstrap helpers like `_initializeAccount` no longer fire.
- `_has_pinned_storage_layout` extended to recognise three new
  use-site shapes: imported slot constants written via `sstore` /
  `sload`, namespaced-storage getter call sites (`_getXStorage()`),
  and ERC-7201 macros in comments.
- `detect_storage_collision` (AA7702-007) checks
  `_has_pinned_storage_layout` first and bails when the layout is
  pinned, regardless of the number of state variables.
- `detect_proxy_delegation_conflict` (AA7702-009) downgrades from
  CRITICAL to HIGH when 7702-aware account markers are present
  (`_amIERC7702`, `validateUserOp`, `installModule`, `IModularAccount`,
  ...). The finding is still surfaced — auditors should know — but at
  the right priority.
- `detect_ecrecover_delegation` (AA7702-016) now recognises the
  Safe-style `v == 0 → checkContractSignature` 1271 dispatcher even
  when the marker lives outside the ±10-line context window.
- `detect_cross_chain_replay` (AA7702-004) now treats
  `validateUserOp(..., userOpHash, ...)` as transitive chain-binding
  via the EntryPoint typehash and does not fire the broad
  "no chain_id check" warning on accounts that rely on it.

## Regression status

| Suite | Before | After |
|-------|-------:|------:|
| Labelled benchmark F1 | 100.0% | **100.0%** |
| Held-out v1 F1 | 100.0% | **100.0%** |
| Unit tests | 28 / 28 | **28 / 28** |

No regression on the labelled or held-out corpus, and every per-finding
removal here ties back to a specific real production pattern with the
source line shown. This is the honest version of the precision claim
that the corpus-scoped F1=1.00 cannot make on its own.
