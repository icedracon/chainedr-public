# ChainEDR Changelog

---

## v3.2.0 — Niche-only cleanup: legacy / runtime / fuzzing surfaces removed (2026-06-09)

The product is now strictly the EIP-7702 / ERC-4337 / ERC-7562 static
analyzer plus its dev-time tooling. Everything else was removed.

### Removed

- `__main__.py` shrank from **4,457 lines** of legacy command stack to a
  13-line shim that re-exports `cli.main`.
- 46 top-level `src/*.py` legacy modules and 14 research-scratch
  directories (full list in `docs/EXPERIMENTAL_MODULES.md`).
- 12 obsolete tests under `tests/` and 4 under `src/`.
- `cli.py`:
  - `_LEGACY_COMMANDS` set + `_route_legacy()` function.
  - `cmd_live` + the `live` subparser (runtime EDR direction).
  - `prove report` / `prove benchmark` / `prove replay` subparsers
    (all delegated to deleted legacy handlers).

### Fixed (consequences of cleanup)

- `api/app.py` now routes `/scan` through `EIP7702Detector.scan_files`,
  i.e. the same Analyzer code path that powers `chainedr scan`. The
  deleted `Hunter` import is gone.
- `AA7702-009` severity downgrade is gated on *runtime* 7702 markers
  (`validateUserOp`, `IModularAccount`, `installModule`, ...) — naming a
  contract `EIP7702Whatever` no longer changes severity by itself.
- `AA7702-006` access-gate suppression is now conditional on
  `_has_pinned_storage_layout`. Functions guarded by `msg.sender ==
  owner` on a raw delegation target still fire, because the gate runs
  against zeroed EOA storage.

### Numbers held throughout

- Labelled benchmark F1: **100.0%** (57 samples)
- Held-out v1 F1: **100.0%** (25 samples)
- src/ unit tests: 28 / 28 pass
- tests/ suite: 265 / 265 pass (1 skipped — websockets dep)
- Production real-7702 scan: 2 AA7702-* HIGH advisories across 6
  upstream accounts (same as before cleanup)
- `src/*.py` count: 54 (was 107)
- `src/` total LOC: ~31,000 (was ~85,000)

---

## v3.1.0 — Beta-polish sweep: dev-time linter + alias-flow + held-out F1=100% (2026-06-09)

The 10/10 prototype-beta sweep. 19 commits, 28 unit tests, two new
benchmarks (perf + holdout), one completed competitor matrix, one
explicit experimental-surface contract. Labelled benchmark stays at
F1 = 1.00 throughout; the new 25-sample held-out corpus scores
**F1 = 1.00** on patterns the analyzer was not tuned on.

### Added — Dev-time linter wedge

- `chainedr scan --format compact` — one-line-per-finding output
  `file:line:col: [SEV/GRADE] RULE_ID title` for IDE problem matchers
  and grep pipelines. Suppresses banner, sections, and per-detector
  progress.
- `chainedr watch <path>` — polls .sol / .nr changes (1.5 s default),
  re-runs the scan, emits diagnostics. No new dependencies, works on
  every platform. Closes the dev-time linter wedge over audit-phase
  scanners.
- `.vscode/tasks.json` + `.vscode/extensions.json` +
  `docs/VSCODE_INTEGRATION.md` — wires watch / scan / scan+prove into
  the VS Code Tasks UI with a problem matcher that lands diagnostics
  in the Problems panel.
- `chainedr ci init --hook precommit` / `--hook prepush` — installs a
  git hook that runs `chainedr scan --format compact --fail-on high`
  on staged Solidity files. Refuses to clobber a hand-written hook
  unless it carries the ChainEDR marker.
- `chainedr scan --prove` / `--prove-on-finding RULE_ID` /
  `--prove-out DIR` — emits Foundry `.t.sol` skeletons inline with
  the scan via `poc_skeletons.generate_skeletons`. Works in compact
  mode and the watch loop.

### Added — Static depth

- `_function_signature_modifiers` /
  `_function_has_guard_modifier` — parses multi-line function
  signatures (modifier-arg parens collapsed so
  `onlyRole(ADMIN_ROLE)` matches), recognises a curated set of guard
  names plus the `only*` convention. Wired into AA7702-001 / 002 / 006.
- `_function_has_inline_auth` — body-level shapes:
  `require(msg.sender == owner/admin/governance/...)`,
  `require(hasRole(...))`, `require(_isOwner/_isAdmin/...)`,
  `_checkOwner/_checkRole/_checkAuth` calls, owner-compare
  if-revert, `authorized[msg.sender]` / `operators[msg.sender]`
  map gates.
- `_function_is_access_gated` — unified "modifier OR inline auth"
  helper. Replaces the modifier-only check in AA7702-001 / 002 /
  003 / 006.
- `_contract_inheritance_bases` /
  `_file_has_known_access_control_base` — recognises Ownable /
  AccessControl / UUPS / Auth bases. Attached as semantic context,
  not used as a suppression signal on its own.
- `_state_aliases_for_origin_sender` — file-level alias map for
  state-variable assignments from tx.origin / msg.sender.
- `_detect_aliased_tx_origin_compare` — intra-function alias-flow
  pass: catches `address a = tx.origin; address b = msg.sender;
  require(a == b);` and the reassignment variant.
- Cross-function state-variable flow pass — catches
  `initiator = tx.origin` in one function and
  `require(initiator == msg.sender)` in another.
- `_function_body_range` now INCLUDES the opening-brace line so
  single-line `function f() { body; }` bodies are not silently
  dropped.
- `is_affected` widened with an alias-candidate hook so files with
  no literal `tx.origin == msg.sender` but with an alias assignment
  + comparison are no longer screened out before `check()` runs.

### Added — Output / proof discipline

- Per-finding **reviewer-confidence grade** (A/B/C/D) surfaced in
  scan terminal output next to severity and in the summary
  histogram. Severity says "how bad"; grade says "how proven".
- `_emit_prove_skeletons` helper factored so the prove pipeline
  fires from both the compact early-return path and the default
  path.

### Added — Benchmarks

- `benchmarks/holdout_v1/` — 25-sample generalisation corpus
  authored after the detector logic was frozen. Covers OZ Ownable,
  inline auth, alias-flow, cross-function state flow, isContract
  airdrop guards, delegation-target shapes, ERC-20 permit, UUPS
  upgrade gating, re-callable initialise, chain_id replay, EIP-712
  + ERC-1271 fallback, ERC-7201 namespaced storage, raw delegation-
  target storage, selfdestruct in delegation target, single vs
  multi relayer, EntryPoint v0.6 hardcode, governance inline auth,
  Ownable inheritance, interface-only files.
- `scripts/holdout_evaluator.py` — runs ChainEDR over the holdout
  and reports TP/FP/FN/TN + precision/recall/F1.
- Result: **TP=13, FP=0, FN=0, TN=12, P=R=F1=100%**.
- `scripts/perf_benchmark.py` + `docs/PERFORMANCE.md` — per-file
  scan latency. Results: **mean 2.3 ms, p50 2.2 ms, p95 3.6 ms,
  max 4.2 ms, throughput 5,702 LOC/sec** on 57 files / 825 LOC.
- `scripts/competitor_baseline.py` — runs Slither / Aderyn /
  Semgrep on the labelled corpus.
- Result: ChainEDR 21/21, Slither 10/21, Aderyn 0/21, Semgrep
  0/21, **ChainEDR-unique 11/21**.

### Added — Documentation

- `docs/COMPETITOR_BASELINE.md` + `docs/competitor_baseline.json` —
  per-sample matrix.
- `docs/HOLDOUT_RESULTS.md` + `docs/holdout_results.json` — per-
  sample verdicts and rationale.
- `docs/PERFORMANCE.md` + `docs/perf_benchmark.json` — per-file
  scan latency.
- `docs/UNCERTAIN_VERDICTS.md` — per-finding verdict for the 9
  frozen UNCERTAINs with a 4-tag taxonomy
  (`BY_DESIGN_PROXY_7702`, `SIGNATURE_VALIDATOR_BY_DESIGN`,
  `INFO_ONLY_HARDENING_HINT`, `STORAGE_HYGIENE_ADVISORY`).
- `docs/VSCODE_INTEGRATION.md` — one-time setup walkthrough.
- `docs/EXPERIMENTAL_MODULES.md` — explicit beta-surface vs
  experimental-surface contract.
- `docs/BETA_RELEASE_GATE.md` — closed-gate verdict updated with
  the new infrastructure.
- `REVIEWER_BRIEF.md` + `docs/AUDITOR_BETA_START.md` — refreshed
  reviewer demo, new commands, executed competitor numbers, new
  strongest / weakest parts.

### Fixed — Suppression layer

- `_suppress_finding` for AA7702-001: alias-flow and cross-function
  state-flow findings (`analysis = intra_function_alias_flow` /
  `cross_function_state_alias_flow`) bypass the IR-unreachable-
  fact gate. The IR can only see literal `tx.origin` tokens; it
  cannot prove unreachability for aliased forms.
- `EIP7702Detector.scan_files` no longer clobbers the detector-set
  `semantic_context` (which carries the alias-flow tag) with the
  project-level context. Now merges so both layers remain visible.
- AA7702-003 callback-reentrancy now honours the unified
  `_function_is_access_gated` helper. OZ Ownable withdraw with
  `onlyOwner` + tx.origin defence-in-depth no longer triggers a
  self-harm reentrancy alert.
- AA7702-002 no longer fires when `signer.code.length > 0` is used
  as the branch condition for ERC-1271 / ecrecover routing — that
  pattern is exactly the 7702-aware fallback the analyzer should
  encourage.

### Tests

- `src/test_eip7702_modifier_suppression.py` — **28 unit tests**
  covering modifier suppression, inline-auth shapes, inheritance-
  base detection, intra-function alias-flow, cross-function
  state-variable flow, and edge cases (multi-line signatures,
  reassignment, visibility-keyword filtering).

### Headline numbers

| Metric | Value |
|---|---|
| Labelled benchmark F1 (57 samples) | **100.0%** |
| Held-out generalisation F1 (25 samples) | **100.0%** |
| Slither hits on labelled-vulnerable samples | 10 / 21 |
| Aderyn hits on labelled-vulnerable samples | 0 / 21 |
| Semgrep hits on labelled-vulnerable samples | 0 / 21 |
| ChainEDR-unique vulnerable detections | **11 / 21** |
| Per-file scan p95 | 3.6 ms |
| Throughput | 5,702 LOC/sec |
| Unit tests | 28 passing |

---

## v2.1.0 — Production validation + 2026 attack class detectors (2026-05-21)

### Major: External validation
- **InfiniFi waterfall bug found by `safety_buffer_waterfall` detector confirmed
  by Cantina** — finding [#242](https://cantina.xyz/competitions/infinifi-protocol),
  HIGH severity, Duplicate of 17 independent submissions, 50 points awarded.
  See [CASE_STUDIES.md](../CASE_STUDIES.md). All major OSS static analyzers
  (Slither, Aderyn, Wake, Semgrep) missed this pattern.

### Added — 2026 detector pack
- `bridge_address_validation_gap` — cross-chain message handlers without source
  address verification (38% of Q1 2026 DeFi losses, Purrlend-class)
- `zk_verifier_misconfig` — ZK proof verifier integrations missing public input
  validation or with unguarded verifier setter (Foom Cash $2.3M class)
- `cross_contract_oracle_taint` — multi-hop oracle taint tracker (catches
  ResolvOracle-class freshness laundering Slither misses)
- `safety_buffer_waterfall` — loss-cliff bug class (InfiniFi-validated)

### Added — Pipeline architecture
- `FPAnalyzer` — labels every finding with verdict (REAL/UNCERTAIN/FALSE_POSITIVE)
  + concrete rule + reason. 11 rules driven by real production evidence.
- `AttackVectorEnumerator` — structured attacker / entry / chain / sink model per finding
- `ExploitabilityGraph` — typed edges (entry/call/state_read/sink) with feasibility
  scoring; critical_path detection
- `BountyVerdictEngine` — per-program triage profiles (Cantina, Sherlock, Code4rena,
  Immunefi, solo_research) — first tool with this
- `CrossToolDedup` — canonical-category dedup with consensus_confidence boost
- `OracleTaintTracker` — cross-contract value flow analysis
- `OWASP 2026 mapping` — every finding tagged with SC01–SC10 category
- `PriorAuditDedup` — 44 curated entries + Sherlock/Code4rena scrapers
- `Calibrator` — empirical precision per check (Source A/B/C tagging)
- `PoCGenerator` — Foundry .t.sol scaffold + Halmos invariant for REAL findings
- `SARIFOutput` — GitHub Code Scanning compatible
- `BenchRunner` — labeled-corpus precision/recall/F1 (EVMbench compatible)

### Added — CLI consolidation
- 22 commands → 6 visible: `scan`, `live`, `bench`, `init`, `doctor`, `debug`, `poc`
- `chainedr doctor` — diagnostic for tool health
- `chainedr scan --bounty --bounty-profile X` — triage mode
- `chainedr scan --format sarif` — GitHub Security tab upload
- `chainedr poc <path>` — generate Foundry reproducers
- `chainedr bench <corpus>` — labeled-corpus benchmark

### Added — Reliability
- Foundry submodule auto-init (30s timeout)
- Hardhat npm/yarn auto-install (60s timeout)
- Project-type detection (foundry / hardhat / plain)
- Pre-scan readiness banner — user sees up-front which tools will/won't contribute
- GitHub Action workflow template (`.github/workflows/chainedr-scan.yml`)
- e2e smoke test runner (`tests/e2e_smoke.py`) — 7 real targets

### Architecture summary
Pipeline order in `Hunter.scan_source_directory`:
1. Internal detectors (~22 checks)
2. Oracle taint tracker
3. Bridge + ZK 2026 detectors
4. External tools in parallel (Slither + Wake + Semgrep + Aderyn)
5. Cross-tool dedup with consensus boost
6. FP analyzer (label REAL/UNCERTAIN/FALSE_POSITIVE — never hide)
7. Confidence calibrator
8. Prior audit dedup (novelty marking)
9. Competitive gap filter
10. Attack vector enumeration
11. Exploitability path graph
12. OWASP 2026 annotation
13. Bounty verdict (SUBMITTABLE / NEEDS_POC / etc.)

Output formats: text (default) / json / markdown / sarif

---

## v1.2.1 — FP Reduction Update (2026-04-22)

### Fixes

#### `_detect_reentrancy_cei`
- **Added `_same_function(offset_a, offset_b, source)`** — safety helper that verifies
  two raw character offsets belong to the same function body before emitting a CEI finding.
  Prevents cross-function offset matching where an external call in function A was
  incorrectly paired with a state write in function B via global position comparison.
- **Added `_has_inline_reentrancy_guard(func_source)`** — recognises custom reentrancy
  guard patterns beyond the `nonReentrant` modifier:
  - `reentrancyGuard* = true` named variable pattern
  - Struct-field guards: `s_foo.reentrancyGuardEntered = true` (Chainlink OnRamp pattern)
  - Classic mutex names: `locked = true`, `_mutex = true`, `_entered = true`
  - Revert-on-entry check: `if (...) revert *Reentrancy*`
- CEI detector now also skips interface declarations (body length < 5 chars), which
  previously caused `linkAvailableForPayment()` interface stub to be flagged.

#### `_extract_functions`
- **Broadened privileged modifier regex** from a hardcoded list to `only\w+|admin\w*|requiresAuth|guard\w+`.
  Now correctly captures `onlyAdminOrExecutor`, `onlyOffRamp`, `onlyOnRamp`,
  `onlyRouter`, `onlyKeeperRegistry`, `onlyRelayer`, and any future `only*` modifier
  without requiring a code change.

#### `_detect_missing_validation_pair`
- **Skip view/pure functions (Fix 2a):** View functions returning a mapping default
  for an unknown key are safe Solidity behaviour, not a missing-validation bug.
- **Skip privileged functions (Fix 2b):** Functions gated by `onlyOwner`, `onlyRole`,
  or any `only*` modifier. Admin misconfiguration is out of scope for bug bounty.
- **Detect implicit validation (Fix 2c):** Recognise mapping-key lookup + `msg.sender`
  conditional as implicit parameter validation (e.g. `s_destChainConfigs[selector].router`
  compared to `msg.sender`).

#### `_detect_permissionless_critical_functions`
- **Internal validator delegation (Fix 1b/1c):** Functions that call `_validate*`,
  `_only*`, `_check*`, `_verify*`, or `_auth*` internal helpers are no longer flagged
  as permissionless — access control is enforced inside the helper.
- **`super.` delegation (Fix 1b):** Calls to `super.<method>()` inherit the parent
  contract's access control and are now correctly suppressed.
- **Internal helper pattern (Fix 1c):** Calls to `_lockRelease*`, `_process*`,
  `_relay*`, `_incoming*`, `_outgoing*` internal helpers are suppressed (these wrap
  validation by convention in CCIP-style contracts).

#### `_detect_batch_atomicity_dos` + `_detect_missing_try_catch_in_loops`
- **Bool-captured return (Fix 3a):** Suppress when the external call's return value
  is captured in a `bool` and handled via conditional — failure is isolated, not reverted.
- **Inline reentrancy guard (Fix 3b):** Suppress when the function sets a
  `reentrancy*Guard* = true` inline guard, indicating deliberate non-CEI design.

#### `_detect_unchecked_erc20_transfers`
- **Privileged function downgrade (Fix 4):** Findings in functions protected by
  any `only*` modifier are downgraded from MEDIUM to LOW, since only trusted actors
  can reach the code path.

#### `admin_modifiers` set
- Added: `onlyAdminOrExecutor`, `onlyExecutor`, `onlyKeeperRegistry`, `onlyRelayer`,
  `adminOnly`, `onlyManager`, `onlyController`, `requiresAuth`.

---

### Results

| Metric | Before v1.2.1 | After v1.2.1 |
|--------|--------------|-------------|
| Chainlink CCIP scan — HIGH | 17 | 1 |
| Chainlink CCIP scan — MEDIUM | 16 | 1 |
| Chainlink CCIP scan — LOW | 0 | 1 |
| **Total notable findings** | **33** | **3** |
| FP eliminated | — | **30** |
| Benchmark F1 | 40.0% | **40.0%** (unchanged) |
| Test suite | 26/26 ✓ | **26/26 ✓** |

### Surviving findings (confirmed non-FP)
- `[HIGH]` `HybridLockReleaseUSDCTokenPool.transferLiquidity()` — real CEI violation;
  `onlyOwner` limits exploitability but pattern is genuine.
- `[MEDIUM]` `OnRamp.withdrawFeeTokens()` — `safeTransfer` loop with no per-token
  error handling; one blacklisted fee token blocks all withdrawals. Needs Foundry PoC.
- `[LOW]` `LinkAvailableBalanceMonitor.withdraw()` — unchecked LINK `transfer()` return;
  correctly downgraded because `onlyAdminOrExecutor` restricts callers.

---

## v1.2.0 — New Detectors (2026-04-15)

- Added `_detect_precision_loss` (division-before-multiplication via regex + AST)
- Added `_detect_fee_on_transfer_accounting` (balance-diff accounting)
- Added `_detect_missing_validation_pair` (inconsistent cross-function validation)
- Added hunter.py checks: read-only reentrancy (#15), sandwich/oracle manipulation (#16),
  permit/EIP-2612 attack surface (#17)
- Added fp_filter.py Rule 15: test file exclusion

## v1.1.0 — Phase 3 Detectors (2026-03-01)

- ERC-4626 share inflation
- CEI reentrancy detection
- Flash-loan price manipulation
- Missing zero-address checks
- Unchecked ERC-20 return values

## v1.0.0 — Initial Release

- Batch atomicity DoS detector
- Missing bounds checks
- Admin trust assumptions
- Unsafe external calls
- Unchecked returns
- Waterfall skip logic
- Permissionless critical functions
