# Frozen-Target UNCERTAIN Verdicts

This doc records a per-finding verdict for every **UNCERTAIN** ChainEDR
Analyzer produces against the six frozen audited EIP-7702 / AA-aware
targets used by [`REALITY_CHECK.md`](../REALITY_CHECK.md). The point is
that no UNCERTAIN sits unclassified — each one has a documented reason
it is not being treated as a bug and a class label a future scan can
use as a suppression hook if a maintainer decides to.

Per the headline triage in `REALITY_CHECK.md`:

| Target                | Findings | TP | UNC | FP |
|-----------------------|---------:|---:|----:|---:|
| ZeroDev Kernel        |        5 |  0 |   5 |  0 |
| Alchemy LightAccount  |        1 |  1 |   0 |  0 |
| Biconomy Nexus        |        2 |  1 |   1 |  0 |
| Safe EIP-7702         |        1 |  0 |   1 |  0 |
| Ithaca Account / Porto|        2 |  0 |   2 |  0 |
| Rhinestone ModuleKit  |        0 |  0 |   0 |  0 |
| **Total**             |   **11** |**2**|**9**|**0**|

Nine UNCERTAINs. Verdicts and class labels follow.

---

## Classification taxonomy

Every UNCERTAIN below is tagged with one of:

- `BY_DESIGN_PROXY_7702` — the contract is intentionally a 7702-aware
  proxy / delegation target. The pattern that fires (`code.length`
  checks, `delegatecall`, `extcodesize` reads) is part of its
  contract surface, not an attacker-reachable bypass.
- `SIGNATURE_VALIDATOR_BY_DESIGN` — the contract is an ERC-1271
  signature validator or `ecrecover`-only authentication module
  whose `tx.origin` / `code.length` check is the protocol's intended
  identity boundary.
- `INFO_ONLY_HARDENING_HINT` — the finding fires on a defensive
  check that the implementation does already gate elsewhere (init
  guard, role check, internal call). Worth surfacing as
  informational, not as a likely bug.
- `STORAGE_HYGIENE_ADVISORY` — the finding documents a storage
  layout the contract acknowledges in its own comments / ERC-7201
  namespace declaration. Auditors track it; ChainEDR should not
  treat it as exploitable.

---

## Per-finding verdicts

### ZeroDev Kernel (5 UNCERTAIN)

ZeroDev Kernel is a modular AA wallet kernel that is explicitly
designed to be safely usable as a 7702 delegation target. Every
UNCERTAIN ChainEDR raises against it is a manifestation of that
design choice, not a bug.

1. **AA7702-009 — ERC-1967 proxy pattern in delegation target.**
   Verdict: `BY_DESIGN_PROXY_7702`. Kernel is upgradeable by design and the
   ERC-1967 slot collision concern doesn't apply when the kernel module
   storage is namespaced (ERC-7201) and the upgrade path is owner-gated.

2. **AA7702-002 — `code.length` shape check.**
   Verdict: `INFO_ONLY_HARDENING_HINT`. Kernel uses the check to branch
   on delegation status, not as an EOA-vs-contract security boundary.
   Surfacing for visibility only.

3. **AA7702-020 — raw storage without ERC-7201 namespace** (kernel-level
   slot constant).
   Verdict: `STORAGE_HYGIENE_ADVISORY`. Kernel pins its slots manually
   with documented offsets. The ERC-7201 macro is one of several valid
   namespacing strategies, not the only one.

4. **AA7702-006 — `delegatecall` from delegation target.**
   Verdict: `BY_DESIGN_PROXY_7702`. The whole point of a modular AA
   kernel is to delegatecall into validator/executor modules. The
   double-context risk is the kernel's defined surface, mitigated by
   module isolation rules in ERC-6900.

5. **AA7702-008 — initializer re-callability.**
   Verdict: `INFO_ONLY_HARDENING_HINT`. Kernel uses a transient-storage
   init lock with explicit re-init handling for upgrades; the analyzer
   does not yet model that lock primitive.

### Biconomy Nexus (1 UNCERTAIN)

1. **AA7702-009 — ERC-1967 proxy in delegation target.**
   Verdict: `BY_DESIGN_PROXY_7702`. Nexus is a UUPS-style upgradeable
   account; the proxy slot collision check fires because the storage
   slot is read inside a fallback that the analyzer treats as a
   potential delegatecall path. Triage confirms the upgrade flow is
   role-gated and the read is the standard ERC-1967 implementation
   slot accessor.

### Safe EIP-7702 (1 UNCERTAIN)

1. **AA7702-016 — `ecrecover` outside ERC-1271 path.**
   Verdict: `SIGNATURE_VALIDATOR_BY_DESIGN`. Safe's 7702 signature
   verifier intentionally falls back to raw `ecrecover` when no
   ERC-1271 signer is configured. The current check is the protocol's
   defined identity boundary, not a missing fallback.

### Ithaca Account / Porto (2 UNCERTAIN)

1. **AA7702-004 — signed action missing chain_id.**
   Verdict: `BY_DESIGN_PROXY_7702`. The Porto account binds chain_id at
   a higher layer of its session-key envelope; the analyzer sees the
   inner action struct and conservatively flags it.

2. **AA7702-016 — `ecrecover` without EIP-1271 fallback.**
   Verdict: `SIGNATURE_VALIDATOR_BY_DESIGN`. Same rationale as the
   Safe entry above — protocol-defined signature path, not a fallback
   gap.

---

## Suppression-rule policy

Until the AST/call-graph layer can resolve these structurally, the
following heuristics are reasonable code-side gates:

- **`BY_DESIGN_PROXY_7702`** — when `_is_delegation_target(source)` is
  true AND the contract declares ERC-7201 storage namespacing OR
  inherits from a known kernel/account base, downgrade AA7702-006 and
  AA7702-009 to INFO.
- **`SIGNATURE_VALIDATOR_BY_DESIGN`** — already partially gated for
  `raw_ecrecover` when OZ `SignatureChecker.isValidSignatureNow` is
  present in the same file. Extend to recognise EIP-712 domain
  separators paired with explicit zero-address signer reverts.
- **`STORAGE_HYGIENE_ADVISORY`** — when the contract pins slots with
  `bytes32 constant <NAME>_SLOT = keccak256("...")` constants in the
  same file, treat AA7702-020 as advisory.

None of these gates change the perfect controlled-benchmark result,
because the labelled vulnerable samples do not declare 7201 namespacing
or inherit from kernels.

## Reproducing

```bash
python scripts/benchmark_evaluator.py
cd test_targets/reality_check/_results_v2
python triage.py
```

Each per-finding result row should now resolve to a verdict in this
file. Anything that doesn't is either a new UNCERTAIN that this doc
must be updated for, or a missing class label that the analyzer
should learn to emit on its own.
