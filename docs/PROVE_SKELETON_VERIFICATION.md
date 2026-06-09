# `--prove` Skeleton Compilation Verification

The proof-discipline claim only holds if generated skeletons actually
compile under Foundry. This doc records the verification run.

## What was tested

Generated `.t.sol` skeletons from `chainedr scan --prove` for every
vulnerable sample in `benchmarks/eip7702_sandbox/vulnerable`, then
ran `forge build` over the full set in a clean Foundry project.

```
Generated: 15 skeletons covering 11 distinct rules
  AA7702-001, AA7702-002, AA7702-006, AA7702-007 (×4 contracts),
  AA7702-008, AA7702-009, AA7702-010, AA7702-013, AA7702-016,
  AA7702-021
```

## Result

```
Compiling 15 files with Solc 0.8.34
Solc 0.8.34 finished in 853.16ms
Compiler run successful!
```

All 15 skeletons compile against forge-std `Test.sol` under solc 0.8.34
with no errors and no warnings. The skeleton template is therefore
guaranteed Solidity-valid for every rule the SUPPORTED_RULES set covers.

## What this proves and what it does not

**Proven** — every emitted `.t.sol` is syntactically valid Solidity
that imports `forge-std/Test.sol`, declares a `setUp()` + two test
functions, uses `vm.label` / `vm.etch` / `vm.startPrank` correctly,
and links against forge-std types.

**Not proven** — the TODO blocks inside `setUp()` and the test bodies
are still placeholders. The skeletons document the proof objective,
the pre-/post-Pectra invariants, and a refutation path, but a reviewer
still has to fill in the calldata + the assertion to turn it into a
real proof.

This is the honest line for the proof-discipline claim:

> ChainEDR generates compilable Foundry test skeletons per finding,
> one per supported rule, with a documented objective and a
> refutation path. The skeletons are workspaces, not exploits.

## Reproduce

```bash
chainedr scan benchmarks/eip7702_sandbox/vulnerable \
    --no-external --prove --prove-out tmp_skeletons/
forge init --no-git /tmp/chainedr_prove_test
cp tmp_skeletons/*.t.sol /tmp/chainedr_prove_test/test/
cd /tmp/chainedr_prove_test && forge build
```

If the SUPPORTED_RULES set in `src/poc_skeletons.py` grows, re-run
this verification before claiming the new rule is "prove-discipline
covered".
