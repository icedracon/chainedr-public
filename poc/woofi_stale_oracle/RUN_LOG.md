# WooFi stale-oracle PoC run log

Date: 2026-06-02

## Build

Command:

```powershell
C:\Users\zevs\.foundry\bin\forge.exe build
```

Result:

- Compiles successfully.
- Also compiles successfully under WSL with Foundry `1.7.1`.

## Live fork checks

### Base

Target:

- WooPPV2: `0xed9e3f98bbed560e66b89aac922e29d4596a9642`
- WooracleV2_2 from `pool.wooracle()`: `0x2A375567f5E13F6bd74fDa7627Df3b1Af6BfA5a6`

Result:

- `testFork_livePreconditions()` failed: `pool is paused`.
- Verdict: not submit-ready on latest Base state.

Historical fork sampling:

- Base block `26797218`: pool unpaused, quote reserve positive, WETH reserve positive, USDbC reserve positive.
- Blocking condition: `cloPreferred=false` for WETH and USDbC, so the direct stale Chainlink fallback path is not live.

Strict impact test at block `26797218`:

- Command: `bash scripts/run_fork_test.sh base 26797218 testFork_staleChainlinkPriceAcceptedAndTransfersExcessBase`
- Result: failed with `no live cloPreferred candidate with reserve`.

Local-only forced impact test at block `26797218`:

- Command: `bash scripts/run_fork_test.sh base 26797218 testLocal_forcedCloPreferredStalePriceTransfersExcessBase`
- Result: passed after locally impersonating the oracle owner and setting `cloPreferred=true`.
- Base token: `0x4200000000000000000000000000000000000006` (WETH)
- Quote token: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (USDC)
- Fresh baseline output for 10 USDC: `3666810750167082` wei WETH
- Stale-price output for 10 USDC: `3985663858881079` wei WETH
- Accepted stale price deviation: `9200` bps of the fresh base feed answer
- Stale age: `7200` seconds
- Verdict: mechanics proven locally, but not a submit-ready live exploit because the real config had `cloPreferred=false`.

### Arbitrum

Target:

- WooPPV2: `0xed9e3f98bbed560e66b89aac922e29d4596a9642`
- Wooracle from `pool.wooracle()`: `0xCf4EA1688bc23DD93D933edA535F8B72FC8934Ec`

Result:

- `testFork_livePreconditions()` failed: `pool is paused`.
- Verdict: not submit-ready on latest Arbitrum state.

### BSC

Target:

- Candidate address: `0x9498563e47D7CFdFa22B818bb8112781036c201C`

Result:

- Address has code and `paused()` returns `false`.
- EIP-1967 implementation slot resolves to `0x2120c8631bf156ef0f5302dc0b20ce4fa19436b4`.
- `wooracle()`, `woOracle()`, `oracle()`, `quoteToken()`, and `poolSize(address)` reverted.
- Verdict: this address does not expose the WooPPV2 interface expected by this PoC. It needs separate ABI/source triage before it can be used for the stale `WooracleV2_2` path.

## Current submission verdict

Do not submit yet.

The static ChainEDR signal is real at the code level, and the Foundry PoC is ready to prove impact, but the checked live pool states did not satisfy the submission preconditions.

Submit only if a future run passes:

```powershell
forge test --match-test testFork_staleChainlinkPriceAcceptedAndTransfersExcessBase -vvv
```

Required pass condition:

- pool unpaused;
- positive quote and base reserves;
- selected base token has `cloPreferred = true`;
- stale `latestRoundData().updatedAt` is accepted;
- `swap()` transfers more base token than the fresh-price baseline.
