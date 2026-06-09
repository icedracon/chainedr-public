# WooFi stale Chainlink fallback fork PoC

This Foundry PoC checks whether WooFi's `WooracleV2_2.price()` accepts a stale Chainlink fallback price and whether `WooPPV2.swap()` can turn that accepted stale price into a token balance gain.

It is intentionally fail-closed:

- if the pool is paused, the test fails;
- if no candidate token has reserve, the test fails;
- if `cloPreferred` is not enabled, the test fails;
- if WooFi's guard ranges reject the stale price, the test fails;
- if a swap cannot transfer more base token than the fresh-price baseline, the test fails.

Passing this test is the minimum evidence needed before writing a manual Immunefi submission. A static detector hit alone is not enough.

## Run

Verified WSL path:

```powershell
cd <repo-root>/poc/woofi_stale_oracle && bash scripts/run_fork_test.sh base 0 testFork_staleChainlinkPriceAcceptedAndTransfersExcessBase"
```

Native Windows path if `forge.exe` is available:

```powershell
cd poc/woofi_stale_oracle
$env:FORK_RPC_URL="https://base-mainnet.g.alchemy.com/v2/YOUR_KEY"
C:\Users\zevs\.foundry\bin\forge.exe test --match-test testFork_staleChainlinkPriceAcceptedAndTransfersExcessBase -vvv
```

Optional knobs:

```powershell
$env:FORK_BLOCK="0"         # 0 means latest
$env:STALE_PRICE_BPS="8000" # starts at 80% of fresh price, then walks toward 100% if guards reject
$env:WOO_PP="0x..."         # override pool address for Arbitrum/BSC/etc.
$env:WOORACLE="0x..."       # optional; if set, must match pool.wooracle()
$env:WOO_BASE_TOKEN_0="0x..." # optional extra candidate token
```

## Target

Default target:

- WooPPV2 Base: `0xed9e3f98bbed560e66b89aac922e29d4596a9642`
- WooracleV2_2 Base: read from `pool.wooracle()` and expected to be `0x2A375567f5E13F6bd74fDa7627Df3b1Af6BfA5a6`

Known candidate commands:

```powershell
# Base, default target. Latest fork currently fails if the pool is paused.
$env:FORK_RPC_URL="https://base-mainnet.g.alchemy.com/v2/YOUR_KEY"
Remove-Item Env:\WOO_PP -ErrorAction SilentlyContinue
forge test --match-test testFork_livePreconditions -vvv

# Arbitrum candidate from the hunt notes.
$env:FORK_RPC_URL="https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY"
$env:WOO_PP="0xed9e3f98bbed560e66b89aac922e29d4596a9642"
forge test --match-test testFork_livePreconditions -vvv

# BSC candidate from the hunt notes. Requires a BSC RPC URL.
$env:FORK_RPC_URL="https://bsc-dataseed.binance.org"
$env:WOO_PP="0x9498563e47D7CFdFa22B818bb8112781036c201C"
forge test --match-test testFork_livePreconditions -vvv
```

## What a pass means

A pass means:

1. The live pool accepted a fallback Chainlink answer whose `updatedAt` is older than the configured heartbeat used by the PoC.
2. The pool priced a quote-to-base swap from that stale answer.
3. The attacker received more base token than the same swap would receive under a fresh answer.

## What a fail means

A fail means the report is not submit-ready. Common reasons:

- no live reserve for the tested token;
- `cloPreferred` disabled;
- pool paused;
- guardian min/max price range blocks the stale price;
- swap limits or gamma checks block the attempted amount.

## Local-only impact model

There is also a local-only test that force-enables `cloPreferred` by impersonating the oracle owner on the fork:

```powershell
cd <repo-root>/poc/woofi_stale_oracle && bash scripts/run_fork_test.sh base 26797218 testLocal_forcedCloPreferredStalePriceTransfersExcessBase"
```

This proves the mechanics of the stale Chainlink fallback path on real WooFi contracts and reserves, but it is not a submit-ready proof because the real historical config had `cloPreferred=false` for the reserve-bearing Base tokens.
