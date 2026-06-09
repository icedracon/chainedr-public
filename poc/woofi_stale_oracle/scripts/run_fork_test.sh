#!/usr/bin/env bash
set -euo pipefail

CHAIN="${1:-base}"
FORK_BLOCK_ARG="${2:-0}"
TEST_NAME="${3:-testFork_staleChainlinkPriceAcceptedAndTransfersExcessBase}"

REPO_DIR="${CHAINEDR_REPO_DIR:-/mnt/c/Users/zevs/Documents/chainedr_commercial}"
FORGE_BIN="${FORGE_BIN:-/root/.foundry/bin/forge}"

ALCHEMY_API_KEY="${ALCHEMY_API_KEY:-}"
if [[ -z "$ALCHEMY_API_KEY" ]]; then
  ALCHEMY_API_KEY="$(grep -m1 '^ALCHEMY_API_KEY=' "$REPO_DIR/.env" | cut -d= -f2- | tr -d '\r')"
fi

case "$CHAIN" in
  base)
    export FORK_RPC_URL="https://base-mainnet.g.alchemy.com/v2/$ALCHEMY_API_KEY"
    ;;
  arbitrum|arb)
    export FORK_RPC_URL="https://arb-mainnet.g.alchemy.com/v2/$ALCHEMY_API_KEY"
    ;;
  bsc)
    export FORK_RPC_URL="${BSC_RPC_URL:-https://bsc-dataseed.binance.org}"
    ;;
  *)
    export FORK_RPC_URL="$CHAIN"
    ;;
esac

if [[ "$FORK_BLOCK_ARG" != "0" ]]; then
  export FORK_BLOCK="$FORK_BLOCK_ARG"
else
  unset FORK_BLOCK || true
fi

cd "$REPO_DIR/poc/woofi_stale_oracle"
"$FORGE_BIN" test --match-test "$TEST_NAME" -vvv
