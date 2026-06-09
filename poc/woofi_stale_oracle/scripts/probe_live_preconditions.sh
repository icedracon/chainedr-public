#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${CHAINEDR_REPO_DIR:-/mnt/c/Users/zevs/Documents/chainedr_commercial}"
CAST_BIN="${CAST_BIN:-/root/.foundry/bin/cast}"
POOL="${WOO_PP:-0xEd9e3f98bBed560e66B89AaC922E29D4596A9642}"

if [[ ! -x "$CAST_BIN" ]]; then
  echo "missing cast binary: $CAST_BIN" >&2
  exit 2
fi

ALCHEMY_API_KEY="${ALCHEMY_API_KEY:-}"
if [[ -z "$ALCHEMY_API_KEY" ]]; then
  ALCHEMY_API_KEY="$(grep -m1 '^ALCHEMY_API_KEY=' "$REPO_DIR/.env" | cut -d= -f2- | tr -d '\r')"
fi

if [[ -z "$ALCHEMY_API_KEY" ]]; then
  echo "missing ALCHEMY_API_KEY" >&2
  exit 2
fi

safe_call() {
  local rpc="$1"
  local block="$2"
  local target="$3"
  local sig="$4"
  shift 4
  "$CAST_BIN" call "$target" "$sig" "$@" --block "$block" --rpc-url "$rpc" 2>/dev/null || echo "ERR"
}

probe_chain() {
  local chain="$1"
  local rpc="$2"
  shift 2
  local candidates=("$@")

  local latest
  latest="$("$CAST_BIN" block-number --rpc-url "$rpc")"
  echo "== $chain latest=$latest pool=$POOL =="

  local deltas=(0 50000 100000 200000 500000 1000000 2000000 4000000 8000000 12000000 16000000 20000000 26000000 32000000 38000000)
  for delta in "${deltas[@]}"; do
    local block=$((latest - delta))
    [[ "$block" -le 0 ]] && continue

    local paused oracle quote
    paused="$(safe_call "$rpc" "$block" "$POOL" 'paused()(bool)')"
    oracle="$(safe_call "$rpc" "$block" "$POOL" 'wooracle()(address)')"
    quote="$(safe_call "$rpc" "$block" "$POOL" 'quoteToken()(address)')"
    echo "$chain block=$block paused=$paused oracle=$oracle quote=$quote"

    if [[ "$paused" == "false" && "$oracle" != "ERR" && "$quote" != "ERR" ]]; then
      local quote_reserve
      quote_reserve="$(safe_call "$rpc" "$block" "$POOL" 'poolSize(address)(uint256)' "$quote")"
      echo "  quote_reserve=$quote_reserve"
      for base in "${candidates[@]}"; do
        [[ "${base,,}" == "${quote,,}" ]] && continue
        local base_reserve clo
        base_reserve="$(safe_call "$rpc" "$block" "$POOL" 'poolSize(address)(uint256)' "$base")"
        clo="$(safe_call "$rpc" "$block" "$oracle" 'clOracles(address)(address,uint8,bool)' "$base")"
        echo "  base=$base reserve=$base_reserve clo=$clo"
      done
    fi
  done
}

BASE_RPC="https://base-mainnet.g.alchemy.com/v2/$ALCHEMY_API_KEY"
ARB_RPC="https://arb-mainnet.g.alchemy.com/v2/$ALCHEMY_API_KEY"

probe_chain \
  "base" \
  "$BASE_RPC" \
  0x4200000000000000000000000000000000000006 \
  0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA \
  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

probe_chain \
  "arbitrum" \
  "$ARB_RPC" \
  0x82aF49447D8a07e3bd95BD0d56f35241523fBab1 \
  0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8 \
  0xaf88d065e77c8cC2239327C5EDb3A432268e5831 \
  0xcAFcD85D8ca7Ad1e1C6F82F651fA15E33AEfD07b
