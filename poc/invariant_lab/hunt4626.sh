#!/bin/bash
# Run the generic ERC-4626 invariant hunt against real mainnet vaults on a fork.
export PATH=$HOME/.foundry/bin:$PATH
cd /mnt/c/Users/zevs/Documents/chainedr_commercial/poc/invariant_lab
RPC=$(grep '^RPC_URL=' ../../.env | cut -d= -f2-)

# name:address  — real mainnet ERC-4626 vaults
declare -A V=(
  [sDAI]=0x83F20F44975D03b1b09e64809B757c47f942BEeA
  [sUSDe]=0x9D39A5DE30e57443BfF2A8307A4256c8797A3497
  [Morpho_gtUSDC]=0xBEEf01735c132Ada46AA9aA4c54623cAA92A64CB
  [Morpho_steakUSDC]=0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB
  [sFRAX]=0xA663B02CF0a4b149d2aD41910CB81e23e1c41c32
)
for name in "${!V[@]}"; do
  echo "===== $name ${V[$name]} ====="
  VAULT=${V[$name]} forge test --mc ERC4626Hunt --fork-url "$RPC" -vv 2>&1 \
    | grep -E "\[PASS\]|\[FAIL\]|INFLATION|INSOLVENT|deposited|redeemed|revert" | head -12
done
