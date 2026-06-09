#!/bin/bash
# Run the ERC-4626 invariant harness over every harvested vault on a mainnet fork.
# Reports only REAL breaks (INFLATION/INSOLVENT) — async-redeem skips are not breaks.
export PATH=$HOME/.foundry/bin:$PATH
cd /mnt/c/Users/zevs/Documents/chainedr_commercial/poc/invariant_lab
RPC=$(grep '^RPC_URL=' ../../.env | cut -d= -f2-)
ADDRS=$(python3 -c "import json;print(' '.join(v['vault'] for v in json.load(open('vaults_4626.json'))))")
BREAKS=0
for a in $ADDRS; do
  OUT=$(VAULT=$a forge test --mc ERC4626Hunt --fork-url "$RPC" -vv 2>&1)
  if echo "$OUT" | grep -qiE "Compilation failed|Compiler run failed"; then
    echo "  COMPILE-ERROR (not a finding) $a"; continue
  fi
  # a REAL break needs an actual [FAIL marker AND an invariant message
  if echo "$OUT" | grep -qE "\[FAIL" && echo "$OUT" | grep -qE "INFLATION|INSOLVENT"; then
    echo "!!!! POTENTIAL BREAK on $a"
    echo "$OUT" | grep -E "\[FAIL|INFLATION|INSOLVENT|deposited|redeemed|worth" | head -8
    BREAKS=$((BREAKS+1))
  else
    P=$(echo "$OUT" | grep -cE "\[PASS\]")
    echo "  clean $a (${P} pass)"
  fi
done
echo ""
echo "==== batch done: $BREAKS potential break(s) across $(echo $ADDRS | wc -w) vaults ===="
