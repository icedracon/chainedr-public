#!/bin/bash
export PATH=$HOME/.foundry/bin:$PATH
cd /mnt/c/Users/zevs/Documents/chainedr_commercial/poc/invariant_lab
forge build 2>&1 | tail -2
anvil --base-fee 0 --gas-price 0 --silent &
AP=$!
sleep 3
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC=http://127.0.0.1:8545
VAULT=$(forge create BuggyVault.sol:BuggyVault --rpc-url $RPC --private-key $KEY --broadcast 2>/dev/null | grep "Deployed to:" | grep -oE "0x[0-9a-fA-F]{40}")
echo "vault=$VAULT"
ASSET=$(cast call "$VAULT" "asset()(address)" --rpc-url $RPC)
echo "asset=$ASSET"
python3 run_acceptance.py "$VAULT" "$ASSET"
RC=$?
kill $AP 2>/dev/null
exit $RC
