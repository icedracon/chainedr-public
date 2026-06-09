"""
Harvest live ERC-4626 vaults precisely via the standard Deposit event
(Deposit(address,address,uint256,uint256)) over recent blocks, dedupe, sanity-
check the 4626 interface, and emit a vault list for the invariant batch runner.

Usage: python harvest_4626.py [n_blocks] [max_vaults]   (uses RPC_URL from .env)
"""
import json, os, sys
from web3 import Web3
from eth_utils import keccak, to_checksum_address

N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
MAX = int(sys.argv[2]) if len(sys.argv) > 2 else 40
rpc = [l.split("=", 1)[1].strip() for l in open(os.path.join(os.path.dirname(__file__), "..", "..", ".env")) if l.startswith("RPC_URL=")][0]
w3 = Web3(Web3.HTTPProvider(rpc))
DEPOSIT_TOPIC = "0x" + keccak(text="Deposit(address,address,uint256,uint256)").hex()
latest = w3.eth.block_number
seen, vaults = set(), []
step = 2  # Alchemy caps topic-only (no-address) log queries to tiny ranges
bn = latest
while bn > latest - N and len(vaults) < MAX:
    frm = max(bn - step + 1, latest - N)
    try:
        logs = w3.eth.get_logs({"fromBlock": frm, "toBlock": bn, "topics": [DEPOSIT_TOPIC]})
    except Exception:
        logs = []
    for lg in logs:
        a = to_checksum_address(lg["address"])
        if a in seen:
            continue
        seen.add(a)
        # sanity: must look like ERC-4626
        try:
            c = w3.eth.contract(address=a, abi=[
                {"name": "asset", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]},
                {"name": "totalSupply", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
                {"name": "convertToAssets", "type": "function", "stateMutability": "view", "inputs": [{"type": "uint256"}], "outputs": [{"type": "uint256"}]},
            ])
            asset = c.functions.asset().call()
            ts = c.functions.totalSupply().call()
            c.functions.convertToAssets(10**18).call()
            vaults.append({"vault": a, "asset": asset, "totalSupply": str(ts)})
            if len(vaults) >= MAX:
                break
        except Exception:
            continue
    bn -= step

out = os.path.join(os.path.dirname(__file__), "vaults_4626.json")
json.dump(vaults, open(out, "w"), indent=1)
print(f"scanned ~{N} blocks; harvested {len(vaults)} live ERC-4626 vaults -> {out}")
for v in vaults:
    print(f"  {v['vault']}  ts={v['totalSupply']}")
