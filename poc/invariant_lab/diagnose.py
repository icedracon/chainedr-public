import json, os, sys, traceback
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from web3 import Web3
from invariant_engine import InvariantGenerator
from protocol_classifier import ProtocolClass

vault_addr, asset_addr = Web3.to_checksum_address(sys.argv[1]), Web3.to_checksum_address(sys.argv[2])
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
dep = w3.eth.accounts[0]
vault_abi = json.load(open(os.path.join(os.path.dirname(__file__), "out", "BuggyVault.sol", "BuggyVault.json")))["abi"]
asset_abi = json.load(open(os.path.join(os.path.dirname(__file__), "out", "BuggyVault.sol", "MockAsset.json")))["abi"]
asset = w3.eth.contract(address=asset_addr, abi=asset_abi)
asset.functions.mint(dep, 10**24).transact({"from": dep, "gasPrice": 0})
asset.functions.approve(vault_addr, 2**255).transact({"from": dep, "gasPrice": 0})
w3.provider.make_request("evm_mine", [])

gen = InvariantGenerator("http://127.0.0.1:8545", dep)
invs = gen.generate(ProtocolClass.ERC4626, vault_abi, vault_addr)
print(f"generated {len(invs)} invariants:")
for inv in invs:
    print(f"  - {inv.name}")
    try:
        v = inv.check_fn()   # call directly, NO swallow
        print(f"      result: {'VIOLATION '+v.invariant_name if v else 'ok/None'}")
    except Exception as e:
        print(f"      RAISED: {type(e).__name__}: {str(e)[:160]}")
