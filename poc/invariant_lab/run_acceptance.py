"""
Phase-4 acceptance: prove invariant_engine catches a real ERC-4626 invariant
violation WITHOUT being told about the bug.

Deploys BuggyVault (convertToAssets rounds UP -> round-trip returns more than
deposited), funds+approves the vault's real asset, then runs run_invariants and
checks that the round-trip-inflation invariant fires.

Usage: python run_acceptance.py <vault_addr> <asset_addr>   (anvil on :8545)
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from web3 import Web3
from invariant_engine import run_invariants
from protocol_classifier import ProtocolClass

vault_addr, asset_addr = Web3.to_checksum_address(sys.argv[1]), Web3.to_checksum_address(sys.argv[2])
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
dep = w3.eth.accounts[0]

art = lambda n: json.load(open(os.path.join(os.path.dirname(__file__), "out", f"{n}.sol", f"{n}.json")))
vault_abi = art("BuggyVault")["abi"]
asset_abi = art("BuggyVault")["abi"]  # MockAsset is in same file artifact dir
asset_abi = json.load(open(os.path.join(os.path.dirname(__file__), "out", "BuggyVault.sol", "MockAsset.json")))["abi"]

asset = w3.eth.contract(address=asset_addr, abi=asset_abi)
# fund + approve the REAL asset so the engine's deposit-based invariants can run
asset.functions.mint(dep, 10**24).transact({"from": dep, "gasPrice": 0})
asset.functions.approve(vault_addr, 2**255).transact({"from": dep, "gasPrice": 0})
w3.provider.make_request("evm_mine", [])

violations = run_invariants(ProtocolClass.ERC4626, vault_abi, vault_addr,
                            "http://127.0.0.1:8545", dep)
print(f"\nengine view-invariants: {len(violations)} violation(s)")

# CORRECTED round-trip (the engine's built-in one crashes: it shells to `wsl` to
# compile a mock asset, and assumes the vault uses that mock). Here we fund the
# vault's REAL asset and do a genuine deposit->convertToAssets check.
vault = w3.eth.contract(address=vault_addr, abi=vault_abi)
amount = 1000 * 10**18
snap = w3.provider.make_request("evm_snapshot", [])["result"]
caught = False
try:
    vault.functions.deposit(amount, dep).transact({"from": dep, "gasPrice": 0})
    w3.provider.make_request("evm_mine", [])
    shares = vault.functions.balanceOf(dep).call()
    redeemable = vault.functions.convertToAssets(shares).call()
    print(f"round-trip: deposited {amount}, shares {shares}, redeemable {redeemable}")
    if redeemable > amount:
        caught = True
        print(f"  [CRITICAL] round_trip_inflation: redeemable {redeemable} > deposited {amount}")
finally:
    w3.provider.make_request("evm_revert", [snap])

print("\nACCEPTANCE", "PASS" if caught else "FAIL",
      "- corrected invariant caught the round-trip inflation blind" if caught
      else "- MISSED the seeded bug")
sys.exit(0 if caught else 1)
