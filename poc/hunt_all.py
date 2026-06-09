import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from web3 import Web3
from bytecode_oracle import EIP7702DelegationProbe, extract_push4_selectors

anvil = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert anvil.is_connected(), "forked anvil not up"
atk = anvil.eth.accounts[2]
impls = json.load(open(os.path.join(os.path.dirname(__file__), "..", "hunt_impls.json")))
hits = []
for i, r in enumerate(impls):
    addr = Web3.to_checksum_address(r["impl"])
    rt = anvil.eth.get_code(addr).hex()  # from fork (real code + deps present)
    sels = extract_push4_selectors(rt, dispatcher_only=True) or extract_push4_selectors(rt)
    victim = "0x7702" + f"{i:036x}"
    p = EIP7702DelegationProbe(anvil, Web3.to_checksum_address(victim))
    try:
        sw = p.confirm_unauthorized_state_writes(addr, sels, atk)  # fork: no reinstall
        vf = p.probe_receive_value(addr)
    except Exception as e:
        print(f"  {addr} deleg={r['delegations']}: probe error {type(e).__name__}"); continue
    flags = []
    if sw: flags.append(f"STATE-WRITE {[(w.selector, w.changed_slots) for w in sw]}")
    if vf.observed_outbound_value: flags.append("VALUE-SWEEP " + str([f.to_dict() for f in vf.value_flows]))
    if flags:
        print(f"  !! {addr} deleg={r['delegations']} code={r['code']}B sels={len(sels)} -> {' | '.join(flags)}")
        hits.append({"impl": addr, "delegations": r["delegations"], "flags": flags,
                     "state_writes": [w.to_dict() for w in sw],
                     "value_flows": [f.to_dict() for f in vf.value_flows] if vf.observed_outbound_value else []})

print(f"\nprobed {len(impls)} long-tail delegators -> {len(hits)} flagged")
json.dump(hits, open(os.path.join(os.path.dirname(__file__), "..", "hunt_hits.json"), "w"), indent=1)
