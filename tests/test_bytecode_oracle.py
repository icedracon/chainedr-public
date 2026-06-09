import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from eth_utils import keccak  # noqa: E402
from eth_abi import encode  # noqa: E402

from bytecode_oracle import (  # noqa: E402
    DELEGATION_PREFIX,
    KNOWN_SELECTORS,
    EIP7702DelegationProbe,
    build_erc20_approval_execute_candidates,
    build_erc20_sweep_execute_candidates,
    build_erc721_sweep_execute_candidates,
    build_erc1155_sweep_execute_candidates,
    classify_guard_surface,
    erc20_approve_calldata,
    erc20_transfer_calldata,
    execute_calldata,
    extract_push20_addresses,
    extract_push4_selectors,
    extract_value_flows_from_call_trace,
    profile_bytecode,
)


def _mapping_key(account: str, slot: int) -> str:
    return "0x" + keccak(encode(["address", "uint256"], [account, slot])).hex()


def test_known_selectors_hash_correctly():
    # P0 guard: every entry's key MUST equal keccak(signature)[:4]. Prevents
    # shipping a fabricated selector->signature mapping (the e9cb1f0d regression).
    for selector, (signature, _tag) in KNOWN_SELECTORS.items():
        assert keccak(text=signature)[:4].hex() == selector, (selector, signature)


def test_extract_push20_skips_all_ff_mask():
    # PUSH20 0xff..ff (address bitmask) must NOT be reported as an embedded address.
    assert extract_push20_addresses("0x73" + "ff" * 20 + "00") == []


def test_dispatcher_only_selectors_require_eq():
    # PUSH4 sel EQ  -> kept;  bare PUSH4 -> dropped in dispatcher_only mode.
    # 0x63<70a08231>14 (EQ)  then  0x63<a9059cbb>00 (no EQ)
    bytecode = "0x6370a0823114" + "63a9059cbb00"
    assert extract_push4_selectors(bytecode, dispatcher_only=True) == ["70a08231"]
    # raw mode still sees both (preserved API)
    assert extract_push4_selectors(bytecode) == ["70a08231", "a9059cbb"]


def test_execute_calldata_matches_abi_for_execute_and_batch():
    token = "0x2222222222222222222222222222222222222222"
    recipient = "0x000000000000000000000000000000000000beef"
    inner = erc20_transfer_calldata(recipient, 123)
    inner_bytes = bytes.fromhex(inner[2:])

    single = execute_calldata("b61d27f6", token, 0, inner)
    expected_single = "0xb61d27f6" + encode(
        ["address", "uint256", "bytes"],
        [token, 0, inner_bytes],
    ).hex()
    assert single == expected_single

    batch = execute_calldata("47e1da2a", token, 0, inner)
    expected_batch = "0x47e1da2a" + encode(
        ["address[]", "uint256[]", "bytes[]"],
        [[token], [0], [inner_bytes]],
    ).hex()
    assert batch == expected_batch

    tuple_batch = execute_calldata("34fcd5be", token, 0, inner)
    expected_tuple_batch = "0x34fcd5be" + encode(
        ["(address,uint256,bytes)[]"],
        [[(token, 0, inner_bytes)]],
    ).hex()
    assert tuple_batch == expected_tuple_batch


def test_erc20_sweep_candidates_only_for_supported_execute_selectors():
    candidates = build_erc20_sweep_execute_candidates(
        ["0xb61d27f6", "47e1da2a", "c4d66de8"],
        "0x2222222222222222222222222222222222222222",
        "0x000000000000000000000000000000000000beef",
        123,
    )

    assert {c.selector for c in candidates} == {"b61d27f6", "47e1da2a"}
    assert {c.objective for c in candidates} == {"erc20_sweep_via_execute"}
    assert all(c.inner_call.startswith("0xa9059cbb") for c in candidates)


def test_v2_candidate_builders_cover_approval_and_nfts():
    selectors = ["b61d27f6", "34fcd5be", "c4d66de8"]
    token = "0x2222222222222222222222222222222222222222"
    victim = "0x7702000000000000000000000000000000000001"
    recipient = "0x000000000000000000000000000000000000beef"

    approvals = build_erc20_approval_execute_candidates(selectors, token, recipient, 123)
    erc721 = build_erc721_sweep_execute_candidates(selectors, token, victim, recipient, 7)
    erc1155 = build_erc1155_sweep_execute_candidates(selectors, token, victim, recipient, 7, 2)

    assert {c.selector for c in approvals} == {"b61d27f6", "34fcd5be"}
    assert all(c.inner_call.startswith("0x095ea7b3") for c in approvals)
    assert {c.objective for c in erc721} == {
        "erc721_sweep_safe_transfer_via_execute",
        "erc721_sweep_transfer_from_via_execute",
    }
    assert {c.objective for c in erc1155} == {"erc1155_sweep_via_execute"}


def test_value_flow_skips_delegatecall():
    # A proxy delegatecalling its impl carries `value` but moves no ETH — must NOT
    # be counted as an outbound transfer (the Coinbase EIP7702Proxy FP).
    trace = {
        "type": "CALL", "from": "0xpayer", "to": "0xvictim", "value": "0xde0b6b3a7640000",
        "calls": [
            {"type": "DELEGATECALL", "from": "0xvictim", "to": "0ximpl",
             "value": "0xde0b6b3a7640000"}
        ],
    }
    flows = extract_value_flows_from_call_trace(trace)
    # only the inbound CALL counts; the delegatecall frame is excluded
    assert [f.call_type for f in flows] == ["CALL"]
    assert [f.recipient for f in flows] == ["0xvictim"]


def test_probe_state_write_confirms_unauthorized_write():
    # Simulate Porwarder: a non-owner calls initialize(address); slot 0 flips.
    attacker = "0x000000000000000000000000000000000000bEEF"

    class FakeEth:
        accounts = ["0x0000000000000000000000000000000000000111"]

        def __init__(self):
            self.storage = {}

        def get_storage_at(self, addr, slot):
            return self.storage.get(slot, b"\x00" * 32)

        def send_transaction(self, tx):
            arg_word = tx["data"][2:][8:8 + 64]   # the 32-byte arg after the selector
            self.storage[0] = bytes.fromhex(arg_word)   # setter writes slot 0
            return b"\x11" * 32

        def wait_for_transaction_receipt(self, h):
            return type("R", (), {"status": 1})()

    class FakeProvider:
        def make_request(self, method, params):
            return {"result": True}

    class FakeW3:
        def __init__(self):
            self.eth = FakeEth()
            self.provider = FakeProvider()

    probe = EIP7702DelegationProbe(FakeW3(), "0x7702000000000000000000000000000000000001")
    v = probe.probe_state_write(
        "0x1212121212121212121212121212121212121212", "c4d66de8", attacker)
    assert v.confirmed is True
    assert 0 in v.changed_slots
    assert v.tx_status == 1


def test_probe_erc20_sweep_confirms_balance_diff():
    victim = "0x7702000000000000000000000000000000000001"
    implementation = "0x1212121212121212121212121212121212121212"
    token = "0x2222222222222222222222222222222222222222"
    recipient = "0x000000000000000000000000000000000000beef"
    attacker = "0x000000000000000000000000000000000000aaaa"
    amount = 100

    class FakeEth:
        accounts = ["0x0000000000000000000000000000000000000111", attacker]

        def __init__(self):
            self.balances = {
                victim.lower(): 1_000,
                recipient.lower(): 0,
            }

        def call(self, tx):
            assert tx["to"].lower() == token.lower()
            assert tx["data"].startswith("0x70a08231")
            account = "0x" + tx["data"][-40:]
            return self.balances.get(account.lower(), 0).to_bytes(32, "big")

        def send_transaction(self, tx):
            assert tx["from"].lower() == attacker.lower()
            assert tx["to"].lower() == victim.lower()
            assert tx["data"].startswith("0xb61d27f6")
            assert "a9059cbb" in tx["data"]
            self.balances[victim.lower()] -= amount
            self.balances[recipient.lower()] += amount
            return b"\x22" * 32

        def wait_for_transaction_receipt(self, h):
            return type("R", (), {"status": 1})()

    class FakeProvider:
        def make_request(self, method, params):
            assert method == "anvil_setCode"
            return {"result": True}

    class FakeW3:
        def __init__(self):
            self.eth = FakeEth()
            self.provider = FakeProvider()

    calldata = execute_calldata(
        "b61d27f6",
        token,
        0,
        erc20_transfer_calldata(recipient, amount),
    )
    probe = EIP7702DelegationProbe(FakeW3(), victim)

    verdict = probe.probe_erc20_sweep_with_calldata(
        implementation,
        token,
        recipient,
        calldata,
        caller=attacker,
    )

    assert verdict.confirmed is True
    assert verdict.victim_before == 1_000
    assert verdict.victim_after == 900
    assert verdict.recipient_before == 0
    assert verdict.recipient_after == 100
    assert verdict.tx_status == 1


def test_probe_erc20_approval_confirms_allowance_and_transfer_from():
    victim = "0x7702000000000000000000000000000000000001"
    implementation = "0x1212121212121212121212121212121212121212"
    token = "0x2222222222222222222222222222222222222222"
    spender = "0x000000000000000000000000000000000000aaaa"
    recipient = "0x000000000000000000000000000000000000beef"
    amount = 100

    class FakeEth:
        accounts = ["0x0000000000000000000000000000000000000111", spender]

        def __init__(self):
            self.balances = {victim.lower(): amount, recipient.lower(): 0}
            self.allowance = 0

        def call(self, tx):
            data = tx["data"]
            if data.startswith("0xdd62ed3e"):
                return self.allowance.to_bytes(32, "big")
            if data.startswith("0x70a08231"):
                account = "0x" + data[-40:]
                return self.balances.get(account.lower(), 0).to_bytes(32, "big")
            raise AssertionError(data)

        def send_transaction(self, tx):
            data = tx.get("data", "")
            if tx["to"].lower() == victim.lower():
                assert data.startswith("0xb61d27f6")
                assert "095ea7b3" in data
                self.allowance = amount
            elif tx["to"].lower() == token.lower():
                assert tx["from"].lower() == spender.lower()
                assert data.startswith("0x23b872dd")
                self.balances[victim.lower()] -= amount
                self.balances[recipient.lower()] += amount
            return b"\x44" * 32

        def wait_for_transaction_receipt(self, h):
            return type("R", (), {"status": 1})()

    class FakeProvider:
        def make_request(self, method, params):
            return {"result": True}

    class FakeW3:
        def __init__(self):
            self.eth = FakeEth()
            self.provider = FakeProvider()

    calldata = execute_calldata(
        "b61d27f6",
        token,
        0,
        erc20_approve_calldata(spender, amount),
    )
    probe = EIP7702DelegationProbe(FakeW3(), victim)

    verdict = probe.probe_erc20_approval_with_calldata(
        implementation,
        token,
        spender,
        recipient,
        calldata,
        amount,
        caller=spender,
    )

    assert verdict.allowance_confirmed is True
    assert verdict.exploited is True
    assert verdict.victim_after == 0
    assert verdict.recipient_after == amount


def test_erc20_funding_patches_verified_balance_slot():
    token = "0x2222222222222222222222222222222222222222"
    holder = "0x7702000000000000000000000000000000000001"
    amount = 123

    class FakeEth:
        accounts = []

        def __init__(self):
            self.balances = {holder.lower(): 0}
            self.last_balance_holder = ""

        def call(self, tx):
            self.last_balance_holder = "0x" + tx["data"][-40:]
            return self.balances.get(self.last_balance_holder.lower(), 0).to_bytes(32, "big")

    class FakeProvider:
        def __init__(self, eth):
            self.eth = eth
            self.requests = []

        def make_request(self, method, params):
            self.requests.append((method, params))
            if method == "anvil_setStorageAt":
                self.eth.balances[self.eth.last_balance_holder.lower()] = int(params[2], 16)
            return {"result": True}

    class FakeW3:
        def __init__(self):
            self.eth = FakeEth()
            self.provider = FakeProvider(self.eth)

    probe = EIP7702DelegationProbe(FakeW3(), holder)

    verdict = probe.fund_erc20_balance_slot(token, holder, amount, candidate_slots=[0])

    assert verdict.confirmed is True
    assert verdict.before == 0
    assert verdict.after == amount
    assert verdict.storage_slot == 0
    assert verdict.storage_key == _mapping_key(holder, 0)


def test_erc721_funding_and_sweep_probe_confirm_owner_change():
    victim = "0x7702000000000000000000000000000000000001"
    implementation = "0x1212121212121212121212121212121212121212"
    nft = "0x2222222222222222222222222222222222222222"
    recipient = "0x000000000000000000000000000000000000beef"
    attacker = "0x000000000000000000000000000000000000aaaa"
    token_id = 7

    class FakeEth:
        accounts = ["0x0000000000000000000000000000000000000111", attacker]

        def __init__(self):
            self.owner = "0x0000000000000000000000000000000000000000"

        def call(self, tx):
            assert tx["data"].startswith("0x6352211e")
            return int(self.owner, 16).to_bytes(32, "big")

        def send_transaction(self, tx):
            assert tx["to"].lower() == victim.lower()
            assert "42842e0e" in tx["data"]
            self.owner = recipient
            return b"\x55" * 32

        def wait_for_transaction_receipt(self, h):
            return type("R", (), {"status": 1})()

    class FakeProvider:
        def __init__(self, eth):
            self.eth = eth

        def make_request(self, method, params):
            if method == "anvil_setStorageAt":
                self.eth.owner = "0x" + params[2][-40:]
            return {"result": True}

    class FakeW3:
        def __init__(self):
            self.eth = FakeEth()
            self.provider = FakeProvider(self.eth)

    w3 = FakeW3()
    probe = EIP7702DelegationProbe(w3, victim)
    funding = probe.fund_erc721_owner_slot(nft, victim, token_id, candidate_slots=[0])
    calldata = build_erc721_sweep_execute_candidates(
        ["b61d27f6"], nft, victim, recipient, token_id,
    )[0].calldata

    verdict = probe.probe_erc721_sweep_with_calldata(
        implementation, nft, recipient, token_id, calldata, caller=attacker,
    )

    assert funding.confirmed is True
    assert verdict.confirmed is True
    assert verdict.victim_before.lower() == victim.lower()
    assert verdict.victim_after.lower() == recipient.lower()


def test_extract_push4_selectors_skips_push_data():
    # PUSH4 balanceOf, PUSH4 transfer, STOP
    bytecode = "0x6370a0823163a9059cbb00"

    assert extract_push4_selectors(bytecode) == ["70a08231", "a9059cbb"]


def test_profile_flags_erc20_sweep_surface():
    # PUSH4 balanceOf + PUSH4 transfer + CALLVALUE + CALL
    bytecode = "0x6370a0823163a9059cbb34f100"

    profile = profile_bytecode(bytecode, "0x0000000000000000000000000000000000000001")

    assert profile.severity == "HIGH"
    assert "erc20_balance_sweep_surface" in profile.risk_flags
    assert profile.known_selectors["70a08231"] == "balanceOf(address)"
    assert profile.known_selectors["a9059cbb"] == "transfer(address,uint256)"
    assert "token_movement_surface" in profile.proof_surfaces
    assert "erc20_balance_or_allowance_diff" in profile.recommended_probes
    assert profile.triage_score > profile.risk_score


def test_guard_classifier_identifies_auth_surfaces():
    # Dispatcher-style PUSH4/EQ constants plus CALLER. This is a guard hint, not
    # a proof of safety; dynamic probes still decide exploitability.
    bytecode = (
        "0x"
        "638da5cb5b14"  # owner()
        "63b0d691fe14"  # entryPoint()
        "637ecebe0014"  # nonces(address)
        "631626ba7e14"  # isValidSignature(bytes32,bytes)
        "633644e51514"  # DOMAIN_SEPARATOR()
        "33"            # CALLER
    )

    surface = classify_guard_surface(bytecode)

    assert surface.guard_strength == "strong"
    assert surface.likely_guarded is True
    assert "owner_or_signer_surface" in surface.hints
    assert "entrypoint_or_userop_surface" in surface.hints
    assert "erc1271_signature_surface" in surface.hints
    assert "nonce_surface" in surface.hints

    profile = profile_bytecode(bytecode)
    assert profile.guard_surface["guard_strength"] == "strong"
    assert "erc1271_magic_value_negative_control" in profile.recommended_probes


def test_profile_plans_live_value_and_selfdestruct_probes():
    bytecode = "0x34f1ff00"  # CALLVALUE, CALL, SELFDESTRUCT, STOP

    profile = profile_bytecode(bytecode)

    assert "unguarded_receive_value" in profile.proof_surfaces
    assert "selfdestruct_surface" in profile.proof_surfaces
    assert "receive_value_delegation" in profile.recommended_probes
    assert "selfdestruct_or_forced_value_probe" in profile.recommended_probes


def test_extract_push20_addresses():
    bytecode = "0x73b1280932da6df283be6dddd99f2a147d4177398800"

    addresses = extract_push20_addresses(bytecode)

    assert [a.lower() for a in addresses] == ["0xb1280932da6df283be6dddd99f2a147d41773988"]


def test_extract_value_flows_from_nested_call_trace():
    trace = {
        "type": "CALL",
        "from": "0xaaa",
        "to": "0xvictim",
        "value": "0xde0b6b3a7640000",
        "calls": [
            {
                "type": "CALL",
                "from": "0xvictim",
                "to": "0xbeef",
                "value": "0xde0b6b3a7640000",
            }
        ],
    }

    flows = extract_value_flows_from_call_trace(trace)

    assert [f.recipient for f in flows] == ["0xvictim", "0xbeef"]
    assert flows[1].value_wei == 10**18


def test_delegation_probe_writes_eip7702_pointer_code():
    class FakeProvider:
        def __init__(self):
            self.requests = []

        def make_request(self, method, params):
            self.requests.append((method, params))
            return {"result": True}

    class FakeW3:
        def __init__(self):
            self.provider = FakeProvider()

    w3 = FakeW3()
    probe = EIP7702DelegationProbe(
        w3,
        "0x7702000000000000000000000000000000000001",
    )
    impl = "0x1212121212121212121212121212121212121212"

    probe.set_delegation(impl)

    assert w3.provider.requests == [
        (
            "anvil_setCode",
            [
                "0x7702000000000000000000000000000000000001",
                "0x" + DELEGATION_PREFIX + impl[2:],
            ],
        )
    ]
