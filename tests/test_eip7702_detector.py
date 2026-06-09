"""
Tests for EIP-7702 Account Abstraction vulnerability detector.

Each check has:
  - POSITIVE: vulnerable Solidity snippet → must fire
  - NEGATIVE: safe variant → must not fire
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from eip7702_detector import (
    EIP7702Detector,
    detect_tx_origin_eoa_bypass,
    detect_iscontract_bypass,
    detect_callback_reentrancy,
    detect_cross_chain_replay,
    detect_missing_revocation,
    detect_delegatecall_from_delegation,
    detect_storage_collision,
    detect_initialization_race,
    detect_proxy_delegation_conflict,
    detect_permit_bypass,
    detect_batch_auth_ordering,
    detect_nonce_gap,
    detect_gas_griefing,
    detect_value_transfer_confusion,
    detect_selfdestruct_delegation,
    detect_ecrecover_delegation,
    detect_erc777_delegation,
    detect_approval_frontrun,
    detect_hardcoded_relayer,
    detect_missing_storage_namespace,
    detect_entrypoint_mismatch,
    _strip_comments,
)


@pytest.fixture(scope="module")
def detector():
    return EIP7702Detector()


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-001: tx.origin == msg.sender
# ─────────────────────────────────────────────────────────────────────────────

TX_ORIGIN_POSITIVE = """
pragma solidity ^0.8.0;
contract FlashLoanGuard {
    function borrow(uint256 amount) external {
        require(tx.origin == msg.sender, "no contracts");
        // ... lending logic
    }
}
"""

TX_ORIGIN_NEGATIVE = """
pragma solidity ^0.8.0;
contract SafeLending {
    mapping(address => bool) public allowlist;
    function borrow(uint256 amount) external {
        require(allowlist[msg.sender], "not allowed");
    }
}
"""

TX_ORIGIN_MODIFIER_POSITIVE = """
pragma solidity ^0.8.0;
contract NFTMint {
    modifier onlyEOA() {
        require(tx.origin == msg.sender);
        _;
    }
    function mint() external onlyEOA {
        // mint logic
    }
}
"""


class TestTxOriginBypass:
    def test_positive_require(self):
        findings = detect_tx_origin_eoa_bypass(_strip_comments(TX_ORIGIN_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-001"
        assert findings[0].severity == "CRITICAL"
        assert "borrow" in findings[0].title

    def test_negative_allowlist(self):
        findings = detect_tx_origin_eoa_bypass(_strip_comments(TX_ORIGIN_NEGATIVE))
        assert len(findings) == 0

    def test_positive_modifier(self):
        findings = detect_tx_origin_eoa_bypass(_strip_comments(TX_ORIGIN_MODIFIER_POSITIVE))
        assert len(findings) >= 1
        assert any("onlyEOA" in f.title for f in findings)

    def test_in_comment_ignored(self):
        src = """
pragma solidity ^0.8.0;
contract X {
    // require(tx.origin == msg.sender, "old guard");
    function foo() external {}
}
"""
        findings = detect_tx_origin_eoa_bypass(_strip_comments(src))
        assert len(findings) == 0

    def test_reversed_operand_order(self):
        src = """
pragma solidity ^0.8.0;
contract X {
    function bar() external {
        require(msg.sender == tx.origin, "no bots");
    }
}
"""
        findings = detect_tx_origin_eoa_bypass(_strip_comments(src))
        assert len(findings) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-002: isContract / code.length bypass
# ─────────────────────────────────────────────────────────────────────────────

ISCONTRACT_POSITIVE_OZ = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Address.sol";
contract Airdrop {
    using Address for address;
    function claim() external {
        require(!msg.sender.isContract(), "no contracts");
        // distribute tokens
    }
}
"""

ISCONTRACT_POSITIVE_RAW = """
pragma solidity ^0.8.0;
contract TokenSafe {
    function isEOA(address a) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(a) }
        return size == 0;
    }
    function withdraw() external {
        require(msg.sender.code.length == 0, "EOA only");
    }
}
"""

ISCONTRACT_NEGATIVE = """
pragma solidity ^0.8.0;
contract SafeToken {
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""


class TestIsContractBypass:
    def test_positive_oz_iscontract(self):
        findings = detect_iscontract_bypass(_strip_comments(ISCONTRACT_POSITIVE_OZ))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-002"

    def test_positive_raw_extcodesize(self):
        findings = detect_iscontract_bypass(_strip_comments(ISCONTRACT_POSITIVE_RAW))
        assert len(findings) >= 1
        # Should catch both extcodesize and code.length
        all_titles = " ".join(f.title for f in findings)
        assert "AA7702-002" == findings[0].check_id

    def test_negative_no_code_check(self):
        findings = detect_iscontract_bypass(_strip_comments(ISCONTRACT_NEGATIVE))
        assert len(findings) == 0

    def test_project_scan_suppresses_erc1271_signature_routing(self):
        src = """
pragma solidity ^0.8.0;
interface IERC1271 { function isValidSignature(bytes32, bytes calldata) external view returns (bytes4); }
library Address { function isContract(address a) internal view returns (bool) { return a.code.length > 0; } }
contract Wallet {
    bytes4 constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
    function _verifySig(address signer, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (Address.isContract(signer)) {
            return IERC1271(signer).isValidSignature(digest, sig) == EIP1271_MAGIC_VALUE;
        }
        return true;
    }
}
"""
        scanner = EIP7702Detector()
        findings, _ = scanner.scan_files({"Wallet.sol": src})
        assert not any(f.check_id == "AA7702-002" for _, f in findings)

    def test_project_scan_suppresses_contract_address_config_guard(self):
        src = """
pragma solidity ^0.8.0;
library Address { function isContract(address a) internal view returns (bool) { return a.code.length > 0; } }
contract AdminConfig {
    address public implementation;
    modifier onlyOwner(){_;}
    function setImplementation(address newImplementation) external onlyOwner {
        require(Address.isContract(newImplementation));
        implementation = newImplementation;
    }
}
"""
        scanner = EIP7702Detector()
        findings, _ = scanner.scan_files({"AdminConfig.sol": src})
        assert not any(f.check_id == "AA7702-002" for _, f in findings)

    def test_project_scan_suppresses_initializable_address_this_check(self):
        src = """
pragma solidity ^0.8.0;
library Address { function isContract(address a) internal view returns (bool) { return a.code.length > 0; } }
abstract contract Initializable {
    uint8 private _initialized;
    modifier initializer() {
        bool isTopLevelCall = true;
        require((isTopLevelCall && _initialized < 1) || (!Address.isContract(address(this)) && _initialized == 1));
        _;
    }
}
"""
        scanner = EIP7702Detector()
        findings, _ = scanner.scan_files({"Initializable.sol": src})
        assert not any(f.check_id == "AA7702-002" for _, f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-003: Callback reentrancy via delegated EOA
# ─────────────────────────────────────────────────────────────────────────────

CALLBACK_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdrawToEOA(address payable user) external {
        require(tx.origin == msg.sender, "EOA only");
        uint256 amt = balances[user];
        balances[user] = 0;
        user.transfer(amt);
    }
}
"""

CALLBACK_POSITIVE_OWNER = """
pragma solidity ^0.8.0;
contract Escrow {
    address payable public owner;
    function release() external {
        owner.transfer(address(this).balance);
    }
}
"""

CALLBACK_NEGATIVE_GUARDED = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SafeVault is ReentrancyGuard {
    function withdraw() external nonReentrant {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""


class TestCallbackReentrancy:
    def test_positive_eoa_guard(self):
        findings = detect_callback_reentrancy(_strip_comments(CALLBACK_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-003"
        assert findings[0].severity == "HIGH"

    def test_positive_owner_context(self):
        findings = detect_callback_reentrancy(_strip_comments(CALLBACK_POSITIVE_OWNER))
        assert len(findings) >= 1

    def test_negative_reentrancy_guard(self):
        findings = detect_callback_reentrancy(_strip_comments(CALLBACK_NEGATIVE_GUARDED))
        assert len(findings) == 0

    def test_project_scan_suppresses_oz_address_send_value_helper(self):
        src = """
pragma solidity ^0.8.0;
library Address {
    function sendValue(address payable recipient, uint256 amount) internal {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value");
    }
}
contract ProxyAdmin {}
"""
        scanner = EIP7702Detector()
        findings, _ = scanner.scan_files({"ProxyAdmin.sol": src})
        assert not any(f.check_id == "AA7702-003" for _, f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-004: Cross-chain delegation replay
# ─────────────────────────────────────────────────────────────────────────────

CROSS_CHAIN_POSITIVE = """
pragma solidity ^0.8.0;
contract DelegationManager {
    struct Authorization {
        uint256 chainId;
        address target;
        uint256 nonce;
    }
    function applyAuthorization(Authorization calldata auth) external {
        // accepts chainId = 0 without checking
        delegations[msg.sender] = auth.target;
    }
}
"""

CROSS_CHAIN_POSITIVE_ZERO = """
pragma solidity ^0.8.0;
contract EIP7702Handler {
    function setDelegation(address target) external {
        uint256 chainId = 0;
        // cross-chain by default
        _store(msg.sender, target, chainId);
    }
    function _store(address a, address t, uint256 c) internal {}
}
"""

CROSS_CHAIN_NEGATIVE = """
pragma solidity ^0.8.0;
contract SafeDelegation {
    function setDelegation(address target) external {
        require(block.chainid == 1, "mainnet only");
        delegations[msg.sender] = target;
    }
}
"""


class TestCrossChainReplay:
    def test_positive_no_chainid_check(self):
        findings = detect_cross_chain_replay(_strip_comments(CROSS_CHAIN_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-004"

    def test_positive_explicit_zero(self):
        findings = detect_cross_chain_replay(_strip_comments(CROSS_CHAIN_POSITIVE_ZERO))
        assert len(findings) >= 1
        assert any(f.check_id == "AA7702-004" for f in findings)

    def test_negative_chain_check(self):
        findings = detect_cross_chain_replay(_strip_comments(CROSS_CHAIN_NEGATIVE))
        assert len(findings) == 0

    def test_project_scan_suppresses_plain_proxy_delegatecall(self):
        src = """
pragma solidity ^0.8.0;
contract ProxyAdmin {
    function forward(address impl, bytes calldata data) external {
        (bool ok,) = impl.delegatecall(data);
        require(ok);
    }
}
"""
        scanner = EIP7702Detector()
        findings, _ = scanner.scan_files({"ProxyAdmin.sol": src})
        assert not any(f.check_id == "AA7702-004" for _, f in findings)

    def test_no_delegation_context(self):
        src = """
pragma solidity ^0.8.0;
contract Plain {
    uint256 chainId = 0;
    function foo() external {}
}
"""
        findings = detect_cross_chain_replay(_strip_comments(src))
        assert len(findings) == 0

    def test_unauthorized_error_is_not_authorization_context(self):
        src = """
pragma solidity ^0.8.0;
contract PlainAccessControl {
    error Unauthorized();
    function onlyOwner() external {
        revert Unauthorized();
    }
}
"""
        findings = detect_cross_chain_replay(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-005: Missing delegation revocation
# ─────────────────────────────────────────────────────────────────────────────

REVOCATION_POSITIVE = """
pragma solidity ^0.8.0;
contract WalletDelegation {
    mapping(address => address) public delegations;
    function setDelegation(address target) external {
        delegations[msg.sender] = target;
    }
    // no revoke function!
}
"""

REVOCATION_NEGATIVE = """
pragma solidity ^0.8.0;
contract SafeWallet {
    mapping(address => address) public delegations;
    function setDelegation(address target) external {
        delegations[msg.sender] = target;
    }
    function revokeDelegation() external {
        delete delegations[msg.sender];
    }
}
"""


class TestMissingRevocation:
    def test_positive_no_revoke(self):
        findings = detect_missing_revocation(_strip_comments(REVOCATION_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-005"

    def test_negative_has_revoke(self):
        findings = detect_missing_revocation(_strip_comments(REVOCATION_NEGATIVE))
        assert len(findings) == 0

    def test_no_delegation(self):
        src = """
pragma solidity ^0.8.0;
contract Plain { function foo() external {} }
"""
        findings = detect_missing_revocation(_strip_comments(src))
        assert len(findings) == 0

    def test_delegate_to_factory_is_not_7702_delegation_state(self):
        src = """
pragma solidity ^0.8.26;
contract Vault {
    address public vaultFactory;
    modifier onlyFactory() { require(msg.sender == vaultFactory); _; }
    function delegateToFactory(bytes calldata data) external onlyFactory returns (bytes memory) {
        return vaultFactory.delegatecall(data);
    }
}
"""
        findings = detect_missing_revocation(_strip_comments(src))
        assert len(findings) == 0

    def test_layerzero_set_delegate_is_not_7702_revocation_state(self):
        src = """
pragma solidity ^0.8.20;
interface IEndpoint { function setDelegate(address delegate) external; }
abstract contract OAppCore {
    IEndpoint public immutable endpoint;
    constructor(IEndpoint ep, address delegate) {
        endpoint = ep;
        endpoint.setDelegate(delegate);
    }
    function setDelegate(address delegate) public {
        endpoint.setDelegate(delegate);
    }
}
"""
        findings = detect_missing_revocation(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-006: delegatecall from delegation target
# ─────────────────────────────────────────────────────────────────────────────

DELEGATECALL_POSITIVE = """
pragma solidity ^0.8.0;
contract EIP7702DelegationTarget {
    function executeAs(address impl, bytes calldata data) external {
        (bool ok,) = impl.delegatecall(data);
        require(ok);
    }
}
"""

DELEGATECALL_NEGATIVE = """
pragma solidity ^0.8.0;
contract EIP7702DelegationTarget {
    function executeAs(address impl, bytes calldata data) external {
        (bool ok,) = impl.call(data);
        require(ok);
    }
}
"""

DELEGATECALL_NO_7702 = """
pragma solidity ^0.8.0;
contract Proxy {
    function execute(address impl, bytes calldata data) external {
        (bool ok,) = impl.delegatecall(data);
        require(ok);
    }
}
"""


class TestDelegatecallFromDelegation:
    def test_positive_delegatecall_in_target(self):
        findings = detect_delegatecall_from_delegation(
            _strip_comments(DELEGATECALL_POSITIVE)
        )
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-006"

    def test_negative_regular_call(self):
        findings = detect_delegatecall_from_delegation(
            _strip_comments(DELEGATECALL_NEGATIVE)
        )
        assert len(findings) == 0

    def test_negative_not_7702_context(self):
        findings = detect_delegatecall_from_delegation(
            _strip_comments(DELEGATECALL_NO_7702)
        )
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Integration: EIP7702Detector class
# ─────────────────────────────────────────────────────────────────────────────

FULL_VULNERABLE_CONTRACT = """
pragma solidity ^0.8.0;
contract VulnerableVault {
    mapping(address => uint256) public balances;
    mapping(address => address) public delegations;

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "no contracts");
        _;
    }

    function deposit() external payable onlyEOA {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(!msg.sender.isContract(), "EOA only");
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }

    function setDelegation(address target) external {
        delegations[msg.sender] = target;
    }
}
"""


class TestEIP7702DetectorIntegration:
    def test_is_affected(self, detector):
        assert detector.is_affected(FULL_VULNERABLE_CONTRACT) is True

    def test_not_affected(self, detector):
        clean = """
pragma solidity ^0.8.0;
contract Clean {
    function foo() external pure returns (uint256) { return 42; }
}
"""
        assert detector.is_affected(clean) is False

    def test_full_check_multiple_findings(self, detector):
        findings = detector.check(FULL_VULNERABLE_CONTRACT)
        check_ids = {f.check_id for f in findings}
        assert "AA7702-001" in check_ids, "Should detect tx.origin bypass"
        assert "AA7702-002" in check_ids, "Should detect isContract bypass"
        assert "AA7702-005" in check_ids, "Should detect missing revocation"

    def test_all_findings_have_required_fields(self, detector):
        findings = detector.check(FULL_VULNERABLE_CONTRACT)
        for f in findings:
            assert f.check_id.startswith("AA7702-")
            assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert f.cwe.startswith("CWE-")
            assert len(f.description) > 20
            assert len(f.recommendation) > 20
            assert 0 <= f.confidence <= 1.0
            assert f.eip7702_specific is True


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_source(self, detector):
        assert detector.check("") == []
        assert detector.is_affected("") is False

    def test_comments_stripped(self):
        src = """
/* tx.origin == msg.sender */
// require(tx.origin == msg.sender)
contract X {
    function y() external {}
}
"""
        findings = detect_tx_origin_eoa_bypass(_strip_comments(src))
        assert len(findings) == 0

    def test_dedup_same_function(self):
        src = """
contract X {
    function foo() external {
        require(tx.origin == msg.sender);
        require(tx.origin == msg.sender);
    }
}
"""
        findings = detect_tx_origin_eoa_bypass(_strip_comments(src))
        assert len(findings) == 1, "Should dedup per function"

    def test_multiple_functions(self):
        src = """
contract X {
    function foo() external {
        require(tx.origin == msg.sender);
    }
    function bar() external {
        require(tx.origin == msg.sender);
    }
}
"""
        findings = detect_tx_origin_eoa_bypass(_strip_comments(src))
        assert len(findings) == 2, "Separate functions = separate findings"


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-007: Storage collision in delegation target
# ─────────────────────────────────────────────────────────────────────────────

STORAGE_COLLISION_POSITIVE = """
pragma solidity ^0.8.0;
contract EIP7702DelegationTarget {
    address public owner;
    uint256 public balance;
    mapping(address => uint256) public nonces;

    function executeAs(address to, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = to.call(data);
        require(ok);
    }
}
"""

STORAGE_COLLISION_POSITIVE_NO_INIT = """
pragma solidity ^0.8.0;
contract AccountDelegation {
    address public admin;
    uint256 public threshold;
    address[] public guardians;

    function setAdmin(address a) external {
        require(msg.sender == admin);
        admin = a;
    }
}
"""

STORAGE_COLLISION_NEGATIVE = """
pragma solidity ^0.8.0;
contract PlainContract {
    address public owner;
    uint256 public balance;
    function foo() external {}
}
"""


class TestStorageCollision:
    def test_positive_owner_no_init(self):
        findings = detect_storage_collision(_strip_comments(STORAGE_COLLISION_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-007"
        assert findings[0].severity == "CRITICAL"

    def test_positive_admin_no_init(self):
        findings = detect_storage_collision(_strip_comments(STORAGE_COLLISION_POSITIVE_NO_INIT))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-007"

    def test_negative_not_delegation_target(self):
        findings = detect_storage_collision(_strip_comments(STORAGE_COLLISION_NEGATIVE))
        assert len(findings) == 0

    def test_negative_aave_on_behalf_parameter_is_not_7702_target(self):
        src = """
pragma solidity ^0.8.26;

interface IAave {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
}

contract AaveV3Connector {
    IAave public immutable aave;
    address public immutable rewardsController;
    address public immutable swapTarget;
    address public immutable provider;

    constructor(IAave _aave, address _rewardsController, address _swapTarget, address _provider) {
        aave = _aave;
        rewardsController = _rewardsController;
        swapTarget = _swapTarget;
        provider = _provider;
    }
}
"""
        findings = detect_storage_collision(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-008: Initialization race condition
# ─────────────────────────────────────────────────────────────────────────────

INIT_RACE_POSITIVE = """
pragma solidity ^0.8.0;
contract EIP7702DelegationTarget {
    address public owner;
    function initialize(address _owner) external {
        owner = _owner;
    }
    function executeAs(address to, bytes calldata data) external {
        require(msg.sender == owner);
        (bool ok,) = to.call(data);
        require(ok);
    }
}
"""

INIT_RACE_NEGATIVE = """
pragma solidity ^0.8.0;
contract AccountDelegation {
    address public owner;
    bool private _initialized;
    function initialize(address _owner) external {
        require(!_initialized, "already init");
        _initialized = true;
        owner = _owner;
    }
}
"""


class TestInitializationRace:
    def test_positive_no_guard(self):
        findings = detect_initialization_race(_strip_comments(INIT_RACE_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-008"
        assert findings[0].severity == "CRITICAL"

    def test_negative_has_guard(self):
        findings = detect_initialization_race(_strip_comments(INIT_RACE_NEGATIVE))
        assert len(findings) == 0

    def test_negative_not_delegation(self):
        src = """
pragma solidity ^0.8.0;
contract NormalProxy {
    function initialize(address x) external { }
}
"""
        findings = detect_initialization_race(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-009: Proxy + delegation conflict
# ─────────────────────────────────────────────────────────────────────────────

PROXY_CONFLICT_POSITIVE = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
contract EIP7702DelegationTarget is UUPSUpgradeable {
    function executeAs(address to, bytes calldata data) external {
        (bool ok,) = to.call(data);
        require(ok);
    }
    function upgradeToAndCall(address impl, bytes calldata d) external {
        _upgradeToAndCallUUPS(impl, d, true);
    }
}
"""

PROXY_CONFLICT_NEGATIVE = """
pragma solidity ^0.8.0;
contract AccountDelegation {
    function executeAs(address to, bytes calldata data) external {
        (bool ok,) = to.call(data);
        require(ok);
    }
}
"""


class TestProxyDelegationConflict:
    def test_positive_uups_delegation(self):
        findings = detect_proxy_delegation_conflict(_strip_comments(PROXY_CONFLICT_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-009"
        assert findings[0].severity == "CRITICAL"

    def test_negative_no_proxy(self):
        findings = detect_proxy_delegation_conflict(_strip_comments(PROXY_CONFLICT_NEGATIVE))
        assert len(findings) == 0

    def test_scan_suppresses_reverting_upgrade_override_without_proxy_entrypoint(self):
        src = """
pragma solidity ^0.8.26;
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

contract SemiModularAccount7702 is UUPSUpgradeable {
    error UpgradeNotAllowed();
    address internal fallbackSigner;

    function upgradeToAndCall(address, bytes calldata) public payable override {
        revert UpgradeNotAllowed();
    }

    function _retrieveFallbackSignerUnchecked() internal view returns (address) {
        return fallbackSigner;
    }
}
"""
        findings, _ = EIP7702Detector().scan_files({"SemiModularAccount7702.sol": src})
        assert "AA7702-009" not in {finding.check_id for _, finding in findings}

    def test_scan_suppresses_initializable_constructor_code_length_check(self):
        src = """
pragma solidity ^0.8.26;

abstract contract AccountStorageInitializable {
    struct AccountStorage {
        uint64 initialized;
        bool initializing;
    }

    function getAccountStorage() internal pure returns (AccountStorage storage $) {
        assembly { $.slot := 0 }
    }

    modifier initializer() {
        AccountStorage storage $ = getAccountStorage();
        bool isTopLevelCall = !$.initializing;
        uint64 initialized = $.initialized;
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;
        require(initialSetup || construction, "bad init");
        _;
    }
}
"""
        findings, _ = EIP7702Detector().scan_files({"AccountStorageInitializable.sol": src})
        assert "AA7702-002" not in {finding.check_id for _, finding in findings}

    def test_scan_suppresses_deterministic_clone_deploy_status_check(self):
        src = """
pragma solidity ^0.8.26;

library Clones {
    function predictDeterministicAddress(address, bytes32) internal pure returns (address) {
        return address(0x1234);
    }
    function cloneDeterministic(address, bytes32) internal pure returns (address) {
        return address(0x1234);
    }
}

contract FeeRecipientDeployer {
    function deployIfMissing(address implementation, bytes32 salt) external {
        address receiver = Clones.predictDeterministicAddress(implementation, salt);
        if (receiver.code.length == 0) {
            Clones.cloneDeterministic(implementation, salt);
        }
    }
}
"""
        findings, _ = EIP7702Detector().scan_files({"FeeRecipientDeployer.sol": src})
        assert "AA7702-002" not in {finding.check_id for _, finding in findings}

    def test_scan_suppresses_address_not_contract_config_check(self):
        src = """
pragma solidity ^0.8.26;

error AddressNotContract(address addr);

contract ConnectorRegistry {
    function add(bytes32 name, address connector) external {
        if (connector.code.length == 0) revert AddressNotContract(connector);
    }
}
"""
        findings, _ = EIP7702Detector().scan_files({"ConnectorRegistry.sol": src})
        assert "AA7702-002" not in {finding.check_id for _, finding in findings}

    def test_scan_suppresses_beacon_implementation_code_check(self):
        src = """
pragma solidity ^0.8.26;

error BeaconInvalidImplementation(address addr);

contract UpgradeableBeacon {
    address private _implementation;

    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) revert BeaconInvalidImplementation(newImplementation);
        _implementation = newImplementation;
    }
}
"""
        findings, _ = EIP7702Detector().scan_files({"UpgradeableBeacon.sol": src})
        assert "AA7702-002" not in {finding.check_id for _, finding in findings}

    def test_scan_keeps_eoa_only_code_length_gate(self):
        src = """
pragma solidity ^0.8.26;

contract Drop {
    function claim() external {
        require(msg.sender.code.length == 0, "EOA only");
    }
}
"""
        findings, _ = EIP7702Detector().scan_files({"Drop.sol": src})
        assert "AA7702-002" in {finding.check_id for _, finding in findings}


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-010: ERC-20 permit bypass
# ─────────────────────────────────────────────────────────────────────────────

PERMIT_POSITIVE = """
pragma solidity ^0.8.0;
contract Token {
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(...)");
    mapping(address => uint256) public nonces;

    function permit(
        address owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encodePacked(owner, spender, value, nonces[owner]++));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "invalid sig");
        _approve(owner, spender, value);
    }
    function _approve(address o, address s, uint256 v) internal {}
}
"""

PERMIT_NEGATIVE = """
pragma solidity ^0.8.0;
contract Token {
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}
"""


class TestPermitBypass:
    def test_positive_permit(self):
        findings = detect_permit_bypass(_strip_comments(PERMIT_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-010"
        assert findings[0].severity == "HIGH"

    def test_negative_no_permit(self):
        findings = detect_permit_bypass(_strip_comments(PERMIT_NEGATIVE))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-011: Batch authorization ordering
# ─────────────────────────────────────────────────────────────────────────────

BATCH_AUTH_POSITIVE = """
pragma solidity ^0.8.0;
contract DelegationManager {
    struct Authorization { address target; uint256 nonce; }
    function processAuthorizationList(Authorization[] calldata authorizations) external {
        for (uint i = 0; i < authorizations.length; i++) {
            _apply(authorizations[i]);
        }
    }
    function _apply(Authorization calldata a) internal {}
}
"""

BATCH_AUTH_NEGATIVE = """
pragma solidity ^0.8.0;
contract PlainContract {
    function foo() external {}
}
"""


class TestBatchAuthOrdering:
    def test_positive_no_nonce_check(self):
        findings = detect_batch_auth_ordering(_strip_comments(BATCH_AUTH_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-011"

    def test_negative_no_batch(self):
        findings = detect_batch_auth_ordering(_strip_comments(BATCH_AUTH_NEGATIVE))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-012: Nonce gap exploitation
# ─────────────────────────────────────────────────────────────────────────────

NONCE_GAP_META_TX = """
pragma solidity ^0.8.0;
contract MetaTxForwarder {
    mapping(address => uint256) public _nonces;
    function executeMetaTransaction(
        address from, bytes calldata data, uint256 nonce,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(nonce == _nonces[from], "bad nonce");
        _nonces[from]++;
    }
}
"""

NONCE_GAP_PERMIT = """
pragma solidity ^0.8.0;
contract Token {
    bytes32 public PERMIT_TYPEHASH;
    mapping(address => uint256) public nonces;
    function permit(address owner, address spender, uint256 val, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(nonces[owner] == getNonce(owner));
    }
    function getNonce(address a) public view returns (uint256) { return nonces[a]; }
}
"""

NONCE_GAP_NEGATIVE = """
pragma solidity ^0.8.0;
contract Plain {
    function foo() external {}
}
"""


class TestNonceGap:
    def test_positive_meta_tx(self):
        findings = detect_nonce_gap(_strip_comments(NONCE_GAP_META_TX))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-012"

    def test_positive_permit_nonce(self):
        findings = detect_nonce_gap(_strip_comments(NONCE_GAP_PERMIT))
        assert len(findings) >= 1
        assert any(f.check_id == "AA7702-012" for f in findings)

    def test_negative_no_nonce(self):
        findings = detect_nonce_gap(_strip_comments(NONCE_GAP_NEGATIVE))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-013: Gas sponsorship griefing
# ─────────────────────────────────────────────────────────────────────────────

GAS_GRIEFING_POSITIVE = """
pragma solidity ^0.8.0;
contract Paymaster {
    function sponsorGas(address account, bytes calldata data) external {
        (bool ok,) = account.call(data);
        require(ok);
    }
}
"""

GAS_GRIEFING_NEGATIVE = """
pragma solidity ^0.8.0;
contract SafePaymaster {
    function sponsorGas(address account, bytes calldata data) external {
        uint256 gasLimit = gasleft() / 2;
        (bool ok,) = account.call{gas: gasLimit}(data);
        require(ok);
    }
}
"""


class TestGasGriefing:
    def test_positive_no_gas_limit(self):
        findings = detect_gas_griefing(_strip_comments(GAS_GRIEFING_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-013"

    def test_negative_has_gas_limit(self):
        findings = detect_gas_griefing(_strip_comments(GAS_GRIEFING_NEGATIVE))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-014: Value transfer confusion
# ─────────────────────────────────────────────────────────────────────────────

VALUE_TRANSFER_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}
"""

VALUE_TRANSFER_NEGATIVE_CEI = """
pragma solidity ^0.8.0;
contract SafeVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

VALUE_TRANSFER_NEGATIVE_GUARD = """
pragma solidity ^0.8.0;
contract GuardedVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external nonReentrant {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}
"""


class TestValueTransferConfusion:
    def test_positive_state_after_transfer(self):
        findings = detect_value_transfer_confusion(_strip_comments(VALUE_TRANSFER_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-014"
        assert findings[0].severity == "HIGH"

    def test_negative_cei_order(self):
        findings = detect_value_transfer_confusion(_strip_comments(VALUE_TRANSFER_NEGATIVE_CEI))
        assert len(findings) == 0

    def test_negative_reentrancy_guard(self):
        findings = detect_value_transfer_confusion(_strip_comments(VALUE_TRANSFER_NEGATIVE_GUARD))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-015: selfdestruct in delegation target
# ─────────────────────────────────────────────────────────────────────────────

SELFDESTRUCT_POSITIVE = """
pragma solidity ^0.8.0;
contract EIP7702DelegationTarget {
    address public owner;
    function emergencyDestroy() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }
}
"""

SELFDESTRUCT_NEGATIVE = """
pragma solidity ^0.8.0;
contract AccountDelegation {
    function execute(address to, bytes calldata data) external {
        (bool ok,) = to.call(data);
        require(ok);
    }
}
"""


class TestSelfdestructDelegation:
    def test_positive_selfdestruct_in_target(self):
        findings = detect_selfdestruct_delegation(_strip_comments(SELFDESTRUCT_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-015"
        assert findings[0].severity == "CRITICAL"

    def test_negative_no_selfdestruct(self):
        findings = detect_selfdestruct_delegation(_strip_comments(SELFDESTRUCT_NEGATIVE))
        assert len(findings) == 0

    def test_negative_not_delegation_context(self):
        src = """
pragma solidity ^0.8.0;
contract NormalContract {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
"""
        findings = detect_selfdestruct_delegation(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-016: ecrecover without EIP-1271
# ─────────────────────────────────────────────────────────────────────────────

ECRECOVER_POSITIVE = """
pragma solidity ^0.8.0;
contract SigVerifier {
    function verifySignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}
"""

ECRECOVER_NEGATIVE_1271 = """
pragma solidity ^0.8.0;
contract SmartSigVerifier {
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s, address signer) public view returns (bool) {
        address recovered = ecrecover(hash, v, r, s);
        if (recovered == signer) return true;
        (bool ok, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(0x1626ba7e, hash, abi.encodePacked(r, s, v))
        );
        return ok && abi.decode(result, (bytes4)) == 0x1626ba7e;
    }
}
"""


class TestEcrecoverDelegation:
    def test_positive_no_eip1271(self):
        findings = detect_ecrecover_delegation(_strip_comments(ECRECOVER_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-016"

    def test_negative_has_1271(self):
        findings = detect_ecrecover_delegation(_strip_comments(ECRECOVER_NEGATIVE_1271))
        assert len(findings) == 0

    def test_negative_trusted_aml_signer_not_user_account_signature(self):
        src = """
pragma solidity ^0.8.26;
contract Depositor {
    address public amlSigner;
    function _verifyAML(bytes32 messageHash, bytes calldata signature) private {
        address recoveredSigner = ECDSA.recover(messageHash, signature);
        if (recoveredSigner != amlSigner) revert InvalidAmlSigner();
    }
}
"""
        findings = detect_ecrecover_delegation(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-017: ERC-777 hooks + delegation
# ─────────────────────────────────────────────────────────────────────────────

ERC777_POSITIVE = """
pragma solidity ^0.8.0;
contract MyToken {
    function _callTokensReceived(address from, address to, uint256 amount) internal {
        if (to.code.length > 0) {
            IERC777Recipient(to).tokensReceived(msg.sender, from, to, amount, "", "");
        }
    }
}
"""

ERC777_NEGATIVE = """
pragma solidity ^0.8.0;
contract PlainToken {
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}
"""


class TestERC777Delegation:
    def test_positive_hook_skips_eoa(self):
        findings = detect_erc777_delegation(_strip_comments(ERC777_POSITIVE))
        assert len(findings) >= 1
        assert any(f.check_id == "AA7702-017" for f in findings)

    def test_negative_no_erc777(self):
        findings = detect_erc777_delegation(_strip_comments(ERC777_NEGATIVE))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-018: Approval front-running
# ─────────────────────────────────────────────────────────────────────────────

APPROVAL_POSITIVE = """
pragma solidity ^0.8.0;
contract Token {
    mapping(address => mapping(address => uint256)) public allowance;
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
"""

APPROVAL_NEGATIVE = """
pragma solidity ^0.8.0;
contract SafeToken {
    mapping(address => mapping(address => uint256)) public allowance;
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function increaseAllowance(address spender, uint256 add) external returns (bool) {
        allowance[msg.sender][spender] += add;
        return true;
    }
}
"""


class TestApprovalFrontrun:
    def test_positive_no_increase_allowance(self):
        findings = detect_approval_frontrun(_strip_comments(APPROVAL_POSITIVE))
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-018"

    def test_negative_has_increase_allowance(self):
        findings = detect_approval_frontrun(_strip_comments(APPROVAL_NEGATIVE))
        assert len(findings) == 0

    def test_negative_plain_super_approve_override(self):
        src = """
pragma solidity ^0.8.26;
contract Vault is ERC20Upgradeable {
    function approve(address spender, uint256 value)
        public
        override
        returns (bool)
    {
        return super.approve(spender, value);
    }
}
"""
        findings = detect_approval_frontrun(_strip_comments(src))
        assert len(findings) == 0

    def test_negative_approve_lib_wrapper_call(self):
        src = """
pragma solidity ^0.8.26;
library ApproveLib { function approve(address token, address spender, uint256 amount) internal {} }
contract Controller {
    function deposit(address token, address spender, uint256 amount) external {
        ApproveLib.approve(token, spender, amount);
    }
}
"""
        findings = detect_approval_frontrun(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Integration: 21-check detector
# ─────────────────────────────────────────────────────────────────────────────

class TestEIP7702Full21:
    def test_check_count(self, detector):
        assert len(detector._ALL_CHECKS) == 21

    def test_selective_check(self, detector):
        src = _strip_comments(TX_ORIGIN_POSITIVE)
        all_findings = detector.check(src)
        sel_findings = detector.check_selective(src, ["AA7702-001"])
        assert len(sel_findings) <= len(all_findings)
        assert all(f.check_id == "AA7702-001" for f in sel_findings)

    def test_selective_none_runs_all(self, detector):
        f1 = detector.check(FULL_VULNERABLE_CONTRACT)
        f2 = detector.check_selective(FULL_VULNERABLE_CONTRACT, None)
        assert len(f1) == len(f2)

    def test_combined_contract_hits_multiple(self, detector):
        """A contract with many EIP-7702-relevant patterns should trigger multiple checks."""
        combined = """
pragma solidity ^0.8.0;
contract EIP7702DelegationTarget {
    address public owner;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    bytes32 public PERMIT_TYPEHASH;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function permit(address o, address s, uint256 v, uint256 d, uint8 v8, bytes32 r, bytes32 ss) external {
        address signer = ecrecover(keccak256(""), v8, r, ss);
        require(signer == o);
        require(nonces[o] == 0);
    }

    function executeAs(address to, bytes calldata data) external {
        require(msg.sender == owner);
        (bool ok,) = to.delegatecall(data);
        require(ok);
    }

    function emergencyDestroy() external {
        selfdestruct(payable(owner));
    }
}
"""
        findings = detector.check(combined)
        check_ids = {f.check_id for f in findings}
        assert len(check_ids) >= 3, f"Expected 3+ unique check IDs, got {check_ids}"


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-019: Hardcoded single relayer
# ─────────────────────────────────────────────────────────────────────────────

RELAYER_POSITIVE = """
pragma solidity ^0.8.0;
contract SmartAccount {
    address public RELAYER = 0x1234567890AbcdEF1234567890aBcdef12345678;
    function execute(bytes calldata data) external {
        require(msg.sender == RELAYER, "only relayer");
        (bool ok,) = address(this).call(data);
        require(ok);
    }
}
"""

RELAYER_NEGATIVE_MAPPING = """
pragma solidity ^0.8.0;
contract SmartAccount {
    mapping(address => bool) public allowedRelayers;
    function execute(bytes calldata data) external {
        require(allowedRelayers[msg.sender], "not allowed");
        (bool ok,) = address(this).call(data);
        require(ok);
    }
}
"""

RELAYER_NEGATIVE_NO_RELAYER = """
pragma solidity ^0.8.0;
contract Token {
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}
"""


class TestAA7702_019:
    def test_positive_single_relayer(self):
        findings = detect_hardcoded_relayer(RELAYER_POSITIVE)
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-019"

    def test_negative_relayer_mapping(self):
        findings = detect_hardcoded_relayer(RELAYER_NEGATIVE_MAPPING)
        assert len(findings) == 0

    def test_negative_no_relayer(self):
        findings = detect_hardcoded_relayer(RELAYER_NEGATIVE_NO_RELAYER)
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-020: Missing ERC-7201 storage namespace
# ─────────────────────────────────────────────────────────────────────────────

NAMESPACE_POSITIVE = """
pragma solidity ^0.8.0;
contract DelegationTarget {
    address public owner;
    uint256 public nonce;

    function execute(address to, bytes calldata data) external {
        require(msg.sender == owner);
        (bool ok,) = to.call(data);
        require(ok);
        nonce++;
    }
}
"""

NAMESPACE_NEGATIVE_ERC7201 = """
pragma solidity ^0.8.0;
contract DelegationTarget {
    bytes32 private constant STORAGE_LOCATION =
        keccak256("eip7201:delegation.storage.MyAccount");

    struct AccountStorage {
        address owner;
        uint256 nonce;
    }

    function _getStorage() private pure returns (AccountStorage storage s) {
        bytes32 slot = STORAGE_LOCATION;
        assembly { s.slot := slot }
    }
}
"""

NAMESPACE_NEGATIVE_NOT_DELEGATION = """
pragma solidity ^0.8.0;
contract Token {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
}
"""


class TestAA7702_020:
    def test_positive_raw_storage(self):
        findings = detect_missing_storage_namespace(NAMESPACE_POSITIVE)
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-020"

    def test_negative_erc7201(self):
        findings = detect_missing_storage_namespace(NAMESPACE_NEGATIVE_ERC7201)
        assert len(findings) == 0

    def test_negative_not_delegation(self):
        findings = detect_missing_storage_namespace(NAMESPACE_NEGATIVE_NOT_DELEGATION)
        assert len(findings) == 0

    def test_negative_staking_delegation_is_not_7702_target(self):
        src = """
pragma solidity ^0.8.20;
contract Staking {
    address[] public bondedValAddrs;
    event DelegationUpdate(address indexed validator, address indexed delegator, uint256 amount);
    function delegate(address validator, uint256 amount) external {
        bondedValAddrs.push(validator);
        emit DelegationUpdate(validator, msg.sender, amount);
    }
}
"""
        findings = detect_missing_storage_namespace(_strip_comments(src))
        assert len(findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-021: EntryPoint version mismatch
# ─────────────────────────────────────────────────────────────────────────────

ENTRYPOINT_POSITIVE = """
pragma solidity ^0.8.0;
contract SmartAccount {
    address constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    function validateUserOp(bytes calldata userOp) external {
        require(msg.sender == ENTRY_POINT);
    }
}
"""

ENTRYPOINT_NEGATIVE_CONFIGURABLE = """
pragma solidity ^0.8.0;
contract SmartAccount {
    address public entryPoint;

    constructor(IEntryPoint _ep) {
        entryPoint = address(_ep);
    }

    function validateUserOp(bytes calldata userOp) external {
        require(msg.sender == entryPoint);
    }
}
"""

ENTRYPOINT_NEGATIVE_NO_EP = """
pragma solidity ^0.8.0;
contract Token {
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}
"""


class TestAA7702_021:
    def test_positive_hardcoded_v06(self):
        findings = detect_entrypoint_mismatch(ENTRYPOINT_POSITIVE)
        assert len(findings) >= 1
        assert findings[0].check_id == "AA7702-021"

    def test_negative_configurable(self):
        findings = detect_entrypoint_mismatch(ENTRYPOINT_NEGATIVE_CONFIGURABLE)
        assert len(findings) == 0

    def test_negative_no_entrypoint(self):
        findings = detect_entrypoint_mismatch(ENTRYPOINT_NEGATIVE_NO_EP)
        assert len(findings) == 0
