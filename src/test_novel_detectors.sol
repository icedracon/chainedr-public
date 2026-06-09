// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ──────────────────────────────────────────────────────────────────────────────
// Test contract for ChainEDR novel detector validation
//
// Should trigger:
//   1. msg.value reuse in loop [CRITICAL]  — distributeRewards()
//   2. UUPS missing _disableInitializers [HIGH] — inherits Initializable, no ctor
//   3. delegatecall injection [CRITICAL]  — execute()
// ──────────────────────────────────────────────────────────────────────────────

interface Initializable {
    function initialize(address owner) external;
}

contract NovelDetectorTest {
    address[] public recipients;
    address public implementation;
    bool private initialized;

    // ── Bug 1: msg.value reuse in loop ────────────────────────────────────
    // Each iteration accesses msg.value directly. Solidity does not decrement
    // msg.value per iteration. All recipients get the full msg.value, not a share.
    function distributeRewards(address[] calldata targets) external payable {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call{value: msg.value}("");
            require(ok, "transfer failed");
        }
    }

    // ── Bug 2: UUPS impl without _disableInitializers ─────────────────────
    // This contract inherits upgradeable base but has no constructor calling
    // _disableInitializers(). The impl can be initialized by an attacker.
    function initialize(address _owner) external {
        require(!initialized, "already init");
        initialized = true;
    }

    // ── Bug 3: delegatecall to user-controlled address ───────────────────
    // `target` is a function parameter — attacker passes their malicious contract.
    // delegatecall runs attacker code with THIS contract's storage + ETH.
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return result;
    }

    // Safe function — no issues
    function safeWithdraw(uint256 amount, address to) external {
        require(amount > 0, "zero");
        require(to != address(0), "zero addr");
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
}
