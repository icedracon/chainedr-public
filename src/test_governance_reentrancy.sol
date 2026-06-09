// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Test contract for governance attack + cross-contract reentrancy detectors.
//
// Should trigger:
//   1. Governance: no timelock on setRouter()          [HIGH]
//   2. Governance: no timelock on setTreasury()        [HIGH]
//   3. Cross-contract reentrancy: deposit() + onERC721Received()  [HIGH]

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// ── Bug 1 & 2: Admin setters without timelock ──────────────────────────────
contract VaultNoTimelock {
    address public owner;
    address public router;
    address public treasury;
    IERC20  public token;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor(address _token) {
        owner   = msg.sender;
        token   = IERC20(_token);
    }

    // Bug 1: no timelock — owner can instantly swap router to drain contract
    function setRouter(address _router) external onlyOwner {
        router = _router;
    }

    // Bug 2: no timelock — owner can redirect all fees instantly
    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0));
        treasury = _treasury;
    }

    // ── Bug 3: cross-contract reentrancy via ERC721 safeTransfer ─────────
    // deposit() makes external call (transferFrom) BEFORE updating balances.
    // Contract also implements onERC721Received — which could re-enter during
    // a safeTransfer callback.
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);  // external call first
        balances[msg.sender] += amount;                          // state update after
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    // ERC721 receiver hook — re-entrant path exists:
    // attacker calls deposit() → transferFrom triggers onERC721Received
    // on attacker's contract → which calls back into deposit() with stale balance
    function onERC721Received(
        address, address from, uint256, bytes calldata
    ) external returns (bytes4) {
        // Hook: could re-enter deposit() or read stale balances[]
        return this.onERC721Received.selector;
    }

    // Safe function — no issues
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
}
