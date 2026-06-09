// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Test contract with KNOWN bugs for ChainEDR validation
contract VulnerableVault is Ownable2Step {
    using PayoutLib for PayoutPool;

    mapping(uint256 => PayoutPool) public payoutPool;
    mapping(address => bool) public isManager;
    uint256 public currentPayoutId;
    uint256 public totalReserved;

    // BUG 1: Loop with external calls, no try/catch
    function batchClaim(ClaimParams[] memory claims) external {
        for (uint256 i = 0; i < claims.length; i++) {
            if (!IFactory(factory).isVault(claims[i].vault)) revert InvalidVault();
            IVault(claims[i].vault).claimPayout(claims[i].id, claims[i].proof);
        }
    }

    // BUG 2: Missing bounds check (cancelPayout has it, this doesn't)
    function cancelPayout(uint256 payoutId) external onlyOwner {
        if (payoutId >= currentPayoutId) revert PayoutIdInvalid();
        payoutPool[payoutId].canceled = true;
        totalReserved -= payoutPool[payoutId].amount;
    }

    function claimPayout(uint256 payoutId, bytes32[] calldata proof) external {
        if (payoutPool[payoutId].canceled) revert PayoutCanceled();
        totalReserved -= payoutPool[payoutId].amount;
    }

    // SAFE: admin function (should be INFO, not CRITICAL)
    function setManager(address mgr, bool status) external onlyOwner {
        isManager[mgr] = status;
    }

    // SAFE: has nonReentrant
    function withdraw(uint256 amount) external nonReentrant {
        IToken(token).transfer(msg.sender, amount);
        totalReserved -= amount;
    }

    // BUG 3: ETH refund without checking return value
    function refundExcess() external {
        uint256 excess = msg.value - requiredFee;
        payable(msg.sender).call{value: excess}("");
    }
}
