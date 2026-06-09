// SPDX-License-Identifier: MIT
// Real-world anti-pattern: unguarded public function using tx.origin as an
// EOA-only check. Common pre-Pectra style; broken under EIP-7702.
pragma solidity ^0.8.20;

contract FlashLoanGuard {
    function takeLoan(uint256 amount) external {
        require(tx.origin == msg.sender, "no flashloan");
        // ... transfer logic
    }
}
