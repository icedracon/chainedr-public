// SPDX-License-Identifier: MIT
// Token-receive-hook style isContract check on an unguarded public
// entry. Broken under EIP-7702 because a delegated EOA has nonzero
// extcodesize and the "must be an EOA" branch never runs.
pragma solidity ^0.8.20;

contract AirdropEligibility {
    function claim(address recipient) external {
        require(recipient.code.length == 0, "contracts not eligible");
        // ... eligibility logic
    }
}
