// SPDX-License-Identifier: MIT
// ETH send to a user-supplied recipient with no guard but an explicit
// "must be EOA" check. Post-7702 the EOA assumption is broken and the
// recipient can re-enter via its delegated code. AA7702-003 should fire.
pragma solidity ^0.8.20;

contract NaivePayout {
    function payRefund(address payable recipient, uint256 amount) external {
        require(recipient.code.length == 0, "no contracts");
        recipient.transfer(amount);
    }
}
