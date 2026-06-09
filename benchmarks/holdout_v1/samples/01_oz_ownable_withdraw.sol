// SPDX-License-Identifier: MIT
// Modelled after OpenZeppelin Ownable usage. Clean pattern: onlyOwner
// modifier gates the privileged action. tx.origin / msg.sender comparison
// is irrelevant because the role check already restricts callers.
pragma solidity ^0.8.20;

contract OwnableWithdraw {
    address private _owner;

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    constructor() {
        _owner = msg.sender;
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner {
        // Defence-in-depth check; not the primary auth boundary.
        require(tx.origin == msg.sender, "not eoa");
        to.transfer(amount);
    }
}
