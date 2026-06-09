// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Benign vault with CEI and reentrancy guard
contract SimpleVault {
    mapping(address => uint256) public deposits;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked);
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
