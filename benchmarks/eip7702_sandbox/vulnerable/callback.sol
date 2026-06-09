// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CallbackVuln {
    mapping(address => uint) public balances;
    function withdraw() external {
        uint bal = balances[msg.sender];
        require(bal > 0);
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok);
    }
}