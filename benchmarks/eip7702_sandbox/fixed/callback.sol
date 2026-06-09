// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CallbackFixed {
    bool private _status;
    mapping(address => uint) public balances;
    function withdraw() external {
        require(_status == 0);
        _status = 1;
        uint bal = balances[msg.sender];
        require(bal > 0);
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(bal);
        _status = 0;
    }
}