// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
contract IsContractCheck {
    function isEOA(address addr) public view returns (bool) {
        uint codesize;
        assembly { codesize := extcodesize(addr) }
        return codesize == 0;
    }
    function onlyEOA() external view {
        require(isEOA(msg.sender), "not eoa");
    }
}