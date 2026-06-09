// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract TxOriginFixed {
    bool private _locked;
    modifier nonReentrant() {
        require(!_locked); _locked = true; _; _locked = false;
    }
    function humanOnly() external nonReentrant {}
}