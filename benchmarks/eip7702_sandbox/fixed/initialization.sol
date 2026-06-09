// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract InitFixed {
    address public admin; bool private _initialized;
    modifier initializer() { require(!_initialized); _initialized = true; _; }
    function initialize(address _admin) external initializer { admin = _admin; }
}