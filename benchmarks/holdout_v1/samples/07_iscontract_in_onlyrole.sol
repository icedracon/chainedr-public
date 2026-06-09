// SPDX-License-Identifier: MIT
// AccessControl-style role-gated function performing a code.length
// check on a known target. Modifier-aware suppression must keep
// AA7702-002 silent here.
pragma solidity ^0.8.20;

abstract contract AccessControl {
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "missing role");
        _;
    }
    function hasRole(bytes32, address) public view virtual returns (bool);
}

contract Vault is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");

    mapping(address => bool) private _admins;
    function hasRole(bytes32, address a) public view override returns (bool) {
        return _admins[a];
    }

    function isContractTarget(address target) external view onlyRole(ADMIN_ROLE) returns (bool) {
        return target.code.length > 0;
    }
}
