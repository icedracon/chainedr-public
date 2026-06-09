// SPDX-License-Identifier: MIT
// Pure interface — no implementation, cannot hold a runtime vuln.
// _is_interface_file must keep every detector silent. Nothing fires.
pragma solidity ^0.8.20;

interface IDelegationTarget {
    function execute(address impl, bytes calldata data) external;
    function authorize(address target, uint8 v, bytes32 r, bytes32 s) external;
}
