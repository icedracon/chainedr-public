// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: ERC-777 hook exploitation on delegated EOA
/// @notice AA7702-017 — call_boundary bypass
interface IERC777 {
    function send(address to, uint256 amount, bytes calldata data) external;
}

contract ERC777DelegatedReceiver {
    mapping(address => uint256) public balances;
    IERC777 public token;

    constructor(address _token) { token = IERC777(_token); }

    function distribute(address[] calldata recipients, uint256 amount) external {
        for (uint i = 0; i < recipients.length; i++) {
            if (recipients[i].code.length == 0) continue;
            _callTokensReceived(recipients[i], amount);
            token.send(recipients[i], amount, "");
            balances[recipients[i]] += amount;
        }
    }

    function _callTokensReceived(address to, uint256 amount) internal {
        (bool ok,) = to.call(
            abi.encodeWithSignature("tokensReceived(address,uint256)", address(this), amount)
        );
    }
}
