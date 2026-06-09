// SPDX-License-Identifier: MIT
// Pure utility library with no auth and no 7702-relevant patterns.
// Nothing should fire.
pragma solidity ^0.8.20;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        unchecked {
            c = a + b;
            require(c >= a, "overflow");
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "underflow");
        return a - b;
    }
}
