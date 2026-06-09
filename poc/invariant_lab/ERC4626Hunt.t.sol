// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

interface IERC4626 {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
    function deposit(uint256, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
    function maxDeposit(address) external view returns (uint256);
}

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function decimals() external view returns (uint8);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

// Generic ERC-4626 invariant hunt on a mainnet fork. VAULT from env.
// A failing assertion = a candidate bug; the test itself is the PoC.
contract ERC4626Hunt is Test {
    IERC4626 v;
    address asset;
    address user = address(0xA11CE);

    function setUp() public {
        v = IERC4626(vm.envAddress("VAULT"));
        asset = v.asset();
    }

    function _amt() internal view returns (uint256) {
        uint8 dec = 18;
        try IERC20(asset).decimals() returns (uint8 d) { dec = d; } catch {}
        uint256 a = 1000 * (10 ** dec);
        uint256 m = v.maxDeposit(user);
        return a > m ? m : a;
    }

    // INV-1: deposit X then immediately redeem all shares -> must get back <= X.
    // A break = value extracted from nothing (inflation / rounding-in-user-favor).
    function test_roundTrip() public {
        uint256 amt = _amt();
        if (amt == 0) return; // deposits closed
        deal(asset, user, amt);
        vm.startPrank(user);
        IERC20(asset).approve(address(v), amt);
        uint256 shares = v.deposit(amt, user);
        // Skip vaults with async/queued/cooldown redemption - an immediate redeem
        // reverting is by-design there, not an inflation bug.
        try v.redeem(shares, user, user) returns (uint256 out) {
            vm.stopPrank();
            emit log_named_uint("deposited", amt);
            emit log_named_uint("redeemed ", out);
            assertLe(out, amt, "ROUND-TRIP INFLATION: redeemed more than deposited");
        } catch {
            vm.stopPrank();
            emit log("round-trip skipped: redeem not immediate (async/cooldown vault)");
        }
    }

    // INV-2 (solvency) REMOVED: convertToAssets(totalSupply) <= totalAssets is a
    // false-positive generator on real vaults — it breaks on benign rounding (±1 wei)
    // and on non-standard accounting (totalAssets reporting only idle funds while
    // shares are backed by deployed strategy capital / oracle-priced positions).
    // A correct solvency invariant needs per-vault accounting awareness; the naive
    // pro-rata form is unsound and is intentionally not used.

    // INV-3: deposit fairness - after depositing X, the shares received must be
    // worth <= X. Catches deposit-side share inflation WITHOUT needing redeem
    // (robust to queued/async-redemption vaults like sUSDai). A break = a depositor
    // instantly gains value = bug.
    function test_depositFairness() public {
        uint256 amt = _amt();
        if (amt == 0) return;
        deal(asset, user, amt);
        vm.startPrank(user);
        IERC20(asset).approve(address(v), amt);
        uint256 shares = v.deposit(amt, user);
        vm.stopPrank();
        uint256 worth = v.convertToAssets(shares);
        emit log_named_uint("deposited", amt);
        emit log_named_uint("shares_worth", worth);
        assertLe(worth, amt, "DEPOSIT INFLATION: shares received worth more than deposited");
    }

    // INV-4: first-depositor / donation inflation. Only meaningful on an EMPTY vault
    // (fresh deploys). Attacker mints 1 share, donates a large amount to spike the
    // share price, then a victim deposits - a vault without virtual-share protection
    // rounds the victim's shares toward 0, stealing most of their deposit.
    function test_donationInflation() public {
        if (v.totalSupply() != 0) return; // only fresh/empty vaults are attackable
        address attacker = address(0xBAD);
        uint256 victimDep = _amt();
        if (victimDep == 0) return;
        uint256 donation = victimDep * 10; // large relative to victim deposit

        deal(asset, attacker, 1 + donation);
        vm.startPrank(attacker);
        IERC20(asset).approve(address(v), type(uint256).max);
        try v.deposit(1, attacker) returns (uint256) {
            IERC20(asset).transfer(address(v), donation); // inflate price
        } catch { vm.stopPrank(); return; } // min-deposit guard -> not vulnerable here
        vm.stopPrank();

        deal(asset, user, victimDep);
        vm.startPrank(user);
        IERC20(asset).approve(address(v), victimDep);
        uint256 vshares = v.deposit(victimDep, user);
        vm.stopPrank();
        uint256 worth = v.convertToAssets(vshares);
        emit log_named_uint("victim_deposit", victimDep);
        emit log_named_uint("victim_shares_worth", worth);
        // victim must keep most of their value; losing >50% = inflation griefing
        assertGe(worth, victimDep / 2,
            "DONATION INFLATION: first-depositor griefing - victim lost most of deposit");
    }
}
