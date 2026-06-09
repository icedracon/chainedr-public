// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal, self-contained ERC-20 asset.
contract MockAsset {
    string public name = "Mock";
    string public symbol = "MCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 a) external { balanceOf[to] += a; totalSupply += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[to] += a; return true;
    }
}

// Minimal ERC-4626-shaped vault with a DELIBERATE bug: convertToAssets rounds UP
// (ceil), so a deposit->redeem round-trip returns MORE assets than deposited —
// value is created from nothing. A correct vault rounds assets-out DOWN.
// The invariant engine is NOT told about this; the round-trip invariant should break.
contract BuggyVault {
    MockAsset public assetToken;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor() { assetToken = new MockAsset(); }

    function asset() external view returns (address) { return address(assetToken); }
    function totalAssets() public view returns (uint256) { return assetToken.balanceOf(address(this)); }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();           // floor (ok)
    }
    // BUG: returns 1 wei MORE than fair per redemption -> round-trip yields more
    // than deposited (value minted from nothing). Detectable on a single deposit.
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return shares;
        return (shares * totalAssets()) / supply + 1;            // +1 inflation (bug)
    }
    function previewDeposit(uint256 a) external view returns (uint256) { return convertToShares(a); }
    function maxDeposit(address) external pure returns (uint256) { return type(uint256).max; }
    function maxWithdraw(address o) external view returns (uint256) { return convertToAssets(balanceOf[o]); }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        assetToken.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares; balanceOf[receiver] += shares;
    }
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[owner] -= shares; totalSupply -= shares;
        assetToken.transfer(receiver, assets);
    }
}
