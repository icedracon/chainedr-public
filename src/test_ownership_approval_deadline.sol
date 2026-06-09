// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IUniswapV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params)
        external returns (uint256 amountOut);
}

// ── Bug 1: Single-step ownership transfer ────────────────────────────────────
// Inherits OZ Ownable (not Ownable2Step). No pendingOwner / acceptOwnership.
abstract contract Ownable {
    address public owner;
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;   // takes effect immediately — no two-step
    }
}

contract DeFiProtocol is Ownable {
    address public treasury;
    IERC20 public token;
    IUniswapV2Router public router;

    constructor(address _token, address _router) {
        owner = msg.sender;
        token = IERC20(_token);
        router = IUniswapV2Router(_router);
    }

    // ── Bug 2a: approve without reset (USDT griefing) ───────────────────
    // If token is USDT and allowance is already non-zero, this REVERTS.
    function depositAndApprove(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        token.approve(address(router), amount);   // no prior approve(0)
    }

    // ── Bug 2b: safeApprove deprecated ──────────────────────────────────
    // safeApprove has the same USDT non-zero allowance revert bug.
    // (Separate function to show the deprecated pattern)
    function reApproveViaLegacy(address spender, uint256 amount) external {
        // safeApprove(spender, amount);  — would be caught if present
        token.approve(spender, amount);   // same pattern: no reset
    }

    // ── Bug 3a: Uniswap V2 with deadline = block.timestamp ───────────────
    // Miners can hold this transaction and execute it in any future block.
    function swapTokens(uint256 amountIn, uint256 minOut, address[] calldata path) external {
        token.approve(address(router), amountIn);  // also approval griefing
        router.swapExactTokensForTokens(
            amountIn,
            minOut,
            path,
            address(this),
            block.timestamp   // ← no-op deadline: always current block
        );
    }

    // ── Safe function for control: two-step ownership would look like this
    // (not implemented here — showing what's missing)
    function setTreasury(address _treasury) external {
        require(msg.sender == owner, "not owner");
        require(_treasury != address(0), "zero");
        treasury = _treasury;
    }
}
