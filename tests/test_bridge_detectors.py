import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from bridge_detectors import check_bridge_signature_gaps


def test_bridge_signature_gap_requires_signature_context():
    source = {
        "AccountFactory.sol": """
pragma solidity ^0.8.23;

contract AccountFactory {
    function getSaltWebAuthn(uint256 ownerX, uint256 ownerY, uint256 salt, uint32 entityId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(ownerX, ownerY, salt, entityId));
    }
}
""",
    }

    assert check_bridge_signature_gaps(source) == []


def test_bridge_signature_gap_flags_signature_hash_without_contract_binding():
    source = {
        "Bridge.sol": """
pragma solidity ^0.8.23;

contract Bridge {
    function claim(bytes calldata signature, address user, uint256 amount, uint256 nonce, bytes32 requestId) external {
        bytes32 digest = keccak256(abi.encode(user, amount, nonce, requestId));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "bad sig");
    }
}
""",
    }

    findings = check_bridge_signature_gaps(source)
    assert [f["check"] for f in findings] == ["bridge_sig_missing_address"]


def test_bridge_signature_gap_ignores_eip712_domain_contract_binding():
    source = {
        "Depositor.sol": """
pragma solidity ^0.8.23;

contract Depositor {
    address public amlSigner;

    function _verifyAML(bytes32 messageHash, bytes calldata signature) private {
        bytes32 digest = MessageHashUtils.toTypedDataHash(_getDomainSeparator(), messageHash);
        address recoveredSigner = ECDSA.recover(digest, signature);
        require(recoveredSigner == amlSigner, "bad signer");
    }

    function _getDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Depositor"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function _getMessageHash(uint256 amount, address destinationAddress, uint256 deadline)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256("Deposit(address sender,uint256 amount,address destinationAddress,uint256 deadline)"),
                msg.sender,
                amount,
                destinationAddress,
                deadline
            )
        );
    }
}
""",
    }

    assert check_bridge_signature_gaps(source) == []


def test_bridge_signature_gap_ignores_domain_separator_function_binding():
    source = {
        "RewardsController.sol": """
pragma solidity ^0.8.23;

contract RewardsController {
    mapping(address => uint256) public nonces;

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("RewardsController"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function claim(bytes calldata signature, address owner, address spender, uint256 amount) external {
        address recovered = ecrecover(
            keccak256(
                abi.encodePacked(
                    "\\x19\\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            keccak256("ClaimPermit(address owner,address spender,uint256 amount,uint256 nonce)"),
                            owner,
                            spender,
                            amount,
                            nonces[owner]++
                        )
                    )
                )
            ),
            27,
            bytes32(0),
            bytes32(0)
        );
        require(recovered != address(0), "bad signer");
    }
}
""",
    }

    assert check_bridge_signature_gaps(source) == []


def test_bridge_signature_gap_ignores_hash_typed_data_v4_binding():
    source = {
        "FastWithdrawVault.sol": """
pragma solidity ^0.8.23;

contract FastWithdrawVault is EIP712Upgradeable {
    function initialize() external {
        __EIP712_init("FastWithdrawVault", "1");
    }

    function claim(bytes calldata signature, address l1Token, address l2Token, address to, uint256 amount) external {
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Withdraw(address l1Token,address l2Token,address to,uint256 amount)"),
            l1Token,
            l2Token,
            to,
            amount
        ));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        require(signer != address(0), "bad signer");
    }
}
""",
    }

    assert check_bridge_signature_gaps(source) == []


def test_bridge_signature_gap_ignores_permit2_nonce_hash_context():
    source = {
        "Swapper.sol": """
pragma solidity ^0.8.23;

contract Swapper {
    IPermit2 public immutable permit2;

    function swap(address asset, uint256 amount, uint256 deadline, bytes calldata signature) external {
        permit2.permitTransferFrom(
            IPermit2.PermitTransferFrom({
                permitted: IPermit2.TokenPermissions(asset, amount),
                nonce: uint256(keccak256(abi.encode(msg.sender, asset, amount, deadline))),
                deadline: deadline
            }),
            IPermit2.SignatureTransferDetails({to: address(this), requestedAmount: amount}),
            msg.sender,
            signature
        );
    }
}
""",
    }

    assert check_bridge_signature_gaps(source) == []


def test_bridge_receive_ignores_admin_token_rescue_withdraw_tokens():
    source = {
        "PrivateGateway.sol": """
pragma solidity ^0.8.23;

contract PrivateGateway {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    modifier onlyRole(bytes32) { _; }

    function withdrawTokens(address token, address receiver, uint256 amount)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (token == address(0)) {
            Address.sendValue(payable(receiver), amount);
        } else {
            IERC20(token).safeTransfer(receiver, amount);
        }
    }
}
""",
    }

    assert check_bridge_signature_gaps(source) == []
