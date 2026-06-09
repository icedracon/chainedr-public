// SPDX-License-Identifier: MIT
// EIP-712 domain separator with block.chainid binding AND ERC-1271
// smart-contract signer fallback. Cross-chain replay is structurally
// prevented and delegated-EOA signers can still authorise. AA7702-004
// must NOT fire; AA7702-016 must NOT fire because of the 1271 path.
pragma solidity ^0.8.20;

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

contract Eip712Bound {
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes4 private constant _1271_MAGIC = 0x1626ba7e;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Bound")),
            block.chainid,
            address(this)
        ));
    }

    function authorize(
        address signer,
        bytes32 actionHash,
        bytes calldata signature
    ) external view returns (bool) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, actionHash));
        // SignatureChecker-style flow: try ERC-1271 first so delegated EOAs
        // (and any other smart-account signer) are accepted, then fall back
        // to ecrecover for plain EOAs.
        if (signer.code.length > 0) {
            return IERC1271(signer).isValidSignature(digest, signature) == _1271_MAGIC;
        }
        require(signature.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == signer, "bad sig");
        return true;
    }
}
