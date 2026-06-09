"""Tests for the solc-AST foundation (Tier 2). Skip if solc is unavailable."""
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import ast_utils  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("solc"), reason="solc not on PATH")

IFACE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IFoo { function bar(uint256 x) external returns (uint256); }
"""

IMPL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Foo {
    function bar(
        uint256 x
    ) external pure returns (uint256) { return x + 1; }
}
"""

SIGV = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Auth {
    function go(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
"""


def test_interface_detected_via_ast():
    assert ast_utils.is_interface_file_ast(IFACE) is True
    assert ast_utils.is_interface_file_ast(IMPL) is False


def test_multiline_function_body_recognized():
    # the impl uses a multi-line signature that the regex heuristic struggles with
    facts = ast_utils.extract_facts(IMPL)
    foo = next(f for f in facts if f.name == "Foo")
    assert foo.kind == "contract"
    assert foo.has_function_body is True


def test_signature_verification_detected():
    facts = ast_utils.extract_facts(SIGV)
    auth = next(f for f in facts if f.name == "Auth")
    assert auth.verifies_signatures is True
