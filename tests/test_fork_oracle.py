"""
Fork-mode 7702 oracle test. Forks mainnet (anvil + RPC_URL) and confirms the
AA7702-002 EOA-detection break dynamically. Skips when the WSL/anvil/RPC
toolchain or RPC_URL is unavailable — never silently passes.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def test_fork_oracle_module_pure_logic():
    """Engine pieces that need no anvil: delegation-code format + verdict shape."""
    import fork_oracle as fo
    assert fo.DELEGATION_PREFIX == "ef0100"
    v = fo.DynamicVerdict("AA7702-002", True, True, False, "x")
    d = v.to_dict()
    assert d["dynamically_confirmed"] is True
    assert d["finding"] == "AA7702-002"
    assert d["value_before_delegation"] is True and d["value_after_delegation"] is False

WSL_DISTRO = "Ubuntu-22.04"
POC = str(Path(__file__).resolve().parent.parent / "poc" / "fork_7702_oracle.py")


def _ready() -> bool:
    if not shutil.which("wsl"):
        return False
    if not os.environ.get("RPC_URL") and not _rpc_in_env_file():
        return False
    r = subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc",
         "command -v python3 >/dev/null && test -x $HOME/.foundry/bin/anvil && echo OK"],
        capture_output=True, text=True, timeout=30,
    )
    return "OK" in r.stdout


def _rpc_in_env_file() -> bool:
    p = os.path.join(os.path.dirname(__file__), "..", ".env")
    return os.path.exists(p) and "RPC_URL=" in open(p).read()


@pytest.mark.rpc
@pytest.mark.external
@pytest.mark.skipif(not _ready(), reason="WSL/anvil/RPC_URL not available")
def test_fork_proves_eoa_detection_break():
    rpc = os.environ.get("RPC_URL", "")
    if not rpc and _rpc_in_env_file():
        for line in open(os.path.join(os.path.dirname(__file__), "..", ".env")):
            if line.startswith("RPC_URL="):
                rpc = line.strip().split("=", 1)[1]
    r = subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc",
         f"export PATH=$HOME/.foundry/bin:$PATH; export RPC_URL='{rpc}'; python3 {POC}"],
        capture_output=True, text=True, timeout=240,
    )
    if "anvil fork did not start in time" in r.stderr:
        pytest.skip("Anvil was present but did not start in time")
    assert "DIVERGENCE PROVEN" in r.stdout, f"oracle did not prove the break:\n{r.stdout}\n{r.stderr[:500]}"
    assert r.returncode == 0
