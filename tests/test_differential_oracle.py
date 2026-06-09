"""
Differential oracle end-to-end test.

The oracle needs a real EVM (anvil) + solc. In this repo that toolchain lives in
WSL (Ubuntu-22.04). The test invokes the demo there and asserts it both avoids a
false positive on identical implementations AND catches a planted bug. If the
backend is unavailable the test skips (it never silently passes).
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

WSL_DISTRO = "Ubuntu-22.04"


def _to_wsl_path(win_path: str) -> str:
    """Convert a Windows path to its WSL equivalent (``/mnt/<drive>/...``)."""
    path = win_path.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/", path)
    if m:
        return f"/mnt/{m.group(1).lower()}/{path[3:]}"
    return path


DEMO = _to_wsl_path(
    str(Path(__file__).resolve().parent.parent / "poc" / "differential_oracle_demo.py")
)


def _wsl_available() -> bool:
    if not shutil.which("wsl"):
        return False
    r = subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc",
         "command -v python3 >/dev/null && (command -v anvil >/dev/null || test -x $HOME/.foundry/bin/anvil) && echo OK"],
        capture_output=True, text=True, timeout=30,
    )
    return "OK" in r.stdout


@pytest.mark.skipif(not _wsl_available(),
                    reason="WSL Ubuntu-22.04 with anvil+python3 not available")
def test_differential_oracle_sound_and_effective():
    r = subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc",
         f"export PATH=$HOME/.foundry/bin:$PATH && python3 {DEMO}"],
        capture_output=True, text=True, timeout=180,
    )
    out = r.stdout
    assert "EQUIVALENT" in out, f"control scenario should not diverge:\n{out}\n{r.stderr[:500]}"
    assert "DIVERGENCE DETECTED" in out, f"planted bug should be caught:\n{out}"
    assert r.returncode == 0, f"oracle demo failed:\n{out}\n{r.stderr[:500]}"
