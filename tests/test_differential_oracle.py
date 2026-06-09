from pathlib import Path
"""
Differential oracle end-to-end test.

The oracle needs a real EVM (anvil) + solc. In this repo that toolchain lives in
WSL (Ubuntu-22.04). The test invokes the demo there and asserts it both avoids a
false positive on identical implementations AND catches a planted bug. If the
backend is unavailable the test skips (it never silently passes).
"""
import shutil
import subprocess

import pytest

WSL_DISTRO = "Ubuntu-22.04"
DEMO = str(Path(__file__).resolve().parent.parent / "poc" / "differential_oracle_demo.py")


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
