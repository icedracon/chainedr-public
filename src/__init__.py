# Copyright (C) 2026 Zorayr Saroyan <zorayrsaroyan13@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ChainEDR Analyzer — static security analysis for Pectra-era smart accounts.

The supported public surface is the CLI (`chainedr scan / ci / prove / doctor /
watch`). The legacy runtime / EDR / fuzzing / classifier surface was removed in
the 10/10-beta cleanup sweep; importing this package now exposes only the
detector plugin contract and the CLI entry point.
"""

__version__ = "3.2.0"
__author__ = "Zorayr Saroyan"
__license__ = "AGPL-3.0-or-later"


# Install the private-beta CLI hardening layer before the console entry point
# dispatches into chainedr.cli:main. This keeps the public CLI compatible while
# applying baseline-aware CI gating and stable product URLs.
try:
    from .beta_cli import install as _install_beta_cli_patches

    _install_beta_cli_patches()
except Exception:
    # Importing the library must remain safe even in reduced source-tree
    # environments. CI regression tests cover the installed package path.
    pass


# Normalize release-critical EIP-7702 wording and severity semantics at finding
# construction time. This compatibility layer stays intentionally narrow while
# the largest detector module is migrated toward AST/call-graph-backed rules.
try:
    from .beta_semantics import install as _install_beta_semantics

    _install_beta_semantics()
except Exception:
    # A missing optional detector surface must not break normal library imports.
    pass


__all__ = ["__version__"]
