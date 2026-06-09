"""``python -m chainedr`` entry point — Analyzer beta only.

The legacy command stack (monitor, fuzz, profile, replay, hunt, audit,
vectors, bounty, ...) was removed in the 10/10-beta cleanup sweep.
Everything routes through the v3 CLI: scan / ci / prove / doctor / watch.
"""

from __future__ import annotations

from .cli import main


if __name__ == "__main__":
    main()
