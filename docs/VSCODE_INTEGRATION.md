# VS Code Integration

ChainEDR ships a `.vscode/tasks.json` that wires three tasks into the
editor's Tasks UI, all of which use the `compact` format so findings
land in the Problems panel as clickable diagnostics.

## What you get

- **ChainEDR: watch (compact, dev-time)** — runs `chainedr watch` in a
  dedicated terminal panel. Re-scans on every Solidity save and pipes
  findings into the Problems panel with the `chainedr` owner. Default
  build task — `Ctrl/Cmd+Shift+B` triggers it.
- **ChainEDR: scan (one-shot, compact)** — single scan, silent panel,
  Problems-panel diagnostics.
- **ChainEDR: scan + prove (Foundry skeletons)** — single scan that
  also emits `.t.sol` skeletons under `chainedr-poc/` for every
  supported finding.

## Problem matcher

The matcher consumes the compact-format line shape:

```
<file>:<line>:<col>: [<SEV>/<GRADE>] <RULE_ID> <title>
```

Severity maps directly to VS Code's `error` / `warning` / `info` levels
(CRITICAL and HIGH render red; MEDIUM yellow; LOW gray). The rule ID
shows up in the diagnostic's "code" so VS Code links straight to it.

## Recommended extensions

`.vscode/extensions.json` proposes:

- `JuanBlanco.solidity` — syntax + IntelliSense for `.sol`.
- `NomicFoundation.hardhat-solidity` — first-class Hardhat / Foundry
  navigation.
- `tintinweb.solidity-visual-auditor` — the standard Solidity
  auditor view; pairs well with ChainEDR's diagnostic stream.

## One-time setup

1. `python -m pip install -e ./src`
2. Open the repo in VS Code.
3. Accept the workspace extension recommendations.
4. `Ctrl/Cmd+Shift+B` — picks the watch task by default.

After that, every save on a `.sol` file re-runs ChainEDR and the
Problems panel updates in place.
