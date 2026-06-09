# ChainEDR Package Notes

This directory contains the installable Python package for ChainEDR.

For the current public positioning, reviewer path, commands, and limitations, use
the repository-level docs:

- `../README.md`
- `../REVIEWER_BRIEF.md`
- `../REALITY_CHECK.md`
- `../docs/PATH_A_SCOPE.md`

## Current Scope

ChainEDR is a research prototype focused on:

- EIP-7702 delegated-account risk patterns;
- ERC-4337 / ERC-7562 account-abstraction validation boundaries;
- SARIF/JSON CI output;
- evidence bundles for human review;
- opt-in dynamic confirmation and bytecode reach.

It is not a production audit replacement and it has not yet produced a confirmed
live bounty-grade finding.

## Important Modules

- `cli.py` - packaged five-command CLI entry point (`scan`, `ci`, `prove`, `live`, `doctor`).
- `__main__.py` - legacy command handlers and compatibility routes.
- `eip7702_detector.py` - core EIP-7702 static checks.
- `eip7702_validation.py` - ERC-7562 validation-sandbox checks.
- `fork_oracle.py` - fork-mode EIP-7702 behavior confirmation.
- `bytecode_oracle.py` - runtime-bytecode profiling and local/fork probes.
- `confirmation.py` - opt-in dynamic confirmation metadata for scan findings.
- `sarif_output.py` - GitHub Code Scanning output.

## Claims Boundary

The benchmark result is corpus-scoped. Bytecode profiles are prioritization
signals. Dynamic traces and manual triage are required before treating a result
as a real finding.
