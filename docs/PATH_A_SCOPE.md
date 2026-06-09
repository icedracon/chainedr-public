# Path A - Reach: bytecode + fork-oracle analysis of unverified 7702 delegators

## Problem

A meaningful part of the real EIP-7702 surface is unverified deployed bytecode.
ChainEDR's source pipeline (regex/AST over `.sol`) cannot read that code.

The first Path A hunt also exposed a process risk: supplied "top delegator"
addresses can be bad input data. Some early addresses had `code=0`, `nonce=0`,
and no live delegation activity. The pipeline must verify runtime code, nonce,
and observed type-4 delegation counts before making any impact claim.

The goal is therefore not "claim a bug from a list." The goal is to make
ChainEDR able to reach, profile, and dynamically probe deployed implementations
that have no verified source.

## Key Insight

The fork and bytecode oracles operate on deployed bytecode. They do not require
verified Solidity source.

Current primitives:

- `src/fork_oracle.py`: fork-mode EIP-7702 behavior confirmation.
- `src/bytecode_oracle.py`: runtime bytecode profiling and value-flow probing.

## Honest Framing

This builds capability. It does not guarantee a trophy.

Success means:

- ChainEDR can analyze unverified 7702 bytecode.
- It can separate suspicious bytecode shape from dynamic evidence.
- It can confirm or refute selected delegated-account behaviors on a local/fork EVM.

It may still find zero exploitable bugs. That is an acceptable, honest outcome.

## Phases

### Phase 0 - Delegator Enumeration

Build reusable target verification when this path becomes active again.

Deliverables:

- Input: implementation address or recent type-4 delegation window.
- Output: verified runtime code, nonce, delegated EOAs, balances, and relevant state slots.
- Optional later input: Dune/BundleBear/full-history indexer.

### Phase 1 - Bytecode Triage

Profile unverified implementations with `eth_getCode`.

Already started:

- `chainedr live bytecode <address>`
- `chainedr live bytecode --recent-type4 --blocks 300 --top 25`
- raw selector/opcode profile
- proofability planner: `triage_score`, proof surfaces, and recommended probes
- best-effort authority recovery from recent EIP-7702 authorization tuples
- value-flow and call-trace parsing
- optional dynamic confirmation:
  `chainedr live bytecode <address> --dynamic --state-writes --format json`
- optional ERC-20 execute/approval sweep probing:
  `chainedr live bytecode <address> --dynamic --erc20-token 0xTOKEN --erc20-amount 1000000`
- evidence/PoC artifact output:
  `chainedr live bytecode <address> --dynamic --state-writes --evidence-out path_a_out`

Next:

- add decompiler/IR support (heimdall-rs or Panoramix preferred);
- flag state-changing selector surfaces;
- flag origin/code-size/delegatecall/selfdestruct classes.

Bytecode triage is prioritization, not proof.

### Phase 2 - Dynamic Confirmation

Use fork probes only where they support the main product's existing findings.

Probe battery:

- state-hijack: call state-changing selectors as a non-owner and diff storage;
- EOA-gate break: compare behavior before and after `0xef0100 || implementation`;
- sweep: check whether ETH/ERC-20 can be moved from a delegated victim.
- next sweep target: wire ERC-721/ERC-1155 live CLI probes from existing
  bytecode-oracle primitives.

An adverse divergence is a confirmed finding. A suspicious profile without
adverse dynamic behavior remains a lead only.

### Phase 3 - Triage + Auto-PoC

Feed confirmed divergences into the existing evidence and PoC pipeline.

Deliverables:

- JSON evidence for confirmed probes through `--output`;
- Markdown evidence bundle through `--evidence-out`;
- generated Foundry `.t.sol` reproducer for confirmed ETH outbound and
  unauthorized state-write classes.

## Dependencies And Risks

- Anvil + RPC are available locally, but fork startup must stay robust.
- Decompiler integration is still missing.
- Full-history delegator enumeration needs an external indexer; bounded recent
  windows are only partial coverage.
- Some high-volume targets may be deliberately simple fixed-destination sweepers,
  not exploitable bugs.
- Capability does not imply trophy.

## Definition Of Done

Given an unverified implementation address, ChainEDR can:

1. verify that the target is real deployed code;
2. enumerate recent delegate implementations and best-effort recover delegated
   EOAs from authorization signatures when the RPC exposes full auth tuples;
3. profile risky selectors/opcodes from bytecode;
4. dynamically confirm or refute selected behaviors on a local/fork EVM;
5. emit evidence and a runnable PoC for confirmed divergences.

Acceptance test:

- run cleanly against verified live top delegators;
- report null results honestly when no exploitability is observed.
