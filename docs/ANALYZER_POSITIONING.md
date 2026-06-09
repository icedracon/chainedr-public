# ChainEDR Analyzer Positioning

This note captures the current product line after the mentor review.

## Correct Product Definition

ChainEDR is not currently a finished Web3 EDR. The credible product is:

> ChainEDR Analyzer is a strong early static analyzer for EIP-7702, ERC-4337,
> and ERC-7562 security assumptions, with proof discipline for turning selected
> static findings into fork or Foundry evidence.

Runtime monitoring can remain in the repository as an optional workflow, but it
should not be the headline until it has production-grade indexing, alerting,
reorg handling, and long-term correlation.

## Real Competitors

The real comparison set is:

- Slither;
- Semgrep rules;
- CodeQL queries;
- Aderyn;
- Mythril-style symbolic analysis;
- custom Solidity audit scripts;
- ERC-4337 validation checkers.

The wedge is narrower and sharper:

> What old assumptions become unsafe after an EOA can execute delegated code?

That is a valid niche. The tool should be judged primarily on that boundary.

## Static-Analysis Foundation Questions

These are the next questions that determine the ceiling:

- Does it parse Solidity source reliably?
- Does it use AST/call-graph-backed logic, or mostly regex?
- Does it understand inheritance?
- Does it resolve modifiers?
- Does it follow internal function calls?
- Does it understand overridden functions?
- Can it trace access-control conditions across functions?
- Does it support multiple Solidity versions?
- Does it scan proxy implementations separately?
- Can it analyze unverified bytecode as a fallback?

If most rules remain regex-only, ChainEDR Analyzer stays useful but capped. If
the core rules become AST-aware and call-graph-aware, the tool becomes much
more serious.

## Pectra-Specific Core

This is the core product surface:

- `tx.origin == msg.sender` assumptions.
- `extcodesize == 0` / `address.code.length == 0` EOA gates.
- Assumptions that EOAs cannot execute fallback logic.
- Assumptions that EOAs cannot batch calls.
- Delegate target storage-collision risk.
- Insecure initializer logic.
- Reinitialization paths.
- `delegatecall` from delegated-account implementations.
- Unsafe cross-chain authorization assumptions.
- Signature-domain mistakes.
- Nonce and replay weaknesses.
- Assumptions broken by persistent delegation after revert.
- Dangerous receive/fallback behavior.
- Approval-and-transfer paths reachable through delegated execution.

## ERC-4337 / ERC-7562 Core

This is where ChainEDR Analyzer becomes more than "Slither with extra rules":

- Unsafe `validateUserOp()` logic.
- Missing EntryPoint caller checks.
- Banned opcode usage in validation.
- Storage-access violations.
- Unpredictable gas behavior.
- External calls during validation.
- Paymaster misuse.
- Weak or replayable signature checks.
- Validation logic dependent on mutable external state.
- Hardcoded EntryPoint version mismatches.
- Repeated initialization through UserOperation flow.

## Rule-Quality Bar

Every serious rule should include:

- severity;
- confidence;
- source location;
- why the issue matters after Pectra;
- a minimal vulnerable pattern;
- a safe remediation;
- test fixtures;
- a negative control;
- false-positive gates;
- an exploitability label that does not overclaim.

High severity should mean "worth immediate human review", not "automatically a
confirmed exploit".

## Proof Guidance Bar

The most useful part of ChainEDR is preventing sloppy bounty submissions.

Critical rules should answer:

- What is the proof objective?
- What exact function should be called?
- What is the pre-Pectra behavior?
- What is the post-Pectra behavior?
- What state, calldata, or balance diff would confirm impact?
- Can the tool generate a Foundry test skeleton?
- Can the finding be marked as `STATIC_CANDIDATE`, `LIKELY_EXPLOITABLE`,
  `FORK_CONFIRMED`, or `REFUTED`?

No confirmed behavior means no vulnerability claim.

## What Is Not Needed Yet

These are future modules, not blockers for ChainEDR Analyzer:

- mempool monitoring;
- full chain indexer;
- wallet reputation database;
- Telegram/Slack alerts;
- recipient clustering;
- long-term transaction correlation;
- real-time treasury protection.

They can become a separate runtime product later:

```text
ChainEDR Analyzer -> static Pectra security scanner
ChainEDR Monitor  -> optional runtime on-chain watcher
```

## Immediate Milestone

The most important next milestone is not live monitoring. It is:

```text
AST-aware analysis
+ call graph
+ modifier resolution
+ inheritance tracking
+ proxy-aware scanning
+ blind external benchmark
+ Foundry PoC skeleton generation
```
