# EIP-7702 Semantics Notes For Reviewers

## Purpose

This note records the semantic boundaries ChainEDR Analyzer uses when describing
EIP-7702 findings. It exists to keep detector output technically disciplined
while the highest-value rules are migrated from pattern matching toward deeper
AST and call-graph analysis.

## Persistent Delegation

EIP-7702 delegation is not a one-transaction-only behavior flag. Once an
authorization is processed, the account code is represented by a delegation
designator and persists until changed by a later authorization.

Review consequence:

- do not describe EIP-7702 code delegation as merely temporary;
- evaluate lifecycle, revocation, and redelegation assumptions explicitly.

## `chain_id = 0`

EIP-7702 intentionally allows a `chain_id` value of zero for authorizations that
are valid across chains.

Review consequence:

- `chain_id = 0` is not automatically a vulnerability;
- treat it as a policy and deployment-scope review signal;
- ask whether the delegated implementation address is intended and safe across
  every chain where the authorization may be accepted.

## `tx.origin == msg.sender`

EIP-7702 changes the security meaning of EOA-oriented gates. A delegated account
may execute code while preserving account identity assumptions that older code
used as a proxy for non-programmability.

Review consequence:

- do not treat `tx.origin == msg.sender` as proof of non-programmable behavior;
- do not recommend `tx.origin` as an authorization boundary;
- document the exact property the application intended to enforce.

## Value Transfer And Gas

A delegated account can execute delegated code when called. However, gas still
matters.

Review consequence:

- `.call{value: ...}` paths require a full callback and reentrancy review;
- `.transfer()` and `.send()` retain their normal forwarded-gas constraints;
- do not claim arbitrary re-entry is feasible from delegation alone when the
  available gas budget does not support that claim.

## Nested `delegatecall`

Nested `delegatecall` executes another implementation in the delegated account's
storage context while preserving the current call-frame sender and value.

Review consequence:

- focus on storage mutation, implementation trust, and authorization model;
- do not claim that nested `delegatecall` automatically changes `msg.sender` to
  the delegation target;
- do not recommend `tx.origin` as the fix.

## Evidence Discipline

Static findings remain review candidates. Use source review, semantic context,
local tests, and authorized fork-mode evidence to confirm or refute impact.
