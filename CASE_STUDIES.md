# ChainEDR Case Studies

This file separates confirmed evidence from marketing temptation.

Current status:

- Confirmed bounty-grade EIP-7702 / account-abstraction bugs: **0**.
- Confirmed non-EIP-7702 logic bug detected by ChainEDR-style logic: **1
  duplicate Cantina case**.

## Non-EIP-7702 Case Study: InfiniFi Safety Buffer Waterfall

**Protocol:** InfiniFi
**Competition:** Cantina public competition
**Finding:** #242
**Status:** Duplicate, independently found by multiple researchers
**Detector family:** `safety_buffer_waterfall` / DeFi invariant logic
**EIP-7702 trophy status:** Not a trophy. This is not an EIP-7702 bug.

### What Was Detected

The vulnerable flow had a safety buffer that fully absorbed small losses, but in
the partial-loss branch the function propagated the original loss downstream
without first consuming/subtracting the available buffer.

Expected behavior:

```text
downstream_loss = loss - min(loss, safety_buffer)
```

Observed bug pattern:

```text
if safety_buffer >= loss:
    consume buffer
    return

propagate full loss downstream
```

This creates a cliff: if `loss` is just above the buffer, downstream users can
absorb the full loss while the buffer remains unused.

### Why It Matters

The case is useful because it shows the value of domain-specific invariants: a
simple syntactic scanner is unlikely to know that a safety buffer must be
partially consumed before loss propagation.

However, it must be presented honestly:

- It was not unique; multiple humans found it.
- It was not EIP-7702/account-abstraction-specific.
- It does not prove ChainEDR catches live delegated-EOA bugs.
- It is useful as evidence that invariant-style detectors can help, not as the
  main ChainEDR trophy.

### Allowed Wording

Use:

> ChainEDR includes some DeFi invariant detectors outside the EIP-7702 core. One
> such detector matched the InfiniFi safety-buffer waterfall bug class, which was
> also found by multiple researchers in a Cantina competition. This is a useful
> non-core case study, but it is not a confirmed EIP-7702 finding.

Avoid:

- "ChainEDR found a unique production bug."
- "Missed by all major tools" unless we have reproducible tool outputs.
- "Real EIP-7702 case study."
- "Trophy bug."

## EIP-7702 Case Studies

None yet.

When a real case exists, add:

- target and source commit/address;
- exact finding;
- PoC or fork evidence;
- impact;
- disclosure/triage outcome;
- whether it was accepted, duplicated, fixed, or rejected.
