# Real EIP-7702 Bug Benchmark

This corpus is intentionally separate from `benchmarks/eip7702_full`.

`eip7702_full` is a labeled synthetic/regression benchmark. It is useful for
guarding detector behavior, but it is not proof of production recall.

This directory is for externally confirmed public EIP-7702 findings only:

- public advisory, contest report, Immunefi/Cantina/Sherlock/Code4rena report,
  or maintainer-confirmed disclosure;
- source or minimal reproduction available locally;
- expected ChainEDR rule(s) recorded before evaluation.

Current status: no confirmed real EIP-7702 production bugs are in this corpus.
Until cases are added, recall is intentionally reported as `null`, not `0` and
not `1`.
