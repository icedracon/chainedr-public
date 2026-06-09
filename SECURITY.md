# Security Policy

## Supported Status

ChainEDR Analyzer is currently a private-beta research tool. It is designed for
authorized smart-contract review, controlled CI dry-runs, benchmark research,
and proof-oriented triage.

It is **not** a production audit replacement, a runtime EDR guarantee, or an
automatic exploit-confirmation engine.

## Reporting A Security Issue

Please report security-sensitive issues privately to the repository owner before
opening a public issue. Include:

- affected commit or version;
- minimal reproduction steps;
- expected and observed behavior;
- impact assessment;
- whether the issue affects scanning accuracy, report integrity, CI gating,
  dynamic confirmation, RPC handling, or generated proof artifacts.

Do not include private keys, seed phrases, live credentials, or unrelated target
data in a report.

## Responsible Use

Use ChainEDR only for code you own, code you are authorized to review, or targets
covered by an explicit disclosure, contest, or bug-bounty scope.

Static findings are candidates. Escalate only after manual validation and, where
possible, authorized fork or local-harness confirmation.

## Known Private-Beta Boundaries

- Regex and best-effort semantic checks still coexist.
- Some findings remain context-dependent and require human triage.
- Dynamic confirmation covers selected classes, not every rule.
- Bytecode profiling is prioritization evidence, not proof of exploitability.
- Controlled benchmark scores are corpus-scoped and must not be presented as
  production precision.
