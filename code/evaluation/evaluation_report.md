# Evaluation report

The deterministic pipeline processed 32 requests.

## Sample oracle metrics

- Case-level status accuracy: 78.125% (25/32)
- Exact step-array accuracy: 3.125% (1/32)
- Field-level accuracy (aligned steps): 51.727% (659/1274)
- Sequence accuracy: 9.375% (3/32)

The sample oracle is loaded only by this evaluator; it is not used by the production agent.

## Evidence inventory

- Manifest entries: 94
- Missing/unreadable entries: 0
- PDF/image entries without extracted text in this environment: 11
- No evidence content was invented; unsupported artifacts are handled conservatively.

## Additional cases

1. Historical identity change: old and current identifiers are resolved from the audit log.
2. Active synchronization/restore: enabled flows and restorable backups require disable/block
   findings, remediation, and future verification.
3. Retained records/tombstones: security/legal records are verified present and tombstones
   are treated as redaction-sensitive rather than deleted.

## Reliability tests and limitations

The focused test module contains seven executable tests covering full-output shape, step
numbering, historical identities, audit-time cutoffs, disabled-model determinism, invalid
citations, and retained records. Unsupported or unreadable evidence is reported and never
treated as proof of absence. PDF/image parsing is optional and conservative. The current
sample score is not submission-grade: exact step-array and sequence accuracy remain low,
which indicates that some synthetic evidence bundles still need stronger record-to-case
linking.
