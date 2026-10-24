# Evaluation report

The deterministic pipeline processed 32 requests.

## Sample oracle metrics

- Case-level status accuracy: 37.500% (12/32)
- Exact step-array accuracy: 0.000% (0/32)
- Field-level accuracy (aligned steps): 34.921% (374/1071)
- Sequence accuracy: 0.000% (0/32)

The sample oracle is loaded only by this evaluator; it is not used by the production agent.

## Evidence inventory

- Manifest entries: 94
- Missing/unreadable entries: 0
- PDF/image entries without extracted text in this environment: 15
- No evidence content was invented; unsupported artifacts are handled conservatively.

## Additional cases

1. Historical identity change: old and current identifiers are resolved from the audit log.
2. Active synchronization/restore: enabled flows and restorable backups require disable/block
   findings, remediation, and future verification.
3. Retained records/tombstones: security/legal records are verified present and tombstones
   are treated as redaction-sensitive rather than deleted.

## Reliability tests and limitations

The test suite covers timestamps, duplicate identifiers, missing evidence, malformed JSON,
CSV escaping, false matches, and operation ordering. Unsupported or unreadable evidence is
reported and never treated as proof of absence. PDF/image parsing is optional and conservative.
