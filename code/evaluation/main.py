from __future__ import annotations
import json
import sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import AuditAgent, EvidenceExtractor


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    actual = AuditAgent(root / "dataset", "sample_deletion_requests.csv").run()
    oracle = pd.read_csv(root / "dataset/sample_output.csv")
    got = actual[actual.case_id.isin(oracle.case_id)].set_index("case_id")
    exp = oracle.set_index("case_id")
    status_ok = sum(got.loc[i, "deletion_status"] == exp.loc[i, "deletion_status"] for i in exp.index)
    exact = sequence = fields = total = 0
    for i in exp.index:
        a, e = json.loads(got.loc[i, "steps_json"]), json.loads(exp.loc[i, "steps_json"])
        exact += a == e
        sequence += [(x["phase"], x["operation"]) for x in a] == [(x["phase"], x["operation"]) for x in e]
        for x, y in zip(a, e):
            for k in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                total += 1
                fields += x.get(k) == y.get(k)
    report = root / "code/evaluation/evaluation_report.md"
    extractor = EvidenceExtractor(root / "dataset")
    unsupported = sum(not e.text and e.path.suffix.lower() in {".pdf", ".png", ".jpg", ".jpeg"}
                      for e in extractor.items)
    report.write_text(f"""# Evaluation report

The deterministic pipeline processed {len(actual)} requests.

## Sample oracle metrics

- Case-level status accuracy: {status_ok / len(exp):.3%} ({status_ok}/{len(exp)})
- Exact step-array accuracy: {exact / len(exp):.3%} ({exact}/{len(exp)})
- Field-level accuracy (aligned steps): {(fields / total if total else 0):.3%} ({fields}/{total})
- Sequence accuracy: {sequence / len(exp):.3%} ({sequence}/{len(exp)})

The sample oracle is loaded only by this evaluator; it is not used by the production agent.

## Evidence inventory

- Manifest entries: {len(extractor.items)}
- Missing/unreadable entries: {len(extractor.missing)}
- PDF/image entries without extracted text in this environment: {unsupported}
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
""", encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()