import json
from pathlib import Path
from pipeline import AuditAgent


def test_full_output_schema():
    root = Path(__file__).resolve().parents[1]
    out = AuditAgent(root / "dataset").run()
    assert len(out) == 518
    assert out.case_id.is_unique
    for value in out.steps_json:
        assert isinstance(json.loads(value), list)


def test_ordering_and_not_applicable_contract():
    root = Path(__file__).resolve().parents[1]
    out = AuditAgent(root / "dataset").run()
    for _, row in out.iterrows():
        steps = json.loads(row.steps_json)
        assert [x["step_no"] for x in steps] == list(range(1, len(steps) + 1))
        assert row.deletion_status != "NOT_APPLICABLE" or steps == []
