import json
from pathlib import Path
from pipeline import AuditAgent, IdentityResolver, dt


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


def test_historical_identity_tokens_are_resolved():
    root = Path(__file__).resolve().parents[1]
    users, tokens = IdentityResolver(root / "dataset").resolve("e.varga90@yahoo.com")
    assert users
    assert "e.varga90@yahoo.com" in tokens


def test_audit_cutoff_excludes_future_activities():
    root = Path(__file__).resolve().parents[1]
    agent = AuditAgent(root / "dataset", "sample_deletion_requests.csv")
    row = agent.requests.iloc[0]
    activities = agent._activity_matches(["user_01"], dt(row.audit_at))
    assert all(dt(value) <= dt(row.audit_at) for value in activities.event_time)


def test_llm_disabled_is_deterministic():
    root = Path(__file__).resolve().parents[1]
    agent = AuditAgent(root / "dataset", "sample_deletion_requests.csv")
    assert not agent.interpreter.enabled
    assert agent.interpreter.interpret(["user_01"], [])["evidence_refs"] == []
