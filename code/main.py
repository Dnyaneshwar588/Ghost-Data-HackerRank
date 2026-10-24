from pathlib import Path
import sys

import pandas as pd
from pipeline import AuditAgent, validate_output


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = root / "output.csv"
    agent = AuditAgent(root / "dataset")
    result = agent.run()
    result.to_csv(output, index=False, quoting=1)
    usage = agent.interpreter.usage
    total_tokens = usage.input_tokens + usage.output_tokens
    cost = "$0.00" if not agent.interpreter.enabled else "not calculated (pricing not configured)"
    (root / "code/evaluation/usage_report.md").write_text(
        f"""# Model usage report

Final full-dataset run: {len(result)} requests.

- Provider: {"Groq" if agent.interpreter.enabled else "none"}
- Model name: {agent.interpreter.model if agent.interpreter.enabled else "none"}
- API calls: {usage.calls}
- Input tokens: {usage.input_tokens}
- Output tokens: {usage.output_tokens}
- Total tokens: {total_tokens}
- Average tokens per request: {total_tokens / len(result):.2f}
- Estimated total cost: {cost}
- Estimated cost per request: {cost if not agent.interpreter.enabled else "not calculated (pricing not configured)"}

The default run uses no external model and therefore has zero calls and zero tokens.
""",
        encoding="utf-8",
    )
    evidence_ids = set(pd.read_csv(root / "dataset/evidence_files.csv").file_id)
    evidence_ids.update(pd.read_csv(root / "dataset/system_activity.csv").activity_id)
    evidence_ids.update(pd.read_csv(root / "dataset/user_audit_log.csv").audit_id)
    errors = validate_output(output, len(result), evidence_ids)
    if errors:
        raise SystemExit("output validation failed: " + "; ".join(errors))
    print(f"processed={len(result)} output={output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())