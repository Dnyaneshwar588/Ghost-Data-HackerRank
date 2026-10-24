from pathlib import Path
import sys

from pipeline import AuditAgent, validate_output


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = root / "output.csv"
    result = AuditAgent(root / "dataset").run()
    result.to_csv(output, index=False, quoting=1)
    errors = validate_output(output, len(result))
    if errors:
        raise SystemExit("output validation failed: " + "; ".join(errors))
    print(f"processed={len(result)} output={output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())