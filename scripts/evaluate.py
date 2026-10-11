"""Run the reproducible synthetic benchmark; writes inspectable JSON evidence."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.learning import run_research


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=41)
    parser.add_argument("--count", type=int, default=1800)
    parser.add_argument("--output", type=Path, default=ROOT / "research" / "evaluation.json")
    args = parser.parse_args()
    report = run_research(seed=args.seed, count=args.count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "eligible": report["eligible"],
                      "production_eligible": report["production_eligible"],
                      "baseline": report["metrics"].get("baseline"),
                      "candidate": report["metrics"].get("candidate"),
                      "failed_gates": [gate["name"] for gate in report["gates"] if not gate["passed"]]}, indent=2))


if __name__ == "__main__":
    main()
