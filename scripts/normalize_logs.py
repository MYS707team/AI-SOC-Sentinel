"""Offline NDJSON conversion. Sending is a separate, explicit operator action."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.adapters import normalize_wazuh, normalize_zeek


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["wazuh", "zeek"], required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--internal-cidr", action="append", default=[])
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output must be new; no overwrite")
    mapping = json.loads(args.mapping.read_text(encoding="utf-8-sig"))
    accepted, rejected = 0, []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.input.open(encoding="utf-8-sig") as source, args.output.open("x", encoding="utf-8") as target:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                if len(line) > 1_048_576:
                    raise ValueError("LINE_TOO_LARGE")
                record = json.loads(line)
                normalized = normalize_wazuh(record, mapping) if args.format == "wazuh" else normalize_zeek(record, mapping, args.internal_cidr)
                target.write(json.dumps(normalized, separators=(",", ":")) + "\n")
                accepted += 1
            except (ValueError, KeyError, TypeError, OverflowError, OSError):
                # No exception payload or input data copied into rejected metadata.
                rejected.append({"line": line_number, "reason": "unsupported_invalid_or_unmapped", "raw_payload_retained": False})
    args.output.with_suffix(".rejections.json").write_text(json.dumps(rejected, indent=2), encoding="utf-8")
    print(json.dumps({"accepted": accepted, "rejected": len(rejected), "sent": False}))
    if rejected:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
