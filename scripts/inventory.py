"""Register explicitly reviewed CMDB assets in an existing single-node pilot."""
import argparse
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.store import Store, digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--file", type=Path, required=True)
    args = parser.parse_args()
    if not (args.data_dir / "soc.db").exists():
        parser.error("Start the pilot once before registering inventory")
    records = json.loads(args.file.read_text(encoding="utf-8-sig"))
    if not isinstance(records, list) or not 1 <= len(records) <= 10000:
        parser.error("Expected 1-10000 reviewed asset records")
    seen = set()
    for item in records:
        if set(item) != {"id", "name", "criticality", "type"} or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", item["id"]) or item["id"] in seen:
            parser.error("Invalid or duplicate asset")
        if item["criticality"] not in {"standard", "high", "critical"} or item["type"] not in {"server", "endpoint"} or not isinstance(item["name"], str) or len(item["name"]) > 120:
            parser.error("Invalid asset fields")
        seen.add(item["id"])
    store = Store(args.data_dir / "soc.db")
    with store.transaction() as conn:
        for item in records:
            store.put("assets", {**item, "synthetic": False}, conn)
        policy = store.get("settings", "policy", conn)
        policy["version"] += 1  # Invalidate outstanding action approvals.
        store.put("settings", policy, conn)
        store.audit("operator.cli", "inventory.registered", "cmdb", {"count": len(records), "manifest_hash": digest(records)}, conn)
    print(f"Registered {len(records)} reviewed assets; prior response plans invalidated.")


if __name__ == "__main__":
    main()
