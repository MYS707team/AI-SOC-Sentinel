"""Download pinned public data, prepare, train and install a LOCAL LAB model.

No request from the public corpus is ever executed or sent to any target.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.http_learning import prepare_public, load_public, train_http
from app.store import digest

REVISION = "424c6e1c1951570473d9d6c0227eaaac6fdd6d02"
FILES = {
    "normalTrafficTraining.txt": "d51de812d9201ef2b173b6ae3e3e740c309047ac85545c06c51d6fb1ddbc1e63",
    "normalTrafficTest.txt": "f05dfc312d5d14fd1ed8371de27a9e4deab3dc09265f5d7f9df2643df8385089",
    "anomalousTrafficTest.txt": "12fa4f0d496ceb859bb2652abf7f0f0ed8c59e1d9ce501b8a9a0ef38a625c046",
}


def download(directory):
    directory.mkdir(parents=True, exist_ok=True)
    items = []
    for name, checksum in FILES.items():
        url = f"https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/{REVISION}/OriginalDataSets/csic_2010/{name}"
        path = directory / name
        if not path.exists():
            print("Downloading " + name, flush=True)
            with urllib.request.urlopen(url, timeout=60) as response:
                content = response.read(30_000_001)
            if len(content) > 30_000_000 or hashlib.sha256(content).hexdigest() != checksum:
                raise ValueError("PUBLIC_SOURCE_HASH_MISMATCH")
            path.write_bytes(content)
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != checksum:
            raise ValueError("PUBLIC_SOURCE_HASH_MISMATCH")
        items.append({"name": name, "sha256": checksum, "bytes": len(content), "url": url})
    manifest = {"dataset": "CSIC HTTP 2010", "source_kind": "public_lab_capture", "files": items,
        "revision": REVISION, "authors": ["Carmen Torrano Gimenez", "Alejandro Perez Villegas", "Gonzalo Alvarez Maranon"],
        "documentation": "https://web.archive.org/web/20130924222653/http://iec.csic.es/dataset",
        "mirror": "https://github.com/msudol/Web-Application-Attack-Datasets",
        "label_semantics": "normal vs anomalous; includes unintentional invalid requests",
        "license_note": "Public research dataset; attribution retained; raw dataset is not redistributed."}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / ".runtime")
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    data = args.data_dir.resolve()
    source = data / "public-data" / "csic2010"
    if args.download:
        download(source)
    dataset = data / "http" / "public.jsonl"
    print("Preparing deduplicated numeric features...", flush=True)
    summary = prepare_public(source, dataset)
    print(json.dumps({k: v for k, v in summary.items() if k not in {"source_manifest", "limitations"}}), flush=True)
    base, manifest = load_public(dataset)
    print("Training Random Forest; choosing thresholds on validation only...", flush=True)
    artifact, report = train_http(base)
    bundle = {"artifact": artifact, "artifact_hash": digest(artifact), "report": report, "dataset_manifest": manifest}
    path = data / "http" / "bootstrap-model.json"
    path.write_text(json.dumps(bundle), encoding="utf8")
    (ROOT / "research" / "http-evaluation.json").write_text(json.dumps({"report": report, "dataset": manifest}, indent=2), encoding="utf8")
    print(json.dumps(report, indent=2), flush=True)
    print("Local lab artifact: " + str(path), flush=True)


if __name__ == "__main__":
    main()
