"""Export the dataset for people who want it outside scgraph.

``osv_patches`` makes one partial OSV record per advisory. Each record adds the inferred symbol
as ``affected[].ecosystem_specific.affected_functions`` (the field the Go database already
uses) and keeps the provenance in ``database_specific.scgraph``. A maintainer of an advisory
database can read the patch and decide. Nothing is sent anywhere by scgraph.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

__all__ = ["bundle", "osv_patch", "osv_patches"]

SCHEMA = "1.6.0"


def osv_patch(rec: dict) -> dict:
    ev = rec.get("evidence") or {}
    functions = [rec["symbol"]]
    return {
        "schema_version": SCHEMA,
        "id": rec["id"],
        "aliases": rec.get("aliases", []),
        "affected": [
            {
                "package": {"ecosystem": rec["ecosystem"], "name": rec["package"]},
                "ecosystem_specific": {"affected_functions": functions},
            }
        ],
        "database_specific": {
            "scgraph": {
                "method": rec.get("method"),
                "verified": rec.get("verified"),
                "confidence": rec.get("confidence"),
                "evidence": ev.get("fix") or "code search of the affected release",
                "affected_version": rec.get("affected_version"),
                "fixed_version": rec.get("fixed_version"),
                "entry_points": rec.get("entry_points", [])[:20],
            }
        },
    }


def osv_patches(records: list[dict]) -> list[dict]:
    return [osv_patch(r) for r in sorted(records, key=lambda r: r["id"])]


def bundle(data_dir: Path, out: Path) -> list[Path]:
    """Copy each dataset with its manifest, signature and public key, and write the OSV patches."""
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for f in sorted(
        [*data_dir.glob("*.jsonl"), *data_dir.glob("*.manifest.*"), *data_dir.glob("*.pub")]
    ):
        shutil.copy2(f, out / f.name)
        written.append(out / f.name)
    rows = [
        json.loads(x)
        for p in sorted(data_dir.glob("*.jsonl"))
        for x in p.read_text().splitlines()
        if x
    ]
    patches = out / "osv-patches"
    patches.mkdir(exist_ok=True)
    for p in osv_patches(rows):
        f = patches / f"{p['id']}.json"
        f.write_text(json.dumps(p, indent=1) + "\n", encoding="utf-8")
        written.append(f)
    return written
