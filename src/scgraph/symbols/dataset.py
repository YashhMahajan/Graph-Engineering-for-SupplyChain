"""The inferred-symbol dataset: JSON lines plus a SHA-256 manifest, read offline at scan time.

``write`` stores one ``SymbolRecord`` per line, sorted by id, and a ``manifest.json`` with the
count and the SHA-256 of the file. ``load`` refuses a file whose hash does not match the
manifest, so a hand edit or a truncated download is caught before a scan trusts it. This is
integrity, not authorship: the manifest is not signed.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from importlib import resources
from pathlib import Path

__all__ = ["DatasetError", "Index", "load", "packaged_path", "write"]


class DatasetError(ValueError):
    pass


def write(records: Iterable[dict], path: Path, generator: str = "") -> dict:
    rows = sorted(records, key=lambda r: r["id"])
    text = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    manifest = {
        "file": path.name,
        "count": len(rows),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "generator": generator,
        "methods": sorted({r.get("method", "") for r in rows}),
        "ecosystems": sorted({r.get("ecosystem", "") for r in rows}),
    }
    (path.parent / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest


class Index:
    """Records by advisory id and by every alias (GHSA, PYSEC, CVE)."""

    def __init__(self, rows: list[dict]):
        self.rows = rows
        self.by_id: dict[str, dict] = {}
        for r in rows:
            for k in [r["id"], *r.get("aliases", [])]:
                self.by_id.setdefault(k, r)

    def get(self, ids: Iterable[str], package: str = "") -> dict | None:
        for i in ids:
            r = self.by_id.get(i)
            if r and (not package or r["package"].lower() == package.lower()):
                return r
        return None

    def __len__(self) -> int:
        return len(self.rows)


def packaged_path() -> Path | None:
    env = os.environ.get("SCGRAPH_SYMBOLS")
    if env:
        return Path(env)
    try:
        p = Path(str(resources.files("scgraph.symbols").joinpath("data/pypi.jsonl")))
    except (ModuleNotFoundError, FileNotFoundError):
        return None
    return p if p.exists() else None


def load(path: Path | None = None) -> Index:
    """The dataset at ``path`` (default: ``$SCGRAPH_SYMBOLS`` or the packaged file), checked
    against its manifest. An absent dataset is an empty index, not an error."""
    p = path or packaged_path()
    if p is None or not p.exists():
        return Index([])
    text = p.read_text(encoding="utf-8")
    m = p.parent / "manifest.json"
    if m.exists():
        want = json.loads(m.read_text()).get("sha256")
        got = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if want and want != got:
            raise DatasetError(f"{p}: SHA-256 does not match {m.name}; the file was modified")
    return Index([json.loads(line) for line in text.splitlines() if line.strip()])
