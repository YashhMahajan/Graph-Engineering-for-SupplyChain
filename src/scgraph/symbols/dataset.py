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

__all__ = ["DatasetError", "Index", "load", "packaged_paths", "write"]


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
    (path.parent / f"{path.stem}.manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
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


def packaged_paths() -> list[Path]:
    """The dataset files in use: ``$SCGRAPH_SYMBOLS`` (a file or a directory of ``*.jsonl``),
    else every ``*.jsonl`` shipped in ``scgraph/symbols/data``."""
    env = os.environ.get("SCGRAPH_SYMBOLS")
    if env:
        p = Path(env)
        return sorted(p.glob("*.jsonl")) if p.is_dir() else [p]
    try:
        d = Path(str(resources.files("scgraph.symbols").joinpath("data")))
    except (ModuleNotFoundError, FileNotFoundError):
        return []
    return sorted(d.glob("*.jsonl")) if d.is_dir() else []


def _read(p: Path) -> list[dict]:
    text = p.read_text(encoding="utf-8")
    for m in (p.parent / f"{p.stem}.manifest.json", p.parent / "manifest.json"):
        if m.exists():
            want = json.loads(m.read_text()).get("sha256")
            if want and want != hashlib.sha256(text.encode("utf-8")).hexdigest():
                raise DatasetError(f"{p}: SHA-256 does not match {m.name}; the file was modified")
            break
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load(path: Path | None = None) -> Index:
    """The dataset at ``path`` (default: every packaged file), each checked against its
    manifest. An absent dataset is an empty index, not an error."""
    rows: list[dict] = []
    for p in [path] if path else packaged_paths():
        if p.exists():
            rows += _read(p)
    return Index(rows)
