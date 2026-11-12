"""The cached fetcher, npm release extraction, and the download-rank selection."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from scgraph.symbols.fetch import Fetcher
from scgraph.symbols.js import available
from scgraph.symbols.npm import npm_release, npm_versions


class Resp:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status
        self._body = body
        self.headers = headers or {"Content-Length": str(len(body))}

    def iter_content(self, n: int):
        yield self._body


class Session:
    def __init__(self, script: list[Resp]):
        self.script = list(script)
        self.headers: dict[str, str] = {}
        self.calls = 0

    def get(self, url: str, **kw: Any) -> Resp:
        self.calls += 1
        return self.script.pop(0)


def test_responses_and_404s_are_cached_on_disk(tmp_path: Path) -> None:
    s = Session([Resp(200, b"hello"), Resp(404)])
    f = Fetcher(root=tmp_path, session=s)  # type: ignore[arg-type]
    assert f.text("https://x/a") == "hello" and f.text("https://x/a") == "hello"
    assert f.bytes("https://x/missing") is None and f.bytes("https://x/missing") is None
    assert s.calls == 2 and f.requests_made == 2  # the second reads of each cost nothing
    assert Fetcher(root=tmp_path, offline=True).text("https://x/a") == "hello"  # survives restarts
    assert Fetcher(root=tmp_path / "other", offline=True).text("https://x/a") is None


def test_rate_limits_are_waited_out_then_retried(tmp_path: Path, monkeypatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", slept.append)
    s = Session([Resp(429, headers={"Retry-After": "3"}), Resp(503), Resp(200, b'{"a": 1}')])
    f = Fetcher(root=tmp_path, session=s)  # type: ignore[arg-type]
    assert f.json("https://x/j") == {"a": 1}
    assert slept == [3.0, 4.0] and s.calls == 3


def test_oversized_bodies_are_refused_and_remembered(tmp_path: Path) -> None:
    s = Session([Resp(200, b"x" * 50)])
    f = Fetcher(root=tmp_path, session=s, max_bytes=10)  # type: ignore[arg-type]
    assert f.bytes("https://x/big") is None and f.bytes("https://x/big") is None
    assert s.calls == 1


def _tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class NpmFetcher:
    """Serves a registry packument and a tarball without a network."""

    def __init__(self):
        self.tar = _tgz(
            {
                "lib/a.js": "exports.f = function(x){ return x };",
                "test/a.test.js": "x",
                "lib/a.min.js": "x",
                "README.md": "x",
            }
        )

    def json(self, url: str):
        if url.endswith("/pkg"):
            return {"versions": {"1.0.0": {}, "1.1.0": {}, "2.0.0-beta.1": {}}}
        return {"dist": {"tarball": "https://r/pkg.tgz"}, "main": "./lib/a.js"}

    def bytes(self, url: str):
        return self.tar

    def memo(self, key, make, size: int = 48):
        return make()


def test_npm_release_keeps_only_shipped_non_test_javascript() -> None:
    f = NpmFetcher()
    assert npm_versions(f, "pkg") == ["1.0.0", "1.1.0"]  # type: ignore[arg-type]  # prereleases skipped
    rel = npm_release(f, "pkg", "1.1.0")  # type: ignore[arg-type]
    assert rel is not None and sorted(rel.files) == ["lib/a.js"] and rel.main == "lib/a.js"
    assert rel.module_of("lib/a.js") == "pkg/lib/a"
    if available():
        assert [(m, fn.qualname) for m, _, fn in rel.functions()] == [("pkg/lib/a", "f")]


def test_npm_release_unavailable_when_the_registry_has_no_tarball() -> None:
    class Bare(NpmFetcher):
        def json(self, url: str):
            return None

    assert npm_release(Bare(), "pkg", "1.0.0") is None  # type: ignore[arg-type]


def test_select_ranks_by_package_popularity(tmp_path: Path) -> None:
    import sys
    import zipfile

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "symbols"))
    import build_dataset as b

    def rec(i: str, pkg: str, published: str) -> dict:
        return {
            "id": i,
            "published": published,
            "references": [{"type": "FIX", "url": "https://github.com/o/r/commit/abcdef1234567"}],
            "affected": [{"package": {"ecosystem": "PyPI", "name": pkg}}],
        }

    zp = tmp_path / "pypi.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for r in [
            rec("A1", "Rare_Pkg", "2026"),
            rec("B1", "popular-pkg", "2020"),
            rec("B2", "popular-pkg", "2021"),
        ]:
            z.writestr(r["id"] + ".json", json.dumps(r))
        z.writestr("MAL-1.json", json.dumps({**rec("MAL-1", "popular-pkg", "2026")}))

    def ranker(fetcher, top, cands):
        return {"popular-pkg": 1}

    chosen, rank = b.select(zp, "pypi", 10, 0, ranker, 5, object())  # type: ignore[arg-type]
    assert [r["id"] for r, _ in chosen] == ["B2", "B1"]  # only the popular package, newest first
    assert rank == {"popular-pkg": 1}
    newest, _ = b.select(zp, "pypi", 10, 0)
    assert [r["id"] for r, _ in newest] == [
        "A1",
        "B2",
        "B1",
    ]  # no ranking: newest first, MAL skipped
    assert b.norm("Rare_Pkg") == "rare-pkg"
    pytest.importorskip("scgraph")
