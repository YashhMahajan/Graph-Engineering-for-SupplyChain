"""npm: released source from the registry, and the names a project uses to reach a function.

A project reaches an npm package through its *export names*: ``require('lodash').template``,
``import {template} from 'lodash'``, or a deep path ``require('lodash/template')``. A module is
named ``<package>/<path without extension>`` (``lodash/lib/template``), so the same string is
both the module id and the deep import specifier. Names the main entry exports (directly or
through re-exports) also get the short form ``lodash.template``.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
from urllib.parse import quote

from ..versions import sort_versions
from .candidates import is_test_path
from .fetch import Fetcher
from .js import parse_js
from .source import MAX_FILE_BYTES, MAX_FILES, Release

__all__ = ["main_exports", "npm_names", "npm_release", "npm_versions"]

REGISTRY = "https://registry.npmjs.org"
_JS = (".js", ".mjs", ".cjs")


def _doc_url(name: str) -> str:
    return f"{REGISTRY}/{quote(name, safe='@')}"


def npm_versions(f: Fetcher, name: str) -> list[str]:
    d = f.json(_doc_url(name))
    if not d:
        return []
    return sort_versions([v for v in (d.get("versions") or {}) if "-" not in v], "npm")


def _main_of(doc: dict) -> str:
    m = doc.get("main")
    if isinstance(m, str) and m:
        return m
    ex = doc.get("exports")
    if isinstance(ex, str):
        return ex
    if isinstance(ex, dict):
        dot = ex.get(".", ex)
        if isinstance(dot, str):
            return dot
        if isinstance(dot, dict):
            for k in ("require", "node", "default", "import"):
                v = dot.get(k)
                if isinstance(v, str):
                    return v
    return "index.js"


def npm_release(f: Fetcher, name: str, version: str) -> Release | None:
    return f.memo(("npm", name, version), lambda: _npm_release(f, name, version))


def _npm_release(f: Fetcher, name: str, version: str) -> Release | None:
    doc = f.json(f"{_doc_url(name)}/{version}")
    if not doc or not isinstance(doc, dict):
        return None
    url = (doc.get("dist") or {}).get("tarball")
    blob = f.bytes(url) if url else None
    if blob is None:
        return None
    files: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            for m in t.getmembers():
                if not m.isfile() or m.size > MAX_FILE_BYTES:
                    continue
                p = m.name.split("/", 1)[1] if "/" in m.name else m.name
                if not p.endswith(_JS) or is_test_path(p):
                    continue
                fh = t.extractfile(m)
                if fh is not None:
                    files[p] = fh.read().decode("utf-8", errors="replace")
                if len(files) >= MAX_FILES:
                    break
    except (tarfile.TarError, OSError, EOFError):
        return None
    rel = Release("npm", name, version, files)
    rel.main = posixpath.normpath(_main_of(doc)).lstrip("./") or "index.js"
    return rel


def _resolve(release: Release, from_mod: str, spec: str) -> str | None:
    """A relative specifier inside the package -> the module id of the file it names."""
    base = posixpath.dirname(from_mod)
    target = posixpath.normpath(posixpath.join(base, spec))
    for cand in (target, f"{target}/index"):
        if any(release.module_of(p) == cand for p in release.files):
            return cand
    return None


def _exports(
    release: Release, by_mod: dict[str, str], mod: str, seen: set[str]
) -> dict[str, tuple[str, str]]:
    """export name -> (module, local qualname) for ``mod``, re-exports followed."""
    if mod in seen or mod not in by_mod:
        return {}
    seen = seen | {mod}
    pf = parse_js(release.files[by_mod[mod]])
    out: dict[str, tuple[str, str]] = {n: (mod, local) for n, local in pf.exports.items()}
    for spec, names in pf.reexports:
        if not spec.startswith("."):
            continue
        tgt = _resolve(release, mod, spec)
        if tgt is None:
            continue
        sub = _exports(release, by_mod, tgt, seen)
        if names is None:
            out.update({n: v for n, v in sub.items() if n != "default"})
        else:
            for orig, alias in names:
                if orig in sub:
                    out[alias] = sub[orig]
    return out


def main_exports(release: Release) -> dict[str, tuple[str, str]]:
    """What ``require('<package>')`` exposes: name -> (module, local qualname)."""
    by_mod = {release.module_of(p): p for p in release.files}
    main = release.main or "index.js"
    stem = posixpath.splitext(main)[0]
    for cand in (stem, f"{stem}/index", "index"):
        mod = f"{release.package}/{cand}"
        if mod in by_mod:
            return _exports(release, by_mod, mod, set())
    return {}


def npm_names(release: Release, pairs: list[tuple[str, str]]) -> list[str]:
    """Names project code uses to reach each (module, qualname): short main-entry names and
    deep import names. A method ``C.m`` is reached as ``<name of C>.m``."""
    by_mod = {release.module_of(p): p for p in release.files}
    main = main_exports(release)
    out: list[str] = []

    def add(n: str) -> None:
        if n not in out:
            out.append(n)

    for mod, qn in pairs:
        if qn == "<module>":
            continue
        owner, _, method = qn.rpartition(".")
        local = owner or qn
        names_here = [
            n for n, v in _exports(release, by_mod, mod, set()).items() if v == (mod, local)
        ]
        names_main = [n for n, v in main.items() if v == (mod, local)]
        for n in names_here:
            deep = mod if n == "default" else f"{mod}.{n}"
            tail = f".{method}" if owner else ""
            add(deep + tail)
            if mod.endswith("/index"):
                add(
                    (mod[: -len("/index")] if n == "default" else f"{mod[: -len('/index')]}.{n}")
                    + tail
                )
        for n in names_main:
            base = release.package if n == "default" else f"{release.package}.{n}"
            add(base + (f".{method}" if owner else ""))
    return out
