"""More input formats: each parser turns one file's text into a ``DepGraph``.

``lockfiles.parse`` looks a file name up in ``PARSERS`` after its own formats, so adding a
format is one function here plus its name in ``lockfiles.LOCKFILE_NAMES``. Parsers take the
path (for the graph's label and sibling files) and the text, and must not read anything
else: ``scgraph diff`` parses a file from git history through the same entry point.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .lockfiles import DepGraph

__all__ = ["PARSERS"]

PARSERS: dict[str, Callable[[Path, str], DepGraph]] = {}


def _register(name: str):
    def deco(fn: Callable[[Path, str], DepGraph]):
        PARSERS[name] = fn
        return fn

    return deco


# ------------------------------------------------------------------------- mini YAML
def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def _split_flow(body: str) -> list[str]:
    """Split ``a: b, c: {d: e}`` at top-level commas, respecting quotes and braces."""
    parts, depth, quote, cur = [], 0, "", []
    for ch in body:
        if quote:
            cur.append(ch)
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch in "{[":
            depth += 1
            cur.append(ch)
        elif ch in "}]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _scalar(v: str):
    v = v.strip()
    if v.startswith("{") and v.endswith("}"):
        out = {}
        for part in _split_flow(v[1:-1]):
            k, sep, val = part.partition(":")
            if sep:
                out[_unquote(k)] = _scalar(val)
        return out
    return _unquote(v)


def _split_kv(s: str) -> tuple[str, str]:
    if s[0] in "'\"":
        end = s.index(s[0], 1)
        rest = s[end + 1 :].lstrip()
        return s[1:end], rest[1:].strip() if rest.startswith(":") else ""
    if s.endswith(":") and ": " not in s:
        return s[:-1], ""
    key, _, val = s.partition(": ")
    return key, val.strip()


def _yaml_map(text: str) -> dict:
    """The mapping subset of YAML that package-manager lockfiles use: nested maps by
    indentation, quoted keys, and flow maps. List items and comments are skipped."""
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.lstrip(" ")
        if not s or s.startswith(("#", "- ")):
            continue
        indent = len(line) - len(s)
        key, val = _split_kv(s)
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if val == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _scalar(val)
    return root


# ----------------------------------------------------------------------------- pnpm
def _pnpm_key(key: str) -> tuple[str, str, str]:
    """``/name@1.0.0(peer@2)`` or ``name@1.0.0`` -> (name, version, version with peers)."""
    k = key.lstrip("/")
    base = k.split("(", 1)[0]
    at = base.rfind("@")
    if at <= 0:
        raise ValueError(f"unrecognised pnpm package key: {key!r}")
    return base[:at], base[at + 1 :], k[at + 1 :]


@_register("pnpm-lock.yaml")
def _parse_pnpm(path: Path, text: str) -> DepGraph:
    doc = _yaml_map(text)
    try:
        major = int(float(str(doc.get("lockfileVersion", "0")).strip("'\"")))
    except ValueError:
        major = 0
    if major < 6:
        raise ValueError(
            f"pnpm lockfileVersion {doc.get('lockfileVersion')!r} is not supported "
            "(pnpm 8 and 9 write version 6 or later; run pnpm install to upgrade it)"
        )
    g = DepGraph(str(path), "pnpm-lock.yaml", "npm")
    snaps = doc.get("snapshots")
    table = snaps if isinstance(snaps, dict) else doc.get("packages") or {}
    index: dict[tuple[str, str], int] = {}
    entries: list[tuple[int, dict]] = []
    for key, ent in table.items():
        name, ver, full = _pnpm_key(key)
        i = g.add(name, ver)
        index[(name, full)] = i
        entries.append((i, ent if isinstance(ent, dict) else {}))

    def resolve(name: str, value: str) -> int | None:
        if value.startswith(("link:", "file:", "workspace:")):
            return None
        if value[:1].isdigit():  # a plain version, possibly with a peer suffix
            return index.get((name, value))
        # An alias: the value names the real package (``left-pad@1.3.0``, pnpm 9; older
        # lockfiles write ``/left-pad@1.3.0`` or ``npm:left-pad@1.3.0``).
        real, _, full = _pnpm_key(value.removeprefix("npm:"))
        return index.get((real, full))

    for i, ent in entries:
        for field in ("dependencies", "optionalDependencies"):
            for dn, dv in (ent.get(field) or {}).items():
                j = resolve(dn, dv) if isinstance(dv, str) else None
                if j is not None:
                    g.edges.add((i, j))
    importers = doc.get("importers")
    for imp in importers.values() if isinstance(importers, dict) else [doc]:
        for field, scope in (
            ("dependencies", "prod"),
            ("optionalDependencies", "prod"),
            ("devDependencies", "dev"),
        ):
            for dn, dv in ((imp or {}).get(field) or {}).items():
                version = dv.get("version") if isinstance(dv, dict) else dv
                j = resolve(dn, version) if isinstance(version, str) else None
                if j is not None:
                    g.add_direct(j, scope)
    return g
