"""More input formats: each parser turns one file's text into a ``DepGraph``.

``lockfiles.parse`` looks a file name up in ``PARSERS`` after its own formats, so adding a
format is one function here plus its name in ``lockfiles.LOCKFILE_NAMES``. Parsers take the
path (for the graph's label and sibling files) and the text, and must not read anything
else: ``scgraph diff`` parses a file from git history through the same entry point.
"""

from __future__ import annotations

import json
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


# ------------------------------------------------------------------------------ bun
def _loads_jsonc(text: str):
    """JSON with ``//`` and ``/* */`` comments and trailing commas, as Bun writes it."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            i = text.find("\n", i)
            i = n if i < 0 else i - 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 1
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(c)
        else:
            out.append(c)
        i += 1
    return json.loads("".join(out))


def _bun_segments(prefix: str) -> list[str]:
    """``a/@s/b/`` -> ``['a', '@s/b']``: package names, where a scope is one name."""
    parts = [p for p in prefix.split("/") if p]
    out: list[str] = []
    k = 0
    while k < len(parts):
        if parts[k].startswith("@") and k + 1 < len(parts):
            out.append(f"{parts[k]}/{parts[k + 1]}")
            k += 2
        else:
            out.append(parts[k])
            k += 1
    return out


@_register("bun.lock")
def _parse_bun(path: Path, text: str) -> DepGraph:
    doc = _loads_jsonc(text)
    g = DepGraph(str(path), "bun.lock", "npm")
    pk = doc.get("packages") or {}
    nodes: dict[str, tuple[int, dict]] = {}  # key -> (package index, metadata)
    for key, arr in pk.items():
        if not (isinstance(arr, list) and arr and isinstance(arr[0], str)):
            continue
        name, _, ver = arr[0].rpartition("@")
        if not name:
            continue
        meta = arr[2] if len(arr) > 2 and isinstance(arr[2], dict) else {}
        # workspace members and link/file/git packages are expanded through, never reported
        nodes[key] = (g.add(name, ver, local=not ver[:1].isdigit()), meta)

    def lookup(owner_key: str, dep: str) -> int | None:
        """Node-style: the owner's own nested copy first (``express/qs``), then each
        enclosing key outward, then the hoisted top-level copy."""
        segs = _bun_segments(owner_key)
        for upto in range(len(segs), -1, -1):
            head = "/".join(segs[:upto])
            hit = nodes.get(f"{head}/{dep}" if head else dep)
            if hit:
                return hit[0]
        return None

    for key, (i, meta) in nodes.items():
        for field in ("dependencies", "optionalDependencies"):
            for dep in meta.get(field) or {}:
                j = lookup(key, dep)
                if j is not None:
                    g.edges.add((i, j))
    for ws in (doc.get("workspaces") or {}).values():
        for field, scope in (
            ("dependencies", "prod"),
            ("optionalDependencies", "prod"),
            ("devDependencies", "dev"),
        ):
            for dep in (ws or {}).get(field) or {}:
                j = lookup("", dep)
                if j is not None:
                    g.add_direct(j, scope)
    return g
