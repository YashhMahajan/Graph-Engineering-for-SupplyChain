"""Entry points: the public functions of a release that reach the vulnerable function.

A user rarely calls the patched helper itself; they call the public API above it. For
``rebuild_proxies`` in requests that is ``requests.get``, ``Session.request`` and the rest.
Reachability needs those names, because they are what project code references.

The call graph is name-based and built from released source only: a function calls ``f`` if
its body has a call whose last segment is ``f``. A caller outside the target's own module
(Python) or package (Go) is kept only when its file imports that module or package, and very
common names (``get``, ``run``, ``read``) are followed only inside the target's own module.
This over-approximates dynamic dispatch and under-approximates calls through variables; the
evaluation measures how the resulting symbol set compares with the Go database's labels.

For Python, names a package re-exports (``from .api import get`` in ``requests/__init__.py``)
are added as aliases, so ``requests.api.get`` also matches code that writes ``requests.get``.
"""

from __future__ import annotations

import ast
import re
from collections import deque

from .source import Release

__all__ = ["aliases", "entry_points"]

_COMMON = frozenset(
    [
        "get",
        "set",
        "run",
        "call",
        "read",
        "write",
        "close",
        "open",
        "update",
        "items",
        "keys",
        "values",
        "append",
        "extend",
        "pop",
        "format",
        "join",
        "split",
        "strip",
        "encode",
        "decode",
        "copy",
        "load",
        "dump",
        "send",
        "start",
        "stop",
        "init",
        "new",
        "add",
        "remove",
        "delete",
        "next",
        "len",
        "str",
        "int",
        "list",
        "dict",
        "Error",
        "String",
        "Close",
        "Read",
        "Write",
        "Get",
        "Set",
        "New",
        "Run",
        "Do",
        "Add",
        "Len",
        "Reset",
    ]
)


def _imports_target(text: str, target_module: str, lang: str) -> bool:
    if lang == "go":
        return f'"{target_module}"' in text
    leaf = target_module.rsplit(".", 1)[-1]
    return re.search(rf"^\s*(from|import)\s+[\w.]*\b{re.escape(leaf)}\b", text, re.M) is not None


def _imports_name(text: str, target_module: str, name: str) -> bool:
    """``from .loader import load`` / ``from yaml.loader import load``: an exact binding."""
    leaf = re.escape(target_module.rsplit(".", 1)[-1])
    pat = rf"^\s*from\s+(?:\.+|[\w.]*\.)?{leaf}\s+import\s+[^\n]*\b{re.escape(name)}\b"
    return re.search(pat, text, re.M) is not None


def entry_points(
    release: Release, module: str, qualname: str, depth: int = 5, cap: int = 60
) -> list[tuple[str, str]]:
    """(module, qualname) of public functions within ``depth`` calls of the target,
    nearest first. The target itself comes first when it is public."""
    funcs = release.functions()
    by_name: dict[str, list[tuple[str, str, object]]] = {}
    for mod, path, f in funcs:
        for c in f.calls:
            by_name.setdefault(c, []).append((mod, path, f))
    target = release.find(module, qualname)
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = {(module, qualname)}
    if target is not None and target.public:
        out.append((module, qualname))
    q: deque[tuple[str, str, int]] = deque([(module, qualname, 0)])
    while q and len(out) < cap:
        mod, qn, d = q.popleft()
        if d >= depth:
            continue
        name = qn.rsplit(".", 1)[-1]
        for cmod, cpath, cf in by_name.get(name, []):
            key = (cmod, cf.qualname)  # type: ignore[attr-defined]
            if key in seen:
                continue
            same = cmod == mod
            text = release.files.get(cpath, "")
            exact = release.lang == "python" and _imports_name(text, mod, name)
            if (
                not same
                and not exact
                and (
                    name in _COMMON
                    or len(name) <= 3
                    or not _imports_target(text, mod, release.lang)
                )
            ):
                continue
            seen.add(key)
            if cf.public:  # type: ignore[attr-defined]
                out.append(key)
                if len(out) >= cap:
                    break
            q.append((cmod, cf.qualname, d + 1))  # type: ignore[attr-defined]
    return out


def aliases(release: Release) -> dict[str, set[str]]:
    """``{"requests.api": {"requests"}, "requests.sessions.Session": {"requests.Session"}}``:
    module or object paths a package ``__init__`` re-exports under a shorter name."""
    if release.lang != "python":
        return {}
    out: dict[str, set[str]] = {}
    for path, text in release.files.items():
        if not path.endswith("__init__.py"):
            continue
        pkg = release.module_of(path)
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for n in tree.body:
            if not isinstance(n, ast.ImportFrom):
                continue
            if n.level == 1:
                src = f"{pkg}.{n.module}" if n.module else pkg
            elif n.level == 0 and n.module and n.module.startswith(pkg.split(".")[0]):
                src = n.module
            else:
                continue
            for a in n.names:
                if a.name == "*":
                    out.setdefault(src, set()).add(pkg)
                    continue
                out.setdefault(f"{src}.{a.name}", set()).add(f"{pkg}.{a.asname or a.name}")
    return out


def dotted_names(release: Release, pairs: list[tuple[str, str]]) -> list[str]:
    """Dotted names for (module, qualname) pairs, re-export aliases included (Python)."""
    al = aliases(release)
    out: list[str] = []
    for mod, qn in pairs:
        full = f"{mod}.{qn}"
        names = [full]
        for src, dsts in al.items():
            if full == src or full.startswith(src + "."):
                rest = full[len(src) :]
                names.extend(d + rest for d in dsts)
        for n in names:
            if n not in out:
                out.append(n)
    return out
