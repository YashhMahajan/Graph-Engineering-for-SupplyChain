"""Function spans for Python and Go source, with the facts the ranker and verifier use.

Python uses the standard ``ast`` module. Go uses a line scanner that relies on ``gofmt``:
every top-level declaration starts at column 0 with ``func`` and its body closes with a
``}`` at column 0. Published Go modules are gofmt'd almost without exception, and a file that
is not simply yields fewer functions (the candidate is then missed, never invented).

A ``Func`` is a *callable from outside*: module-level functions and methods of module-level
(or nested) classes for Python, functions and methods for Go. A function defined inside
another function cannot be called by a user of the package, so its lines belong to the
enclosing function.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass

__all__ = [
    "Func",
    "enclosing",
    "functions",
    "go_functions",
    "identifier_tokens",
    "py_functions",
]


@dataclass(frozen=True)
class Func:
    qualname: str  # "Class.method" / "func" (Python), "Type.Method" / "Func" (Go)
    start: int  # first line, decorators included (1-based)
    end: int  # last line
    public: bool
    is_method: bool
    doc: str
    calls: frozenset[str]  # bare names this function calls (last segment of a.b.c())
    body_hash: str  # changes whenever the body changes, not on a pure move
    signature: str
    # Python call-graph facts (empty for Go): what a name-based graph needs beyond ``calls``
    is_property: bool = False  # @property / cached_property / setter: runs on attribute access
    dyn: tuple[str, ...] = ()  # literal prefixes of getattr(self, "visit_" + x) dispatches
    loads: frozenset[str] = frozenset()  # bare names read as values (callbacks, properties)
    refs: frozenset[str] = frozenset()  # dotted names resolved through imports (pkg.mod.f)

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def dunder(self) -> bool:
        return self.name.startswith("__") and self.name.endswith("__")

    @property
    def implicit(self) -> bool:
        """Runs through syntax or attribute access, never through ``name(...)``."""
        return self.dunder or self.is_property

    @property
    def owner(self) -> str:
        """The class a method belongs to ("" for a function)."""
        return self.qualname.rsplit(".", 1)[0] if self.is_method else ""


def enclosing(funcs: list[Func], line: int) -> Func | None:
    """The innermost function whose span holds ``line``."""
    best: Func | None = None
    for f in funcs:
        if f.start <= line <= f.end and (best is None or f.end - f.start < best.end - best.start):
            best = f
    return best


_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def identifier_tokens(s: str) -> list[str]:
    """``rebuild_proxies`` -> rebuild, proxies; ``ParseHTTPVersion`` -> parse, http, version."""
    out: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", s):
        out.extend(t.lower() for t in _CAMEL.findall(part))
    return out


# ----------------------------------------------------------------------------- Python


def _calls(node: ast.AST) -> frozenset[str]:
    names: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                names.add(f.id)
            elif isinstance(f, ast.Attribute):
                names.add(f.attr)
    return frozenset(names)


def _alias_map(tree: ast.AST) -> dict[str, str]:
    """Local name -> absolute dotted name for every import in the file."""
    alias: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                alias[a.asname or a.name.split(".")[0]] = (
                    a.name if a.asname else a.name.split(".")[0]
                )
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            for a in n.names:
                if a.name != "*":
                    alias[a.asname or a.name] = f"{n.module}.{a.name}"
    return alias


def _chain(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return parts[::-1]
    return None


def _loads_refs(node: ast.AST, alias: dict[str, str]) -> tuple[frozenset[str], frozenset[str]]:
    loads: set[str] = set()
    refs: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute | ast.Name) and isinstance(
            getattr(n, "ctx", None), ast.Load
        ):
            loads.add(n.attr if isinstance(n, ast.Attribute) else n.id)
            chain = _chain(n)
            if chain and chain[0] in alias:
                refs.add(".".join([alias[chain[0]], *chain[1:]]))
    return frozenset(loads), frozenset(refs)


def _const_prefix(node: ast.AST) -> str:
    """The literal start of a dynamic string: "visit_" in "visit_" + x, f"visit_{x}" or
    "visit_{}".format(x)."""
    if isinstance(node, ast.JoinedStr) and node.values:
        v = node.values[0]
        return v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        left = node.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            return left.value.split("%")[0]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    ):
        return node.func.value.value.split("{")[0]
    return ""


def _dyn_prefixes(node: ast.AST) -> tuple[str, ...]:
    out: set[str] = set()
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "getattr"
            and len(n.args) >= 2
        ):
            pre = _const_prefix(n.args[1])
            if len(pre) >= 3:
                out.add(pre)
    return tuple(sorted(out))


_PROPERTY = {"property", "cached_property", "setter", "getter", "deleter", "classproperty"}


def _is_property(n: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in n.decorator_list:
        name = d.attr if isinstance(d, ast.Attribute) else d.id if isinstance(d, ast.Name) else ""
        if name in _PROPERTY:
            return True
    return False


def _py_hash(node: ast.AST) -> str:
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()[:16]


MODULE_LEVEL = "<module>"


def py_functions(source: str, with_module: bool = False) -> list[Func]:
    """Every module-level function and every method of a class reachable from module level.
    With ``with_module``, a pseudo-function ``<module>`` is appended that stands for the code
    that runs when the file is imported (top-level statements and class bodies)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    alias = _alias_map(tree)
    out: list[Func] = []

    def visit(body: list[ast.stmt], prefix: str, in_class: bool) -> None:
        for n in body:
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                q = f"{prefix}{n.name}"
                start = min([n.lineno, *(d.lineno for d in n.decorator_list)])
                parts = q.split(".")
                public = all(
                    not p.startswith("_") or (p.startswith("__") and p.endswith("__"))
                    for p in parts
                )
                args = [a.arg for a in n.args.args]
                loads, refs = _loads_refs(n, alias)
                out.append(
                    Func(
                        qualname=q,
                        start=start,
                        end=n.end_lineno or n.lineno,
                        public=public,
                        is_method=in_class,
                        doc=(ast.get_docstring(n) or "")[:400],
                        calls=_calls(n),
                        body_hash=_py_hash(n),
                        signature=f"def {n.name}({', '.join(args)})",
                        is_property=_is_property(n),
                        dyn=_dyn_prefixes(n),
                        loads=loads,
                        refs=refs,
                    )
                )
            elif isinstance(n, ast.ClassDef):
                visit(n.body, f"{prefix}{n.name}.", True)
            elif isinstance(n, ast.If | ast.Try):  # `if sys.version_info...: def f()`
                visit(n.body, prefix, in_class)
                visit(n.orelse, prefix, in_class)
                if isinstance(n, ast.Try):
                    for h in n.handlers:
                        visit(h.body, prefix, in_class)
                    visit(n.finalbody, prefix, in_class)

    visit(tree.body, "", False)
    if with_module:
        top = ast.Module(
            body=[
                n for n in tree.body if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
            ],
            type_ignores=[],
        )
        loads, refs = _loads_refs(top, alias)
        out.append(
            Func(
                qualname=MODULE_LEVEL,
                start=1,
                end=0,  # never encloses a diff line
                public=True,
                is_method=False,
                doc="",
                calls=_calls(top),
                body_hash=_py_hash(top),
                signature=MODULE_LEVEL,
                dyn=_dyn_prefixes(top),
                loads=loads,
                refs=refs,
            )
        )
    return out


# ----------------------------------------------------------------------------- Go

_GO_FUNC = re.compile(
    r"^func\s*"
    r"(?:\(\s*(?:[A-Za-z_]\w*\s+)?\*?\s*([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*\)\s*)?"
    r"([A-Za-z_]\w*)"
)
_GO_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\])?\(")
_GO_KEYWORDS = frozenset(
    [
        "if",
        "for",
        "switch",
        "return",
        "func",
        "go",
        "defer",
        "select",
        "case",
        "range",
        "make",
        "new",
        "len",
        "cap",
        "append",
        "panic",
        "recover",
        "copy",
        "delete",
        "close",
        "print",
        "println",
        "string",
        "int",
        "byte",
        "rune",
        "error",
        "map",
        "chan",
        "struct",
        "interface",
    ]
)
_GO_COMMENT = re.compile(r"//.*$")


def go_functions(source: str) -> list[Func]:
    """Top-level ``func`` declarations of gofmt'd Go source."""
    lines = source.splitlines()
    out: list[Func] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _GO_FUNC.match(lines[i])
        if not m:
            i += 1
            continue
        recv, name = m.group(1), m.group(2)
        start = i + 1
        j = i
        head = lines[i].rstrip()
        if head.endswith("}") and head.count("{") == head.count("}") and "{" in head:
            end = i + 1  # one-line body
        elif not head.endswith("{") and "{" not in head and not head.endswith(","):
            end = i + 1  # declaration without body (assembly stub)
        else:
            j = i + 1
            while j < n and not lines[j].startswith("}"):
                j += 1
            end = min(j + 1, n)
        doc_lines: list[str] = []
        k = i - 1
        while k >= 0 and lines[k].startswith("//"):
            doc_lines.append(lines[k][2:].strip())
            k -= 1
        body = "\n".join(lines[i:end])
        code_only = "\n".join(_GO_COMMENT.sub("", ln) for ln in lines[i + 1 : end])
        calls = frozenset(
            c for c in _GO_CALL.findall(code_only) if c not in _GO_KEYWORDS and c != name
        )
        public = name[:1].isupper() and (recv is None or recv[:1].isupper())
        out.append(
            Func(
                qualname=f"{recv}.{name}" if recv else name,
                start=start,
                end=end,
                public=public,
                is_method=recv is not None,
                doc=" ".join(reversed(doc_lines))[:400],
                calls=calls,
                body_hash=hashlib.sha256(" ".join(body.split()).encode()).hexdigest()[:16],
                signature=head.rstrip("{ ").strip(),
            )
        )
        i = max(end, i + 1)
    return out


def functions(source: str, lang: str, with_module: bool = False, path: str = "") -> list[Func]:
    if lang == "python":
        return py_functions(source, with_module)
    if lang == "javascript":
        from .js import js_functions

        return js_functions(source, with_module, ts=path.endswith((".ts", ".mts", ".cts")))
    if lang == "go":
        return go_functions(source)
    raise ValueError(f"unsupported language: {lang}")
