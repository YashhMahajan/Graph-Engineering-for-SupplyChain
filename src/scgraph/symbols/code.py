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

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def dunder(self) -> bool:
        return self.name.startswith("__") and self.name.endswith("__")


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


def _py_hash(node: ast.AST) -> str:
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()[:16]


def py_functions(source: str) -> list[Func]:
    """Every module-level function and every method of a class reachable from module level."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
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


def functions(source: str, lang: str) -> list[Func]:
    if lang == "python":
        return py_functions(source)
    if lang == "go":
        return go_functions(source)
    raise ValueError(f"unsupported language: {lang}")
