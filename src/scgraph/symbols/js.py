"""JavaScript source facts via tree-sitter: functions, exports and the call graph's inputs.

Needs the optional ``tree-sitter`` and ``tree-sitter-javascript`` packages
(``pip install scgraph-cli[symbols-js]``). Without them ``available()`` is False and npm
inference reports that, instead of failing.

JavaScript has no visibility keyword, so *public* means **exported**: a function is public when
its module exports it (CommonJS ``exports.f = ``, ``module.exports = {f}``, ``module.exports = f``;
ES ``export function f``, ``export {f as g}``, ``export default f``) or when it is a method of an
exported class. A project reaches a package through those export names, which is exactly what
reachability needs.

Only functions a user of the package could call are listed: top-level declarations, class
methods, and functions assigned to variables or exports (also inside a top-level IIFE, the shape
of UMD bundles). A function defined inside another function belongs to the outer one.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .code import Func

__all__ = [
    "JSFile",
    "available",
    "js_functions",
    "parse_js",
    "referenced_names_js",
    "ts_available",
]

try:  # optional dependency
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language as _Language
    from tree_sitter import Parser as _Parser

    _PARSER: Any = _Parser(_Language(_tsjs.language()))
except Exception:  # pragma: no cover - exercised only without the extra
    _PARSER = None

try:  # TypeScript sources of a fix (released packages ship compiled JavaScript)
    import tree_sitter_typescript as _tsts

    _TS_PARSER: Any = _Parser(_Language(_tsts.language_typescript()))
except Exception:  # pragma: no cover
    _TS_PARSER = None


def available() -> bool:
    return _PARSER is not None


def ts_available() -> bool:
    return _TS_PARSER is not None


def _parser(ts: bool) -> Any:
    return _TS_PARSER if ts else _PARSER


_FUNC_TYPES = {"arrow_function", "function_expression", "function", "generator_function"}
_CLASS_DECLS = {"class_declaration", "abstract_class_declaration"}
_WRAPPERS = {
    "parenthesized_expression",
    "unary_expression",
    "as_expression",
    "non_null_expression",
    "satisfies_expression",
    "type_assertion",
}
_DECL_TYPES = {"function_declaration", "generator_function_declaration"}
_STR = re.compile(r"""^['"`](.*)['"`]$""", re.S)


def _text(n: Any) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def _str(n: Any) -> str:
    m = _STR.match(_text(n).strip())
    return m.group(1) if m else ""


@dataclass
class JSFile:
    functions: list[Func] = field(default_factory=list)
    exports: dict[str, str] = field(default_factory=dict)  # export name -> local qualname
    reexports: list[tuple[str, list[tuple[str, str]] | None]] = field(default_factory=list)
    # (specifier, [(name in the other module, name exported here)] or None for "everything")


def spec_of_require(call: Any) -> str:
    """``p`` for ``require('p')`` when ``p`` names a package (not a relative path)."""
    if call is not None and call.type == "call_expression":
        fn = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        if fn is not None and _text(fn) == "require" and args is not None and args.named_children:
            s = _str(args.named_children[0])
            return s if s and not s.startswith(".") else ""
    return ""


def _alias_map(root: Any) -> dict[str, str]:
    """Local name -> absolute specifier path: ``const x = require('p')``, ``const {a: b} =
    require('p')``, ``import x, {a as b} from 'p'``, ``import * as ns from 'p'``."""
    alias: dict[str, str] = {}

    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            spec = spec_of_require(value)
            if not spec and value is not None and value.type == "member_expression":
                inner = value.child_by_field_name("object")  # require('p').member
                prop = value.child_by_field_name("property")
                spec = spec_of_require(inner)
                if spec and name is not None and name.type == "identifier":
                    alias[_text(name)] = f"{spec}.{_text(prop)}"
                    continue
                spec = ""
            if not spec or name is None:
                continue
            if name.type == "identifier":
                alias[_text(name)] = spec
            elif name.type == "object_pattern":
                for c in name.named_children:
                    if c.type == "shorthand_property_identifier_pattern":
                        alias[_text(c)] = f"{spec}.{_text(c)}"
                    elif c.type == "pair_pattern":
                        k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                        if v is not None and v.type == "identifier":
                            alias[_text(v)] = f"{spec}.{_text(k)}"
        elif n.type == "import_statement":
            src = _str(n.child_by_field_name("source"))
            if not src or src.startswith("."):
                continue
            for c in n.children:
                if c.type != "import_clause":
                    continue
                for x in c.children:
                    if x.type == "identifier":
                        alias[_text(x)] = src
                    elif x.type == "namespace_import":
                        ids = [y for y in x.children if y.type == "identifier"]
                        if ids:
                            alias[_text(ids[0])] = src
                    elif x.type == "named_imports":
                        for sp in x.named_children:
                            nm, al = sp.child_by_field_name("name"), sp.child_by_field_name("alias")
                            alias[_text(al or nm)] = f"{src}.{_text(nm)}"
    return alias


def _chain(n: Any) -> list[str] | None:
    parts: list[str] = []
    while n is not None and n.type == "member_expression":
        prop = n.child_by_field_name("property")
        parts.append(_text(prop))
        n = n.child_by_field_name("object")
    if n is not None and n.type == "identifier":
        parts.append(_text(n))
        return parts[::-1]
    return None


def _const_prefix(n: Any) -> str:
    """Literal start of a dynamic member name: ``visit`` in x[`visit${n}`] or x["visit" + n]."""
    if n is None:
        return ""
    if n.type == "template_string":
        for c in n.children:
            if c.type == "string_fragment":
                return _text(c)
            if c.type == "template_substitution":
                return ""
        return ""
    if n.type == "binary_expression" and _text(n.child_by_field_name("operator")) == "+":
        left = n.child_by_field_name("left")
        return _str(left) if left is not None and left.type == "string" else ""
    return ""


def _facts(
    node: Any, alias: dict[str, str]
) -> tuple[frozenset[str], frozenset[str], frozenset[str], tuple[str, ...]]:
    calls: set[str] = set()
    loads: set[str] = set()
    refs: set[str] = set()
    dyn: set[str] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        t = n.type
        if t in ("call_expression", "new_expression"):
            fn = n.child_by_field_name("function" if t == "call_expression" else "constructor")
            if fn is not None:
                if fn.type == "identifier":
                    calls.add(_text(fn))
                elif fn.type == "member_expression":
                    calls.add(_text(fn.child_by_field_name("property")))
        elif t == "identifier":
            loads.add(_text(n))
        elif t == "member_expression":
            loads.add(_text(n.child_by_field_name("property")))
            ch = _chain(n)
            if ch and ch[0] in alias:
                refs.add(".".join([alias[ch[0]], *ch[1:]]))
            else:  # require('pkg').name(...)
                spec = spec_of_require(n.child_by_field_name("object"))
                if spec:
                    refs.add(f"{spec}.{_text(n.child_by_field_name('property'))}")
        elif t == "subscript_expression":
            pre = _const_prefix(n.child_by_field_name("index"))
            if len(pre) >= 3:
                dyn.add(pre)
    for name, target in alias.items():  # a bare use of an imported name: `a(x)`, `new A()`
        if name in loads or name in calls:
            refs.add(target)
    return frozenset(calls), frozenset(loads), frozenset(refs), tuple(sorted(dyn))


def _unwrap(n: Any) -> Any:
    """Strip parentheses, a leading ``!`` / ``void`` (``!function(){}()``) and TypeScript's
    ``as`` / ``!`` / ``satisfies`` wrappers."""
    while n is not None and n.type in _WRAPPERS:
        kids = n.named_children
        if not kids:
            break
        n = kids[-1] if n.type == "unary_expression" else kids[0]
    return n


def _iife_function(expr: Any) -> Any:
    """The function an expression statement invokes immediately, in any of the usual shapes:
    ``(function(){})()``, ``(function(){}).call(this)``, ``(() => {})()``, ``!function(){}()``."""
    e = _unwrap(expr)
    if e is None or e.type != "call_expression":
        return None
    fn = _unwrap(e.child_by_field_name("function"))
    if (  # (function(){}).call(this)
        fn is not None
        and fn.type == "member_expression"
        and _text(fn.child_by_field_name("property")) in ("call", "apply")
    ):
        fn = _unwrap(fn.child_by_field_name("object"))
    return fn if fn is not None and fn.type in _FUNC_TYPES else None


FACTORY_MIN_LINES = 40  # a function this long that assigns properties acts as a module


def _norm_hash(n: Any) -> str:
    return hashlib.sha256(" ".join(_text(n).split()).encode()).hexdigest()[:16]


def _make(
    qual: str, node: Any, public: bool, is_method: bool, alias: dict[str, str], prop: bool = False
) -> Func:
    calls, loads, refs, dyn = _facts(node, alias)
    first = _text(node).splitlines()[0] if _text(node) else ""
    return Func(
        qualname=qual,
        start=node.start_point.row + 1,
        end=node.end_point.row + 1,
        public=public,
        is_method=is_method,
        doc="",
        calls=calls,
        body_hash=_norm_hash(node),
        signature=first[:120],
        is_property=prop,
        dyn=dyn,
        loads=loads,
        refs=refs,
    )


def _private(name: str) -> bool:
    return name.startswith(("_", "#"))


@lru_cache(maxsize=256)
def _parse_cached(source: str, ts: bool) -> JSFile:
    tree = _parser(ts).parse(source.encode("utf-8", errors="replace"))
    root = tree.root_node
    alias = _alias_map(root)
    out = JSFile()
    defs: list[tuple[str, Any, bool, str]] = []  # (qualname, node, is_method, kind)
    exported: dict[str, str] = {}  # export name -> local qualname
    exported_classes: set[str] = set()
    default_local: list[str] = []
    private_funcs: set[str] = set()

    def add_func(name: str, node: Any, is_method: bool = False, kind: str = "fn") -> None:
        defs.append((name, node, is_method, kind))

    def add_class(name: str, node: Any) -> None:
        body = node.child_by_field_name("body")
        for m in body.children if body is not None else []:
            if m.type != "method_definition":
                continue
            nm = m.child_by_field_name("name")
            kinds = {c.type for c in m.children}
            if any(c.type == "accessibility_modifier" and _text(c) != "public" for c in m.children):
                private_funcs.add(f"{name}.{_text(nm)}")
            add_func(
                f"{name}.{_text(nm)}",
                m,
                True,
                "get" if "get" in kinds else "set" if "set" in kinds else "fn",
            )

    def object_members(obj: Any) -> None:
        for c in obj.named_children:
            if c.type == "shorthand_property_identifier":
                exported[_text(c)] = _text(c)
            elif c.type == "pair":
                k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                key = _text(k) or _str(k)
                if v is not None and v.type == "identifier":
                    exported[key] = _text(v)
                elif v is not None and v.type in _FUNC_TYPES:
                    add_func(key, v)
                    exported[key] = key
            elif c.type == "method_definition":
                nm = _text(c.child_by_field_name("name"))
                add_func(nm, c)
                exported[nm] = nm

    def visit(n: Any) -> None:
        t = n.type
        if t in _DECL_TYPES:
            add_func(_text(n.child_by_field_name("name")), n)
        elif t in _CLASS_DECLS:
            add_class(_text(n.child_by_field_name("name")), n)
        elif t in ("lexical_declaration", "variable_declaration"):
            for d in n.named_children:
                if d.type != "variable_declarator":
                    continue
                nm, v = d.child_by_field_name("name"), _unwrap(d.child_by_field_name("value"))
                if nm is not None and nm.type == "identifier" and v is not None:
                    if v.type in _FUNC_TYPES:
                        add_func(_text(nm), v)
                    elif v.type == "class":
                        add_class(_text(nm), v)
        elif t == "export_statement":
            decl = n.child_by_field_name("declaration")
            value = n.child_by_field_name("value")
            src = n.child_by_field_name("source")
            is_default = any(c.type == "default" for c in n.children)
            if decl is not None:
                visit(decl)
                nm = decl.child_by_field_name("name")
                names = (
                    [_text(nm)]
                    if nm is not None
                    else [
                        _text(d.child_by_field_name("name"))
                        for d in decl.named_children
                        if d.type == "variable_declarator"
                    ]
                )
                for x in names:
                    if is_default:
                        default_local.append(x)
                    else:
                        exported[x] = x
                    if decl.type in _CLASS_DECLS:
                        exported_classes.add(x)
            elif value is not None and is_default:
                if value.type == "identifier":
                    default_local.append(_text(value))
                elif value.type in _FUNC_TYPES:
                    add_func("default", value)
                    default_local.append("default")
            clause = next((c for c in n.children if c.type == "export_clause"), None)
            if clause is not None:
                pairs = []
                for sp in clause.named_children:
                    nm, al = sp.child_by_field_name("name"), sp.child_by_field_name("alias")
                    pairs.append((_text(nm), _text(al or nm)))
                if src is not None:
                    out.reexports.append((_str(src), pairs))
                else:
                    for a, b in pairs:
                        exported[b] = a
            elif src is not None and any(c.type == "*" for c in n.children):
                out.reexports.append((_str(src), None))
        elif t == "expression_statement":
            e = n.named_children[0] if n.named_children else None
            if e is None:
                return
            if e.type == "assignment_expression":
                left, right = e.child_by_field_name("left"), e.child_by_field_name("right")
                ch = _chain(left) if left is not None and left.type == "member_expression" else None
                is_export = ch is not None and (
                    ch[0] == "exports" or ch[:2] == ["module", "exports"]
                )
                if ch is not None and is_export:
                    parts = ch[1:] if ch[0] == "module" else ch  # ["exports", ...]
                    if parts == ["exports"]:  # module.exports = ...
                        if right is None:
                            return
                        if right.type == "object":
                            object_members(right)
                        elif right.type == "identifier":
                            default_local.append(_text(right))
                        elif right.type in _FUNC_TYPES:
                            nm = right.child_by_field_name("name")
                            q = _text(nm) or "default"
                            add_func(q, right)
                            default_local.append(q)
                        elif right.type == "call_expression":
                            fn = right.child_by_field_name("function")
                            args = right.child_by_field_name("arguments")
                            if fn is not None and _text(fn) == "require" and args is not None:
                                s = _str(args.named_children[0]) if args.named_children else ""
                                if s:
                                    out.reexports.append((s, None))
                    elif len(parts) == 2:  # exports.x = ... / module.exports.x = ...
                        name = parts[1]
                        if right is not None:
                            if right.type in _FUNC_TYPES:
                                add_func(name, right)
                                exported[name] = name
                            elif right.type == "identifier":
                                exported[name] = _text(right)
                elif left is not None and left.type == "member_expression" and right is not None:
                    # root.u = function(){} inside an IIFE: a function assigned to a property
                    prop = _text(left.child_by_field_name("property"))
                    if (
                        right.type in _FUNC_TYPES
                        and prop
                        and _chain(left)
                        and len(_chain(left) or []) == 2
                    ):
                        add_func(prop, right)
            elif (inner := _iife_function(e)) is not None:  # UMD / IIFE wrapper
                body = inner.child_by_field_name("body")
                for c in (
                    body.children if body is not None and body.type == "statement_block" else []
                ):
                    visit(c)
        elif t in ("if_statement", "try_statement", "statement_block", "else_clause"):
            for c in n.children:
                visit(c)

    for child in root.children:
        visit(child)

    # A long function that assigns properties (``lodash.template = template``) is a module in
    # disguise (UMD builds, factories). Its direct nested functions are listed, and the ones it
    # assigns count as exported under the property name.
    nested_public: set[str] = set()
    known = {d[0] for d in defs}
    for _q, fnode, is_method, _kind in list(defs):
        if is_method or fnode.end_point.row - fnode.start_point.row < FACTORY_MIN_LINES:
            continue
        body = fnode.child_by_field_name("body")
        if body is None or body.type != "statement_block":
            continue
        assigned: dict[str, str] = {}  # property -> local name
        stack = [body]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if (
                    left is not None
                    and left.type == "member_expression"
                    and right is not None
                    and right.type == "identifier"
                ):
                    assigned[_text(left.child_by_field_name("property"))] = _text(right)
        local_names = set(assigned.values())
        for c in body.children:
            found: list[tuple[str, Any]] = []
            if c.type in _DECL_TYPES:
                found.append((_text(c.child_by_field_name("name")), c))
            elif c.type in ("lexical_declaration", "variable_declaration"):
                for d in c.named_children:
                    nm, v = d.child_by_field_name("name"), _unwrap(d.child_by_field_name("value"))
                    if (
                        nm is not None
                        and nm.type == "identifier"
                        and v is not None
                        and v.type in _FUNC_TYPES
                    ):
                        found.append((_text(nm), v))
            for nm, nnode in found:
                if nm and nm not in known:
                    known.add(nm)
                    add_func(nm, nnode)
                    if nm in local_names:
                        nested_public.add(nm)
        for prop, local in assigned.items():
            if local in nested_public:
                exported.setdefault(prop, local)

    for q in default_local:
        exported.setdefault("default", q)
    exported_classes |= {
        v for v in exported.values() if any(d[0].startswith(v + ".") for d in defs)
    }
    out.exports = exported
    exported_local = set(exported.values())
    seen: set[str] = set()
    for q, node, is_method, kind in defs:
        if q in seen:
            continue
        seen.add(q)
        owner = q.split(".")[0] if is_method else ""
        pub = (
            q in exported_local or q in nested_public or (is_method and owner in exported_classes)
        ) and not (q in private_funcs or any(_private(p) for p in q.split(".")))
        out.functions.append(_make(q, node, pub, is_method, alias, prop=kind in ("get", "set")))
    return out


def parse_js(source: str, ts: bool = False) -> JSFile:
    if _parser(ts) is None:
        return JSFile()
    return _parse_cached(source, ts)


def js_functions(source: str, with_module: bool = False, ts: bool = False) -> list[Func]:
    f = parse_js(source, ts)
    funcs = list(f.functions)
    if with_module and _parser(ts) is not None:
        tree = _parser(ts).parse(source.encode("utf-8", errors="replace"))
        alias = _alias_map(tree.root_node)
        top = [
            c
            for c in tree.root_node.children
            if c.type not in _DECL_TYPES and c.type not in _CLASS_DECLS
        ]
        calls: set[str] = set()
        loads: set[str] = set()
        refs: set[str] = set()
        dyn: set[str] = set()
        for c in top:
            a, b, r, d = _facts(c, alias)
            calls |= a
            loads |= b
            refs |= r
            dyn |= set(d)
        funcs.append(
            Func(
                qualname="<module>",
                start=1,
                end=0,
                public=True,
                is_method=False,
                doc="",
                calls=frozenset(calls),
                body_hash=hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:16],
                signature="<module>",
                dyn=tuple(sorted(dyn)),
                loads=frozenset(loads),
                refs=frozenset(refs),
            )
        )
    return funcs


def referenced_names_js(source: str, ts: bool = False) -> set[str]:
    """Every dotted name a JavaScript file reaches through ``require`` / ``import``:
    ``const _ = require('lodash'); _.template()`` -> ``lodash.template``; a bare use of an
    imported name (``const f = require('p'); f(x)``) -> ``p``."""
    if _parser(ts) is None:
        return set()
    root = _parser(ts).parse(source.encode("utf-8", errors="replace")).root_node
    return set(_facts(root, _alias_map(root))[2])
