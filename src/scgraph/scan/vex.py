"""Read OpenVEX documents: a supplier's statement that a finding does not apply.

``scgraph scan --vex FILE`` lets a ``not_affected`` or ``fixed`` statement suppress a
finding, and the suppression is reported as an abstention with the reason ``vex``, never
silently dropped. Rules, chosen so a VEX file cannot hide a real problem by accident:

* parsing is strict: a statement the spec calls invalid raises ``VexError``
* only ``not_affected`` and ``fixed`` suppress; ``affected`` and ``under_investigation`` do not
* for one vulnerability and package the newest timestamp wins, so a later ``affected``
  statement revokes an earlier ``not_affected``
* the engine never lets VEX suppress a malicious package (see ``engine._gates``)

A statement matches a package by purl. A purl without a version covers every version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

__all__ = ["VexError", "VexIndex", "VexStatement", "load_vex", "parse_vex"]

_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
_SUPPRESS = {"not_affected", "fixed"}
_EPOCH = datetime.min.replace(tzinfo=UTC)

PurlKey = tuple[str, str, str | None]  # (type, name, version or None for any)


class VexError(ValueError):
    """The document is not valid OpenVEX, or a statement breaks the spec."""


@dataclass(frozen=True)
class VexStatement:
    vulns: frozenset[str]
    purls: tuple[PurlKey, ...]
    status: str
    justification: str = ""
    impact: str = ""
    timestamp: datetime = _EPOCH
    order: int = 0  # position in the input, to break timestamp ties (later wins)

    @property
    def suppresses(self) -> bool:
        return self.status in _SUPPRESS

    def reason(self) -> str:
        return self.justification or self.impact or self.status


def purl_key(purl: str) -> PurlKey:
    """Normalise a purl to (type, name, version). Qualifiers and subpath are dropped and
    percent-encoding is undone, so ``pkg:npm/%40a/b@1`` equals ``pkg:npm/@a/b@1``."""
    s = unquote(purl.split("#", 1)[0].split("?", 1)[0])
    if not s.startswith("pkg:"):
        raise VexError(f"not a purl: {purl!r}")
    typ, _, rest = s[4:].partition("/")
    if not typ or not rest:
        raise VexError(f"not a purl: {purl!r}")
    at = rest.rfind("@")
    if at > rest.rfind("/") and at > 0:  # an @ after the last slash starts the version
        return typ.lower(), rest[:at], rest[at + 1 :] or None
    return typ.lower(), rest, None


def _when(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _vulns(v: object) -> frozenset[str]:
    if isinstance(v, str):  # OpenVEX 0.0.1 and 0.1 wrote the id as a bare string
        return frozenset({v})
    if isinstance(v, dict):
        names = {v.get("name"), v.get("@id"), *(v.get("aliases") or [])}
        out = frozenset(n for n in names if isinstance(n, str) and n)
        if out:
            return out
    raise VexError(f"statement has no vulnerability name: {v!r}")


def _product_purls(products: object) -> tuple[PurlKey, ...]:
    """A product that lists subcomponents names the application, and the subcomponents
    are the packages. A product without subcomponents is itself the package."""
    if not isinstance(products, list) or not products:
        raise VexError("statement has no products")
    out: list[PurlKey] = []
    for p in products:
        if not isinstance(p, dict):
            raise VexError(f"bad product entry: {p!r}")
        subs = p.get("subcomponents") or []
        targets = subs if subs else [p]
        for t in targets:
            ids = [t.get("@id"), (t.get("identifiers") or {}).get("purl")]
            out.extend(purl_key(i) for i in ids if isinstance(i, str) and i.startswith("pkg:"))
    if not out:
        raise VexError("no product or subcomponent carries a purl")
    return tuple(out)


def parse_vex(doc: object) -> list[VexStatement]:
    if not isinstance(doc, dict) or not str(doc.get("@context", "")).startswith(
        "https://openvex.dev/ns"
    ):
        raise VexError("not an OpenVEX document (missing @context)")
    stmts = doc.get("statements")
    if not isinstance(stmts, list):
        raise VexError("document has no statements list")
    doc_time = _when(doc.get("timestamp")) or _EPOCH
    out: list[VexStatement] = []
    for n, s in enumerate(stmts):
        if not isinstance(s, dict):
            raise VexError(f"statement {n} is not an object")
        status = s.get("status")
        if status not in _STATUSES:
            raise VexError(f"statement {n}: unknown status {status!r}")
        just = str(s.get("justification") or "")
        impact = str(s.get("impact_statement") or "")
        if status == "not_affected" and not (just or impact):
            raise VexError(f"statement {n}: not_affected needs a justification or impact_statement")
        if status == "affected" and not s.get("action_statement"):
            raise VexError(f"statement {n}: affected needs an action_statement")
        out.append(
            VexStatement(
                vulns=_vulns(s.get("vulnerability")),
                purls=_product_purls(s.get("products")),
                status=status,
                justification=just,
                impact=impact,
                timestamp=_when(s.get("timestamp")) or doc_time,
                order=n,
            )
        )
    return out


class VexIndex:
    """Statements from one or more documents, queryable by advisory ids and a package purl."""

    def __init__(self, statements: list[VexStatement] | None = None) -> None:
        self.statements: list[VexStatement] = []
        self._by_vuln: dict[str, list[VexStatement]] = {}
        for s in statements or []:
            self.add(s)

    def add(self, s: VexStatement) -> None:
        s = replace(s, order=len(self.statements))
        self.statements.append(s)
        for v in s.vulns:
            self._by_vuln.setdefault(v, []).append(s)

    def __len__(self) -> int:
        return len(self.statements)

    def match(self, ids: set[str], purl: str) -> VexStatement | None:
        """The suppressing statement for this finding, or None. The newest matching
        statement decides, so a later ``affected`` revokes an earlier ``not_affected``."""
        typ, name, ver = purl_key(purl)
        hits = {
            id(s): s
            for v in ids
            for s in self._by_vuln.get(v, [])
            if any(t == typ and n == name and pv in (None, ver) for t, n, pv in s.purls)
        }
        if not hits:
            return None
        newest = max(hits.values(), key=lambda s: (s.timestamp, s.order))
        return newest if newest.suppresses else None


def load_vex(paths: list[str | Path]) -> VexIndex:
    index = VexIndex()
    for p in paths:
        try:
            doc = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise VexError(f"cannot read VEX file {p}: {e}") from e
        for s in parse_vex(doc):
            index.add(s)
    return index
