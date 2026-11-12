"""Plain-language questions about a scan, answered only from the scan.

``scgraph ask "why am I exposed to CVE-2021-33503?"`` scans the project, picks the findings the
question names (an advisory id or a package), and writes short sentences. Every sentence carries
a citation: a dependency path, an advisory id, a claim, or a fix. A sentence with no citation is
not allowed. No model is used, so no sentence can state something the scan did not find.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["Sentence", "answer", "render"]

_ADV = re.compile(
    r"\b(CVE-\d{4}-\d{3,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)\b",
    re.I,
)
_VERDICT = {
    "reachable": "Your code calls the vulnerable function",
    "class_used": "Your code uses the class that holds the vulnerable method",
    "not_called": "No reference to the vulnerable function was found in your code",
    "not_analyzed": "scgraph could not check whether your code calls the vulnerable function",
}


@dataclass(frozen=True)
class Sentence:
    text: str
    cite: str

    def __post_init__(self) -> None:
        if not self.cite:
            raise ValueError("a sentence needs a citation")


def _alerts(scan: dict) -> list[dict]:
    return [a for r in scan.get("results", []) for a in r.get("alerts", [])]


def _match(question: str, alerts: list[dict]) -> list[dict]:
    ids = {m.upper() for m in _ADV.findall(question)}
    if ids:
        hit = [
            a
            for a in alerts
            if ids & {x.upper() for x in [a["id"], *a.get("ids", []), *a.get("aliases", [])]}
        ]
        if hit:
            return hit
    q = question.lower()
    return [
        a for a in alerts if re.search(rf"(?<![\w-]){re.escape(a['package'].lower())}(?![\w-])", q)
    ]


def _about(a: dict) -> list[Sentence]:
    out = [
        Sentence(
            f"{a['package']} {a['version']} is affected by {a['id']}"
            + (f" (CVSS {a['score']:.1f})" if a.get("score") is not None else "")
            + ".",
            f"advisory:{a['id']}",
        )
    ]
    if a.get("path"):
        out.append(
            Sentence(
                "It enters your project through " + " > ".join(a["path"]) + ".",
                "path: " + " > ".join(a["path"]),
            )
        )
    verdict = a.get("reachability") or ""
    if verdict in _VERDICT:
        how = (
            "inferred from the fix commit"
            if a.get("symbols_source") == "inferred"
            else "named by the advisory"
        )
        cite = f"claim:{a['id']} ({how})" if verdict != "not_analyzed" else f"scan:{a['id']}"
        hops = f" through {a['reach_hops']} packages" if a.get("reach_hops", 0) > 1 else ""
        out.append(Sentence(f"{_VERDICT[verdict]}{hops}. This does not close the alert.", cite))
    if a.get("fix"):
        out.append(Sentence(f"Fix: {a['fix']}.", f"fix:{a['id']}"))
    return out


def answer(question: str, scan: dict, limit: int = 5) -> list[Sentence]:
    alerts = _alerts(scan)
    if not alerts:
        return [Sentence("The scan found no alert.", "scan:summary")]
    hit = _match(question, alerts)
    if not hit:
        top = alerts[:limit]
        head = Sentence(
            f"The scan found {len(alerts)} alert(s). The question names no advisory or package, "
            f"so these are the first {len(top)}.",
            "scan:summary",
        )
        return [head, *[s for a in top for s in _about(a)[:1]]]
    return [s for a in hit[:limit] for s in _about(a)]


def render(sentences: list[Sentence]) -> str:
    return "\n".join(f"{s.text}  [{s.cite}]" for s in sentences)
