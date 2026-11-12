"""``scgraph symbols``: infer, look up, and budget vulnerable-symbol inference."""

from __future__ import annotations

import argparse
import json
import sys

from .fetch import Fetcher

__all__ = ["add_parser"]


def _record_for(fetcher: Fetcher, advisory: str) -> dict | None:
    return fetcher.json(f"https://api.osv.dev/v1/vulns/{advisory}")


def _target(record: dict) -> tuple[str, str] | None:
    for a in record.get("affected") or []:
        p = a.get("package") or {}
        if p.get("ecosystem") in ("PyPI", "Go") and p.get("name") not in ("stdlib", "toolchain"):
            return p["ecosystem"], p["name"]
    return None


def _infer(a: argparse.Namespace) -> int:
    from .pipeline import finalize, prepare, task_for

    f = Fetcher()
    rec = _record_for(f, a.advisory)
    if not rec:
        print(f"scgraph: OSV has no record {a.advisory}", file=sys.stderr)
        return 2
    tgt = _target(rec)
    if tgt is None:
        print("scgraph: only PyPI and Go advisories are supported", file=sys.stderr)
        return 2
    p = prepare(rec, tgt[0], tgt[1], f)
    choice = None
    if a.llm and p.mode != "none" and p.margin() < a.uncertain:
        from .llm import OpenRouter
        from .select import choose

        t = task_for(p)
        if t is not None:
            got, rep = choose(OpenRouter(), [t], batch_size=1, max_requests=1)
            choice = got.get(p.id)
            if rep.get("stopped"):
                print(f"scgraph: LLM step skipped: {rep['stopped']}", file=sys.stderr)
    out = finalize(p, choice)
    if out is None:
        reason = p.reason or "no candidate passed the verifier"
        print(json.dumps({"id": p.id, "abstain": reason}) if a.json else f"abstain: {reason}")
        return 1
    if a.json:
        print(json.dumps(out.to_dict(), indent=1))
        return 0
    print(f"{out.id}  {out.package} (affected {out.affected_version}, fixed {out.fixed_version})")
    print(f"  vulnerable: {out.symbol}")
    print(f"  method:     {out.method}   confidence {out.confidence}   verifier: {out.verified}")
    print(f"              {out.verify_detail}")
    ev = out.evidence
    if "fix" in ev:
        print(f"  evidence:   {ev['fix']}  ({ev.get('file')}, {ev.get('changed_lines')} lines)")
    else:
        print(
            f"  evidence:   code search rank {ev.get('search_rank')}, "
            f"changed in fixed release: {ev.get('changed_in_fixed_release')}"
        )
    if out.entry_points:
        shown = out.entry_points[:12]
        more = len(out.entry_points) - len(shown)
        print("  entry points: " + ", ".join(shown) + (f" (+{more} more)" if more > 0 else ""))
    return 0


def _show(a: argparse.Namespace) -> int:
    from .dataset import load

    idx = load()
    r = idx.get([a.advisory])
    if r is None:
        print(f"scgraph: {a.advisory} is not in the dataset ({len(idx)} records)", file=sys.stderr)
        return 1
    print(json.dumps(r, indent=1))
    return 0


def _budget(a: argparse.Namespace) -> int:
    from .llm import OpenRouter

    c = OpenRouter()
    st = c.remote_status()
    print(f"models (in order): {', '.join(c.models)}")
    off = c.unavailable()
    if off:
        print(f"skipped for 24h (refused this key): {', '.join(off)}")
    print(f"requests logged today: {c.used_today()}")
    if st:
        print(f"free-model requests today: {st.get('used')} used of {st.get('limit')}")
    print(f"this client will still send: {c.remaining()} (reserve {c.reserve})")
    return 0


def add_parser(sub) -> None:
    s = sub.add_parser("symbols", help="which function does an advisory concern? (build-time)")
    ss = s.add_subparsers(dest="symbols_cmd", required=True)
    i = ss.add_parser("infer", help="infer and verify the vulnerable function of one advisory")
    i.add_argument("advisory", help="an OSV id: GHSA-..., PYSEC-..., GO-...")
    i.add_argument("--llm", action="store_true", help="ask the LLM when the ranker is unsure")
    i.add_argument("--uncertain", type=float, default=0.25)
    i.add_argument("--json", action="store_true")
    i.set_defaults(fn=_infer)
    w = ss.add_parser("show", help="look an advisory up in the shipped dataset")
    w.add_argument("advisory")
    w.set_defaults(fn=_show)
    b = ss.add_parser("budget", help="today's free-tier LLM budget")
    b.set_defaults(fn=_budget)
