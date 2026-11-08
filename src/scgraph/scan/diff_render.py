"""Diff results as terminal text, JSON and a Markdown pull-request comment.

The Markdown starts with ``MARKER``, a hidden HTML comment. A CI job looks for it to find the
comment scgraph posted earlier and edit it, so one pull request carries one comment.
"""

from __future__ import annotations

import json

from .. import __version__
from .diff import Delta
from .render import _TAG, _c, _path_lines, _signal_bits, _use_color, md_safe

__all__ = ["MARKER", "delta_json", "delta_markdown", "delta_text"]

MARKER = "<!-- scgraph-diff -->"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _pkg_summary(d: Delta) -> str:
    bits = []
    if d.added:
        bits.append(f"+{_plural(len(d.added), 'package')}")
    if d.removed:
        bits.append(f"-{_plural(len(d.removed), 'package')}")
    if d.changed:
        bits.append(_plural(len(d.changed), "version change"))
    return " · ".join(bits) or "no package changes"


def _totals(deltas: list[Delta]) -> tuple[int, int, int]:
    return (
        sum(len(d.new_alerts) for d in deltas),
        sum(len(d.resolved) for d in deltas),
        sum(d.persisting for d in deltas),
    )


def delta_text(deltas: list[Delta], base: str, color: bool | None = None) -> str:
    on = _use_color() if color is None else color
    out: list[str] = []
    for d in deltas:
        new = "" if d.base_exists else "  (new lockfile)"
        out.append(_c(f"{d.path}  vs {base}{new}", "b", on))
        out.append("  " + _c(_pkg_summary(d), "dim", on))
        for f in d.new_alerts:
            tag = _c(f" NEW {f.priority} {_TAG[f.priority]} ", f.priority, on)
            out.append(f"\n {tag} {_c(f'{f.package}@{f.version}', 'b', on)}  {f.id}")
            bits = _signal_bits(f)
            if bits:
                out.append("   " + _c(bits, "dim", on))
            out.extend(_path_lines(f, on))
            out.append("   " + _c("fix ", "ok", on) + f.fix)
        for f in d.resolved:
            out.append(
                _c(f"\n  resolved  {f.id}  {f.package}@{f.version}", "ok", on)
                + _c("  (no longer an alert)", "dim", on)
            )
        out.append(
            f"\n  {_plural(len(d.new_alerts), 'new alert')} · {len(d.resolved)} resolved · "
            f"{d.persisting} unchanged\n"
        )
    if len(deltas) > 1:
        n, r, p = _totals(deltas)
        out.append(f"total: {_plural(n, 'new alert')} · {r} resolved · {p} unchanged")
    return "\n".join(out).rstrip() + "\n"


def delta_json(deltas: list[Delta], base: str) -> str:
    n, r, p = _totals(deltas)
    return json.dumps(
        {
            "tool": "scgraph",
            "version": __version__,
            "base": base,
            "summary": {"new_alerts": n, "resolved": r, "persisting": p},
            "results": [d.to_dict() for d in deltas],
        },
        indent=2,
    )


def delta_markdown(deltas: list[Delta], base: str) -> str:
    n, r, p = _totals(deltas)
    head = (
        f"## scgraph: {_plural(n, 'new alert')} in this change"
        if n
        else "## scgraph: no new alerts in this change"
    )
    out = [MARKER, head, "", f"Compared with `{md_safe(base)}`: {r} resolved · {p} unchanged.", ""]
    for d in deltas:
        flag = "" if d.base_exists else " (new lockfile)"
        out.append(f"### `{md_safe(d.path)}`{flag} · {_pkg_summary(d)}")
        if d.new_alerts:
            out += ["", "| | advisory | package | signals | fix |", "|---|---|---|---|---|"]
            for f in d.new_alerts:
                out.append(
                    f"| **{f.priority}** | "
                    f"[{md_safe(f.id)}](https://osv.dev/vulnerability/{md_safe(f.ids[0])}) | "
                    f"`{md_safe(f.package)}@{md_safe(f.version)}` | {md_safe(_signal_bits(f))} | "
                    f"`{md_safe(f.fix)}` |"
                )
            out += ["", "<details><summary>how it got in (the dependency paths)</summary>", ""]
            out.append("```")
            out += [
                f"{md_safe(f.id)}: " + " -> ".join(md_safe(h) for h in f.path or [])
                for f in d.new_alerts
            ]
            out += ["```", "</details>"]
        if d.resolved:
            out += [
                "",
                "Resolved by this change: " + ", ".join(f"`{md_safe(f.id)}`" for f in d.resolved),
            ]
        if d.added or d.removed or d.changed:
            out += ["", "<details><summary>package changes</summary>", ""]
            out += [f"- added `{md_safe(x)}`" for x in d.added]
            out += [f"- removed `{md_safe(x)}`" for x in d.removed]
            out += [f"- `{md_safe(name)}` {md_safe(a)} -> {md_safe(b)}" for name, a, b in d.changed]
            out += ["", "</details>"]
        out.append("")
    return "\n".join(out)
