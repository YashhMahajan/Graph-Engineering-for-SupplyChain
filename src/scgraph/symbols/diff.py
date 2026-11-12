"""Parse a unified diff (``git diff`` / GitHub ``.diff``) into files and hunks.

Only what the candidate builder needs is kept: for every hunk, the new-file line numbers of
added lines, the old-file line numbers of removed lines, and an *anchor* in the new file for
each change. A pure deletion has no new-file line of its own, so its anchor is the new-file
line where the deleted text used to be. That is enough to find the enclosing function in the
post-fix source without a second download of the pre-fix file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["FileDiff", "Hunk", "parse_unified"]

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$")
_GIT = re.compile(r"^diff --git a/(.*?) b/(.*)$")


@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    context: str = ""  # the text after the second @@ (git's function-name heuristic)
    added: list[int] = field(default_factory=list)  # new-file line numbers
    removed: list[int] = field(default_factory=list)  # old-file line numbers
    anchors: list[int] = field(default_factory=list)  # new-file lines touched by any change
    removed_anchors: list[int] = field(default_factory=list)  # new-file anchor per removed line
    lines: list[str] = field(default_factory=list)  # the raw body, with +/-/space prefixes

    def text(self, max_lines: int = 40) -> str:
        head = f"@@ -{self.old_start},{self.old_len} +{self.new_start},{self.new_len} @@"
        body = self.lines if len(self.lines) <= max_lines else [*self.lines[:max_lines], "..."]
        return "\n".join([head, *body])


@dataclass
class FileDiff:
    old_path: str | None
    new_path: str | None
    hunks: list[Hunk] = field(default_factory=list)
    binary: bool = False

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or ""

    @property
    def is_new(self) -> bool:
        return self.old_path is None

    @property
    def is_deleted(self) -> bool:
        return self.new_path is None

    def added_text(self) -> list[str]:
        return [ln[1:] for h in self.hunks for ln in h.lines if ln.startswith("+")]


def _strip(p: str) -> str | None:
    p = p.strip().split("\t")[0]
    if p == "/dev/null":
        return None
    return p[2:] if p[:2] in ("a/", "b/") else p


def parse_unified(text: str) -> list[FileDiff]:
    """Every file section in ``text``. Tolerates diffs without ``diff --git`` headers,
    ``\\ No newline at end of file`` markers and binary sections."""
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    hunk: Hunk | None = None
    old_ln = new_ln = 0
    old_left = new_left = 0
    for raw in text.splitlines():
        if hunk is not None and (old_left > 0 or new_left > 0):
            tag = raw[:1]
            if tag == "\\":
                continue
            if tag == "+":
                hunk.added.append(new_ln)
                hunk.anchors.append(new_ln)
                hunk.lines.append(raw)
                new_ln += 1
                new_left -= 1
                continue
            if tag == "-":
                hunk.removed.append(old_ln)
                hunk.anchors.append(new_ln)
                hunk.removed_anchors.append(new_ln)
                hunk.lines.append(raw)
                old_ln += 1
                old_left -= 1
                continue
            if tag == " " or raw == "":
                hunk.lines.append(raw if raw else " ")
                old_ln += 1
                new_ln += 1
                old_left -= 1
                new_left -= 1
                continue
            # anything else ends the hunk early (a truncated diff); fall through
        m = _GIT.match(raw)
        if m:
            cur = FileDiff(old_path=m.group(1), new_path=m.group(2))
            files.append(cur)
            hunk = None
            continue
        if raw.startswith("--- "):
            if cur is None or cur.hunks:
                cur = FileDiff(old_path=None, new_path=None)
                files.append(cur)
            cur.old_path = _strip(raw[4:])
            continue
        if raw.startswith("+++ ") and cur is not None:
            cur.new_path = _strip(raw[4:])
            continue
        if raw.startswith("Binary files ") and cur is not None:
            cur.binary = True
            continue
        if raw.startswith("new file mode") and cur is not None:
            cur.old_path = None
            continue
        if raw.startswith("deleted file mode") and cur is not None:
            cur.new_path = None
            continue
        m = _HUNK.match(raw)
        if m and cur is not None:
            old_ln, new_ln = int(m.group(1)), int(m.group(3))
            old_left = int(m.group(2)) if m.group(2) is not None else 1
            new_left = int(m.group(4)) if m.group(4) is not None else 1
            hunk = Hunk(old_ln, old_left, new_ln, new_left, context=m.group(5).strip())
            cur.hunks.append(hunk)
    return files
