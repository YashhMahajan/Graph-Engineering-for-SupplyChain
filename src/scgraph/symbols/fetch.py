"""A small HTTP layer with a disk cache, and the fix-commit references of an OSV record.

Every response is cached by URL under ``$SCGRAPH_CACHE`` (default ``~/.cache/scgraph``), and a
404 is cached too, so a re-run of an evaluation or a dataset build makes no request it has
made before. Fix diffs and files come from ``github.com/<o>/<r>/commit/<sha>.diff`` and
``raw.githubusercontent.com``, which do not count against the GitHub REST API quota.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from .diff import FileDiff, parse_unified

__all__ = ["Fetcher", "Fix", "FixRef", "cache_dir", "fix_refs", "get_fix"]

_UA = "scgraph-symbols/1.0 (+https://pypi.org/project/scgraph-cli/)"


def cache_dir() -> Path:
    return Path(os.environ.get("SCGRAPH_CACHE") or Path.home() / ".cache" / "scgraph")


class Fetcher:
    """GET with a disk cache, a size cap and polite retries on 429 / 5xx."""

    def __init__(
        self,
        root: Path | None = None,
        timeout: float = 30.0,
        max_bytes: int = 40_000_000,
        session: requests.Session | None = None,
        offline: bool = False,
    ):
        self.root = (root or cache_dir()) / "http"
        self.root.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", _UA)
        self.offline = offline
        self.requests_made = 0
        self._lock = threading.Lock()

    def _path(self, url: str) -> Path:
        h = hashlib.sha256(url.encode()).hexdigest()
        return self.root / h[:2] / h

    def bytes(self, url: str) -> bytes | None:
        p = self._path(url)
        if p.exists():
            return p.read_bytes()
        if p.with_suffix(".404").exists() or self.offline:
            return None
        for attempt in range(4):
            try:
                r = self.session.get(url, timeout=self.timeout, stream=True)
            except requests.RequestException:
                time.sleep(2**attempt)
                continue
            with self._lock:
                self.requests_made += 1
            if r.status_code in (404, 410, 451):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.with_suffix(".404").write_text(str(r.status_code))
                return None
            if r.status_code == 429 or r.status_code >= 500:
                wait = float(r.headers.get("Retry-After") or 2 ** (attempt + 1))
                time.sleep(min(wait, 60.0))
                continue
            if r.status_code != 200:
                return None
            size = int(r.headers.get("Content-Length") or 0)
            if size > self.max_bytes:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.with_suffix(".404").write_text("too large")
                return None
            data = b""
            for chunk in r.iter_content(1 << 16):
                data += chunk
                if len(data) > self.max_bytes:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.with_suffix(".404").write_text("too large")
                    return None
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(f".tmp{os.getpid()}.{threading.get_ident()}")
            tmp.write_bytes(data)
            tmp.replace(p)
            return data
        return None

    def text(self, url: str) -> str | None:
        b = self.bytes(url)
        return None if b is None else b.decode("utf-8", errors="replace")

    def json(self, url: str) -> Any:
        t = self.text(url)
        if t is None:
            return None
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            return None


# ----------------------------------------------------------------------------- fix refs

_COMMIT = re.compile(
    r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})"
)
_PULL = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/pull/(\d+)/?(?:files)?$")


@dataclass(frozen=True)
class FixRef:
    owner: str
    repo: str
    kind: str  # "commit" | "pull"
    ident: str  # sha or pull number
    url: str

    @property
    def diff_url(self) -> str:
        what = "commit" if self.kind == "commit" else "pull"
        return f"https://github.com/{self.owner}/{self.repo}/{what}/{self.ident}.diff"


def fix_refs(record: dict) -> list[FixRef]:
    """GitHub commits and pull requests an OSV record links, ``FIX`` references first.
    Commits come before pull requests: a commit pins the exact change, a PR may have grown."""
    refs = record.get("references") or []
    ordered = [r for r in refs if r.get("type") == "FIX"] + [
        r for r in refs if r.get("type") != "FIX"
    ]
    out: list[FixRef] = []
    seen: set[tuple[str, str, str]] = set()
    for r in ordered:
        url = str(r.get("url") or "").strip()
        m = _COMMIT.match(url)
        if m:
            key = (m.group(1).lower(), m.group(2).lower(), m.group(3)[:7])
            if key not in seen:
                seen.add(key)
                out.append(FixRef(m.group(1), m.group(2), "commit", m.group(3), url))
            continue
        m = _PULL.match(url)
        if m:
            key = (m.group(1).lower(), m.group(2).lower(), "#" + m.group(3))
            if key not in seen:
                seen.add(key)
                out.append(FixRef(m.group(1), m.group(2), "pull", m.group(3), url))
    out.sort(key=lambda f: f.kind != "commit")
    return out


@dataclass
class Fix:
    ref: FixRef
    sha: str  # the revision the post-fix files are read at
    files: list[FileDiff]

    def raw_url(self, path: str) -> str:
        return (
            f"https://raw.githubusercontent.com/{self.ref.owner}/{self.ref.repo}/{self.sha}/{path}"
        )


_FROM = re.compile(r"^From ([0-9a-f]{40}) ", re.M)
MAX_DIFF_BYTES = 3_000_000
MAX_DIFF_FILES = 300


def get_fix(fetcher: Fetcher, ref: FixRef) -> Fix | None:
    """The parsed diff and the revision to read post-fix files at, or None when the diff is
    missing, binary-only, or too large to be a security fix rather than a release merge."""
    text = fetcher.text(ref.diff_url)
    if not text or len(text) > MAX_DIFF_BYTES:
        return None
    files = [f for f in parse_unified(text) if f.hunks]
    if not files or len(files) > MAX_DIFF_FILES:
        return None
    sha = ref.ident
    if ref.kind == "pull" or len(sha) < 40:  # raw file URLs need the full head revision
        what = "pull" if ref.kind == "pull" else "commit"
        patch = fetcher.text(f"https://github.com/{ref.owner}/{ref.repo}/{what}/{ref.ident}.patch")
        heads = _FROM.findall(patch or "")
        if not heads:
            return None
        sha = heads[-1]
    return Fix(ref=ref, sha=sha, files=files)
