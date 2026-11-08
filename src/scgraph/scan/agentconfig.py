"""Audit AI-agent and IDE configuration as a supply-chain surface.

The newest waves of the Shai-Hulud worm no longer needed ``npm install``: they added files
to a repository that run code when a developer opens it or starts their coding agent, such
as a ``runOn: folderOpen`` task in ``.vscode/tasks.json`` or a hook in
``.claude/settings.json``. Reviewers read source diffs and skip these files. This audit reads
them:

  info   every command that runs automatically (MCP server launchers, hooks, tasks), so a
         person can see what starts on its own
  warn   an unpinned ``npx``/``uvx`` launcher: it runs whatever is newest, so a freshly
         published malicious release executes on the next start
  warn   a task that runs when the folder is opened
  warn   a command that downloads and executes (``curl | sh``)
  warn   ``enableAllProjectMcpServers``: a pull request can add an MCP server that starts
         without a prompt
  *      every package a launcher fetches goes through the pre-install guard, so a malicious
         or hallucinated name is a block and a fresh or typosquatted one is a warning
  warn   a file that cannot be read: unreadable config is reported, never treated as clean

Only the project's own files are read, never ``~/.claude`` or other user settings.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from .agent import install_targets
from .formats import loads_jsonc
from .guard import Check, normalize_ecosystem, parse_spec

__all__ = ["CONFIG_FILES", "ConfigFinding", "audit", "audit_file", "to_json", "worst"]

CONFIG_FILES = (
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".vscode/mcp.json",
    ".vscode/tasks.json",
)
_MAX_BYTES = 2_000_000
_LEVEL = {"info": 0, "warn": 1, "block": 2}
_DOWNLOAD_EXEC = re.compile(
    r"(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"
    r"|\b(ba|z)?sh\s+-c\b[^\n]*(\$\(|`)\s*(curl|wget)\b"
    r"|\beval\b[^\n]*\$\(\s*(curl|wget)\b"
    r"|base64\s+(-d|--decode)[^|\n]*\|\s*(ba|z)?sh\b"
    r"|\b(iex|invoke-expression)\b[^\n]*\b(downloadstring|invoke-webrequest|iwr|irm)\b",
    re.IGNORECASE,
)


@dataclass
class ConfigFinding:
    file: str
    where: str  # a path inside the file, for example "mcpServers.github"
    level: str  # info | warn | block
    code: str
    message: str
    command: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def worst(findings: list[ConfigFinding]) -> str:
    return max((f.level for f in findings), key=_LEVEL.__getitem__, default="info")


def _commands(doc: dict, name: str) -> list[tuple[str, str, str]]:
    """``(where, event, command)`` for every command the file runs automatically."""
    out: list[tuple[str, str, str]] = []
    for key in ("mcpServers", "servers"):
        servers = doc.get(key)
        if isinstance(servers, dict):
            for sname, spec in servers.items():
                if isinstance(spec, dict) and isinstance(spec.get("command"), str):
                    args = [str(a) for a in spec.get("args") or []]
                    out.append((f"{key}.{sname}", "mcp-server", " ".join([spec["command"], *args])))
    hooks = doc.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            for gi, group in enumerate(groups if isinstance(groups, list) else []):
                for hi, hook in enumerate((group or {}).get("hooks") or []):
                    cmd = hook.get("command") if isinstance(hook, dict) else None
                    if isinstance(cmd, str):
                        out.append((f"hooks.{event}[{gi}].hooks[{hi}]", f"hook:{event}", cmd))
    tasks = doc.get("tasks")
    if name == "tasks.json" and isinstance(tasks, list):
        for ti, task in enumerate(tasks):
            if isinstance(task, dict) and isinstance(task.get("command"), str):
                args = [
                    a if isinstance(a, str) else str(a.get("value", ""))
                    for a in task.get("args") or []
                ]
                label = task.get("label", ti)
                out.append((f"tasks[{ti}] {label!r}", "task", " ".join([task["command"], *args])))
    return out


def audit_file(
    path: Path, text: str, checker: Callable[..., Check] | None = None, rel: str | None = None
) -> list[ConfigFinding]:
    """Findings for one config file. ``checker`` is the pre-install guard (None skips it)."""
    rel = rel or path.as_posix()
    try:
        doc = loads_jsonc(text)
        if not isinstance(doc, dict):
            raise ValueError("the top level is not an object")
    except ValueError as e:  # json.JSONDecodeError is a ValueError
        return [
            ConfigFinding(
                rel, "", "warn", "unreadable", f"cannot be read, so it is not audited: {e}"
            )
        ]
    found: list[ConfigFinding] = []

    def add(where: str, level: str, code: str, message: str, command: str = "") -> None:
        found.append(ConfigFinding(rel, where, level, code, message, command))

    if doc.get("enableAllProjectMcpServers") is True:
        add(
            "enableAllProjectMcpServers",
            "warn",
            "auto_approve_mcp",
            "every MCP server a repository declares starts without a prompt, so a pull "
            "request that adds a .mcp.json runs code on the next session",
        )
    if path.name == "tasks.json":
        for ti, task in enumerate(doc.get("tasks") or []):
            run_on = (
                ((task or {}).get("runOptions") or {}).get("runOn")
                if isinstance(task, dict)
                else None
            )
            if run_on == "folderOpen":
                add(
                    f"tasks[{ti}] {task.get('label', ti)!r}",
                    "warn",
                    "runs_on_folder_open",
                    "runs automatically when the folder is opened in VS Code, with no action "
                    "from the developer",
                    str(task.get("command", "")),
                )
    for where, event, cmd in _commands(doc, path.name):
        add(where, "info", "runs_automatically", f"runs at {event}: {cmd[:160]}", cmd)
        if _DOWNLOAD_EXEC.search(cmd):
            add(
                where,
                "warn",
                "download_and_execute",
                "downloads code and executes it in one step",
                cmd,
            )
        for eco, spec in install_targets(cmd):
            ecosystem = normalize_ecosystem(eco)
            name, version = parse_spec(spec, eco)
            if not version:
                add(
                    where,
                    "warn",
                    "unpinned_package",
                    f"{name} has no pinned version, so it runs whatever is newest and a freshly "
                    "published malicious release would run on the next start",
                    cmd,
                )
            if checker is None:
                continue
            check = checker(ecosystem, name, version)
            for r in check.reasons:
                add(where, r["level"], f"package_{r['code']}", f"{name}: {r['message']}", cmd)
    return found


def audit(paths: list[Path], checker: Callable[..., Check] | None = None) -> list[ConfigFinding]:
    """Audit the known config files under each directory, or each file given directly."""
    found: list[ConfigFinding] = []
    for root in paths:
        files = [root] if root.is_file() else [root / rel for rel in CONFIG_FILES]
        for f in files:
            if not f.is_file():
                continue
            rel = f.as_posix() if root.is_file() else (f.relative_to(root)).as_posix()
            if f.stat().st_size > _MAX_BYTES:
                found.append(
                    ConfigFinding(rel, "", "warn", "unreadable", "file is too large to audit")
                )
                continue
            found += audit_file(f, f.read_text(encoding="utf-8", errors="replace"), checker, rel)
    return found


def to_json(findings: list[ConfigFinding]) -> str:
    return json.dumps(
        {"worst": worst(findings), "findings": [f.to_dict() for f in findings]}, indent=2
    )
