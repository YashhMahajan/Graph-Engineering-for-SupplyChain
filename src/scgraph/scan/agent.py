"""Guard rails for AI coding agents: a Claude Code hook and an MCP server.

``install_targets(command)``  which packages a shell command would install or execute
                              (npm/pnpm/yarn/bun add, npx, pip/uv/poetry/pipx, uvx,
                              cargo add/install, gem install, composer require, go get)
``claude_code_hook(event)``   a ``PreToolUse`` hook: deny on ``block``, ask on ``warn``,
                              stay silent on ``allow`` (normal permissions still apply)
``serve_mcp()``               a Model Context Protocol server over stdio, written against
                              the JSON-RPC spec with no extra dependency. Tools:
                              ``check_package``, ``scan_lockfile``, ``explain_advisory``.

Wire the hook in ``.claude/settings.json``::

    {"hooks": {"PreToolUse": [{"matcher": "Bash",
      "hooks": [{"type": "command", "command": "scgraph hook claude-code"}]}]}}

and the server with ``claude mcp add scgraph -- scgraph mcp``.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from collections.abc import Callable
from typing import Any

from .. import __version__
from .guard import Check, check_package, parse_spec

__all__ = ["claude_code_hook", "handle_mcp", "install_targets", "serve_mcp"]

# flags whose next token is a value, not a package
_VALUE_FLAGS = {
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "-f",
    "--find-links",
    "--python",
    "-p",
    "--registry",
    "--cache",
    "--tag",
    "--version",
    "--source",
    "--group",
    "-G",
    "--path",
    "--git",
    "--branch",
    "--rev",
    "--features",
    "-F",
    "--with",
    "--from",
}


def _segments(command: str) -> list[list[str]]:
    out = []
    for seg in re.split(r"&&|\|\||;|\||\n", command):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):  # FOO=bar cmd
            toks = toks[1:]
        while toks and toks[0] in ("sudo", "env", "time", "exec", "command"):
            toks = toks[1:]
        if toks:
            out.append(toks)
    return out


def _positional(toks: list[str]) -> list[str]:
    out, skip = [], False
    for t in toks:
        if skip:
            skip = False
            continue
        if t.startswith("-"):
            if t in _VALUE_FLAGS:
                skip = True
            continue
        out.append(t)
    return out


def _looks_like_package(t: str) -> bool:
    return not (
        t in (".", "..")
        or t.startswith(("./", "../", "/", "~", "git+", "http://", "https://", "file:"))
        or t.endswith((".txt", ".whl", ".tar.gz", ".zip", ".tgz", ".toml"))
    )


def install_targets(command: str) -> list[tuple[str, str]]:
    """``[(ecosystem, spec), ...]`` that ``command`` would fetch from a registry."""
    found: list[tuple[str, str]] = []
    for toks in _segments(command):
        tool = toks[0].rsplit("/", 1)[-1]
        rest = toks[1:]
        if tool in ("python", "python3") and rest[:2] == ["-m", "pip"]:
            tool, rest = "pip", rest[2:]
        if tool == "uv" and rest[:1] == ["pip"]:
            tool, rest = "pip", rest[1:]
        eco, specs = None, []
        if tool in ("npm", "pnpm", "yarn", "bun"):
            if (rest and rest[0] in ("install", "i", "add", "in", "isntall", "ci")) or (
                tool == "pnpm" and rest[:1] == ["dlx"]
            ):
                eco, specs = "npm", _positional(rest[1:])
            elif tool == "bun" and rest[:1] == ["x"]:
                eco, specs = "npm", _positional(rest[1:])[:1]
        elif tool in ("npx", "bunx"):
            eco, specs = "npm", _positional(rest)[:1]
        elif tool in ("pip", "pip3"):
            if rest[:1] == ["install"]:
                eco, specs = "pypi", _positional(rest[1:])
        elif tool in ("uv", "poetry", "pdm", "rye"):
            if rest[:1] == ["add"]:
                eco, specs = "pypi", _positional(rest[1:])
        elif tool == "pipx":
            if rest[:1] in (["install"], ["run"]):
                eco, specs = "pypi", _positional(rest[1:])[:1]
        elif tool == "uvx":
            eco, specs = "pypi", _positional(rest)[:1]
        elif tool == "cargo":
            if rest[:1] in (["add"], ["install"]):
                eco, specs = "cargo", _positional(rest[1:])
        elif tool == "gem":
            if rest[:1] == ["install"]:
                eco, specs = "gem", _positional(rest[1:])
        elif tool == "composer":
            if rest[:1] == ["require"]:
                eco, specs = "composer", _positional(rest[1:])
        elif tool == "go" and rest[:1] in (["get"], ["install"]):
            eco, specs = "go", [s for s in _positional(rest[1:]) if "." in s.split("/")[0]]
        if eco:
            found.extend((eco, s) for s in specs if _looks_like_package(s))
    return found


def _check_all(command: str, checker: Callable[..., Check]) -> list[Check]:
    out = []
    for eco, spec in install_targets(command):
        from .guard import normalize_ecosystem

        name, ver = parse_spec(spec, normalize_ecosystem(eco))
        out.append(checker(eco, name, ver))
    return out


def claude_code_hook(event: dict, checker: Callable[..., Check] = check_package) -> dict | None:
    """A Claude Code ``PreToolUse`` hook decision, or None to stay out of the way."""
    if event.get("tool_name") != "Bash":
        return None
    cmd = (event.get("tool_input") or {}).get("command") or ""
    checks = _check_all(cmd, checker)
    flagged = [c for c in checks if c.verdict != "allow"]
    if not flagged:
        return None
    decision = "deny" if any(c.verdict == "block" for c in flagged) else "ask"
    reason = "scgraph package guard:\n" + "\n".join(c.line() for c in flagged)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


# ------------------------------------------------------------------------------ MCP
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

TOOLS = [
    {
        "name": "check_package",
        "description": (
            "Call this BEFORE adding, installing or running (npx/uvx) any third-party package. "
            "Returns allow, warn or block with reasons: the name does not exist (hallucinated), "
            "a known malicious release, a release younger than the cooldown, a typosquat of a "
            "popular package, install scripts, known vulnerabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "description": "npm, pypi, cargo, go, gem or composer",
                },
                "name": {"type": "string"},
                "version": {"type": "string", "description": "optional; defaults to the latest"},
            },
            "required": ["ecosystem", "name"],
        },
    },
    {
        "name": "scan_lockfile",
        "description": (
            "Scan a lockfile (package-lock.json, yarn.lock, poetry.lock, uv.lock, Cargo.lock, "
            "requirements.txt, Pipfile.lock, go.mod, Gemfile.lock, composer.lock) or a directory "
            "of them. Every alert carries the dependency path that proves it and the smallest "
            "safe upgrade; non-actionable findings are abstentions with a reason."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "a lockfile or a directory"},
                "content": {"type": "string", "description": "lockfile text, instead of path"},
                "filename": {
                    "type": "string",
                    "description": "the lockfile's name when content is given",
                },
                "include_dev": {"type": "boolean"},
                "min_severity": {"type": "number"},
            },
        },
    },
    {
        "name": "explain_advisory",
        "description": (
            "Explain one advisory (CVE, GHSA, PYSEC, MAL id): summary, "
            "affected and fixed versions, KEV and EPSS."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
]


def _tool(name: str, args: dict, deps: dict) -> Any:
    if name == "check_package":
        return deps["check"](args["ecosystem"], args["name"], args.get("version")).to_dict()
    if name == "scan_lockfile":
        from .engine import Policy

        pol = Policy(
            min_severity=float(args.get("min_severity") or 0),
            include_dev=bool(args.get("include_dev")),
        )
        results = deps["scan"](args, pol)
        return {
            "lockfiles": [
                {
                    "path": r.path,
                    "packages": r.n_packages,
                    "alerts": [
                        {
                            k: f.to_dict()[k]
                            for k in (
                                "priority",
                                "id",
                                "package",
                                "version",
                                "severity",
                                "kev",
                                "epss",
                                "path",
                                "fix",
                            )
                        }
                        for f in r.alerts
                    ],
                    "abstained": r.abstention_counts(),
                    "fix_plan": r.remediation,
                }
                for r in results
            ]
        }
    if name == "explain_advisory":
        rec = deps["osv"]().get(args["id"])
        if not rec:
            return {"error": f"no advisory {args['id']}"}
        from .engine import _score
        from .sources import Signals

        sig = Signals()
        cves = [x for x in [rec["id"], *(rec.get("aliases") or [])] if x.startswith("CVE-")]
        ep = sig.epss(cves)
        return {
            "id": rec["id"],
            "aliases": rec.get("aliases", []),
            "summary": rec.get("summary") or (rec.get("details") or "")[:500],
            "published": rec.get("published"),
            "withdrawn": rec.get("withdrawn"),
            "malicious": rec["id"].startswith("MAL-"),
            "cvss": _score([rec]),
            "kev": any(c in sig.kev() for c in cves),
            "epss": {c: ep[c][0] for c in cves if c in ep},
            "affected": [
                {
                    "ecosystem": (a.get("package") or {}).get("ecosystem"),
                    "name": (a.get("package") or {}).get("name"),
                    "ranges": [r.get("events") for r in a.get("ranges") or []],
                }
                for a in rec.get("affected") or []
            ][:20],
            "references": [r.get("url") for r in rec.get("references") or []][:10],
            "vulnerable_function": _vulnerable_function(rec),
        }
    raise KeyError(name)


def _vulnerable_function(rec: dict) -> dict | None:
    """The verified vulnerable function from the shipped dataset, when it has one. The answer
    carries its evidence, so an agent can quote it. An unreadable dataset gives None."""
    from ..symbols import dataset

    try:
        hit = dataset.load().get([rec["id"], *(rec.get("aliases") or [])])
    except dataset.DatasetError:
        return None
    if hit is None:
        return None
    ev = hit.get("evidence") or {}
    return {
        "package": hit["package"],
        "symbol": hit["symbol"],
        "entry_points": hit.get("entry_points", [])[:10],
        "method": hit["method"],
        "confidence": hit.get("confidence"),
        "evidence": ev.get("fix") or "code search of the affected release",
    }


def _default_deps() -> dict:
    from pathlib import Path

    from .lockfiles import find_lockfiles, parse
    from .sources import Signals, default_osv, http_json

    def scan(args: dict, pol):
        from .engine import scan_graph

        src, sig = default_osv(), Signals()
        if args.get("content"):
            graphs = [parse(args.get("filename") or "package-lock.json", args["content"])]
        else:
            graphs = [parse(p) for p in find_lockfiles(Path(args.get("path") or "."))]
        return [scan_graph(g, src, sig, pol, registry=http_json) for g in graphs]

    return {"check": check_package, "scan": scan, "osv": default_osv}


def handle_mcp(msg: dict, deps: dict | None = None) -> dict | None:
    """One JSON-RPC message in, one response out (None for notifications)."""
    mid = msg.get("id")
    method = msg.get("method", "")
    if mid is None:
        return None
    try:
        if method == "initialize":
            want = (msg.get("params") or {}).get("protocolVersion")
            result: Any = {
                "protocolVersion": want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "scgraph", "version": __version__},
                "instructions": "Check every package with check_package before installing it.",
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            p = msg.get("params") or {}
            try:
                out = _tool(p.get("name", ""), p.get("arguments") or {}, deps or _default_deps())
                result = {
                    "content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                    "isError": False,
                }
            except KeyError as e:
                if str(e).strip("'") == p.get("name"):
                    return {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32602, "message": f"unknown tool {e}"},
                    }
                result = {
                    "content": [{"type": "text", "text": f"missing argument {e}"}],
                    "isError": True,
                }
            except Exception as e:
                result = {
                    "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                    "isError": True,
                }
        else:
            return {
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
    except Exception as e:  # pragma: no cover - defensive
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def serve_mcp(stdin=None, stdout=None, deps: dict | None = None) -> None:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            resp: dict | None = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }
        else:
            resp = handle_mcp(msg, deps)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
