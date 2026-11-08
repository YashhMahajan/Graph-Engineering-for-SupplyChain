"""The pre-install guard, the Claude Code hook, the MCP server and the CLI."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from scgraph.scan.agent import claude_code_hook, handle_mcp, install_targets, serve_mcp
from scgraph.scan.guard import Check, check_package, parse_spec, typosquat_of

NOW = datetime(2026, 11, 3, tzinfo=UTC)


class NoOSV:
    def query(self, pkgs):
        return {}


class OneMal:
    def query(self, pkgs):
        return {0: [{"id": "MAL-2025-46969"}, {"id": "GHSA-x"}]}


def registry(docs):
    def fetch(url):
        for k, v in docs.items():
            if url.endswith(k):
                return v
        return None

    return fetch


NPM_LEFTPAD = {
    "/left-pad": {
        "time": {
            "created": "2014-03-01T00:00:00Z",
            "1.3.0": "2018-04-01T00:00:00Z",
            "1.4.0": "2026-11-02T20:00:00Z",
        },
        "dist-tags": {"latest": "1.3.0"},
        "versions": {
            "1.3.0": {"scripts": {"test": "x"}},
            "1.4.0": {"scripts": {"postinstall": "node steal.js"}},
        },
        "maintainers": [{}],
    }
}


def test_guard_blocks_hallucinated_names_and_suggests() -> None:
    c = check_package("pypi", "reqeusts", fetch=registry({}), osv=NoOSV(), now=NOW)
    assert c.verdict == "block"
    assert [r["code"] for r in c.reasons] == ["nonexistent", "typosquat"]
    assert "requests" in c.reasons[1]["message"]


def test_guard_allows_a_quiet_old_release() -> None:
    c = check_package("npm", "left-pad", "1.3.0", fetch=registry(NPM_LEFTPAD), osv=NoOSV(), now=NOW)
    assert c.verdict == "allow" and c.reasons == []


def test_guard_warns_on_fresh_release_with_install_script() -> None:
    c = check_package("npm", "left-pad", "1.4.0", fetch=registry(NPM_LEFTPAD), osv=NoOSV(), now=NOW)
    assert c.verdict == "warn"
    # the new-install-script signal replaces the generic one, it does not repeat it
    assert {r["code"] for r in c.reasons} == {"fresh_release", "install_script_added"}


def _pkg(*releases, **top):
    """An npm registry document. releases: (version, ISO time, version document)."""
    return {
        "/pkg": {
            "time": {"created": "2020-01-01T00:00:00Z", **{v: t for v, t, _ in releases}},
            "dist-tags": {"latest": releases[-1][0]},
            "versions": {v: d for v, _, d in releases},
            "maintainers": [{"name": "alice"}],
            **top,
        }
    }


def _v(user="alice", maintainers=("alice",), attested=False, scripts=None):
    d = {
        "_npmUser": {"name": user},
        "maintainers": [{"name": m} for m in maintainers],
        "dist": {"attestations": {"url": "x"}} if attested else {},
    }
    if scripts:
        d["scripts"] = scripts
    return d


def test_guard_flags_a_release_that_looks_like_an_account_takeover() -> None:
    docs = _pkg(
        ("1.0.0", "2026-10-01T00:00:00Z", _v(attested=True)),
        ("1.0.1", "2026-10-30T00:00:00Z", _v("mallory", ("alice", "mallory"))),
    )
    c = check_package("npm", "pkg", "1.0.1", fetch=registry(docs), osv=NoOSV(), now=NOW)
    assert c.verdict == "warn"
    assert {r["code"] for r in c.reasons} == {
        "publisher_changed",
        "maintainer_added",
        "provenance_dropped",
    }
    assert next(r for r in c.reasons if r["code"] == "publisher_changed")["message"].count("'") == 4


def test_guard_stays_quiet_for_an_unremarkable_recent_release() -> None:
    docs = _pkg(("1.0.0", "2026-10-01T00:00:00Z", _v()), ("1.0.1", "2026-10-20T00:00:00Z", _v()))
    c = check_package("npm", "pkg", "1.0.1", fetch=registry(docs), osv=NoOSV(), now=NOW)
    assert c.verdict == "allow" and c.reasons == []


def test_guard_keeps_the_generic_install_script_warning_when_there_is_no_history() -> None:
    docs = _pkg(("1.0.0", "2026-10-01T00:00:00Z", _v(scripts={"postinstall": "node x.js"})))
    c = check_package("npm", "pkg", "1.0.0", fetch=registry(docs), osv=NoOSV(), now=NOW)
    assert [r["code"] for r in c.reasons] == ["install_scripts"]


def test_guard_reports_a_failed_history_comparison_instead_of_assuming_it_is_fine(
    monkeypatch,
) -> None:
    import scgraph.scan.guard as guard

    def boom(*a, **k):
        raise ValueError("bad history")

    monkeypatch.setattr(guard, "npm_release_anomalies", boom)
    docs = _pkg(("1.0.0", "2026-10-01T00:00:00Z", _v()), ("1.0.1", "2026-10-20T00:00:00Z", _v()))
    c = check_package("npm", "pkg", "1.0.1", fetch=registry(docs), osv=NoOSV(), now=NOW)
    assert c.verdict == "warn"
    assert [r["code"] for r in c.reasons] == ["unverified"]
    assert "bad history" in c.reasons[0]["message"]


def test_guard_blocks_malicious_release() -> None:
    c = check_package(
        "npm", "left-pad", "1.3.0", fetch=registry(NPM_LEFTPAD), osv=OneMal(), now=NOW
    )
    assert c.verdict == "block"
    assert {r["code"] for r in c.reasons} == {"malicious", "vulnerable"}


def test_guard_never_turns_a_failed_lookup_into_allow() -> None:
    def boom(url):
        raise OSError("network down")

    class BoomOSV:
        def query(self, pkgs):
            raise OSError("down")

    c = check_package("npm", "left-pad", "1.3.0", fetch=boom, osv=BoomOSV(), now=NOW)
    assert c.verdict == "warn"
    assert {r["code"] for r in c.reasons} == {"unverified"}


def test_typosquat_and_spec_parsing() -> None:
    assert typosquat_of("lodahs", "npm") == "lodash"  # transposition
    assert typosquat_of("expres", "npm") == "express"  # deletion
    assert typosquat_of("dateutil-python", "PyPI") == "python-dateutil"  # reordering
    assert typosquat_of("lodash", "npm") is None  # the real one
    assert typosquat_of("left-pad", "npm") is None
    assert parse_spec("@types/node@20.1.0", "npm") == ("@types/node", "20.1.0")
    assert parse_spec("react@latest", "npm") == ("react", None)
    assert parse_spec("Django[argon2]==3.2.0", "PyPI") == ("django", "3.2.0")
    assert parse_spec("flask>=2", "PyPI") == ("flask", None)


@pytest.mark.parametrize(
    ("cmd", "want"),
    [
        (
            "npm install lodash@4.17.21 -D @types/node",
            [("npm", "lodash@4.17.21"), ("npm", "@types/node")],
        ),
        ("cd web && pnpm add react && yarn add vue", [("npm", "react"), ("npm", "vue")]),
        ("npm ci", []),
        ("npx create-react-app my-app", [("npm", "create-react-app")]),
        (
            "pip install -r requirements.txt requests==2.31.0 ./local -e .",
            [("pypi", "requests==2.31.0")],
        ),
        ("python -m pip install --index-url https://x flask", [("pypi", "flask")]),
        ("uv add httpx; uv pip install rich", [("pypi", "httpx"), ("pypi", "rich")]),
        ("uvx ruff check .", [("pypi", "ruff")]),
        ("cargo add serde --features derive", [("cargo", "serde")]),
        ("go get github.com/pkg/errors@v0.9.1", [("go", "github.com/pkg/errors@v0.9.1")]),
        ("CI=1 sudo gem install rails", [("gem", "rails")]),
        ("ls -la && echo npm install x", []),
    ],
)
def test_install_targets(cmd: str, want) -> None:
    assert install_targets(cmd) == want


def _checker(verdicts):
    def check(eco, name, ver):
        c = Check(eco, name, ver)
        v = verdicts.get(name, "allow")
        if v != "allow":
            c.add(v, "x", f"{name} flagged")
        return c

    return check


def test_claude_code_hook_decisions() -> None:
    ev = {"tool_name": "Bash", "tool_input": {"command": "npm i good bad"}}
    deny = claude_code_hook(ev, _checker({"bad": "block"}))
    assert deny["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "bad flagged" in deny["hookSpecificOutput"]["permissionDecisionReason"]
    ask = claude_code_hook(ev, _checker({"bad": "warn"}))
    assert ask["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert claude_code_hook(ev, _checker({})) is None
    assert (
        claude_code_hook({"tool_name": "Read", "tool_input": {}}, _checker({"bad": "block"}))
        is None
    )


def test_mcp_protocol_round_trip() -> None:
    deps = {"check": _checker({"evil": "block"}), "scan": lambda a, p: [], "osv": lambda: None}
    msgs = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "check_package", "arguments": {"ecosystem": "npm", "name": "evil"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        },
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "check_package", "arguments": {}},
        },
        {"jsonrpc": "2.0", "id": 6, "method": "resources/list"},
    ]
    out = io.StringIO()
    serve_mcp(io.StringIO("\n".join(json.dumps(m) for m in msgs) + "\nnot json\n"), out, deps)
    resp = [json.loads(x) for x in out.getvalue().splitlines()]
    assert [r.get("id") for r in resp] == [1, 2, 3, 4, 5, 6, None]  # the notification gets no reply
    assert resp[0]["result"]["protocolVersion"] == "2025-03-26"
    assert {t["name"] for t in resp[1]["result"]["tools"]} == {
        "check_package",
        "scan_lockfile",
        "explain_advisory",
    }
    body = json.loads(resp[2]["result"]["content"][0]["text"])
    assert body["verdict"] == "block"
    assert resp[3]["error"]["code"] == -32602
    assert resp[4]["result"]["isError"] is True
    assert resp[5]["error"]["code"] == -32601
    assert resp[6]["error"]["code"] == -32700
    assert handle_mcp({"jsonrpc": "2.0", "method": "notifications/cancelled"}) is None
