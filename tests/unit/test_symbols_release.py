"""Released source, entry points, re-export aliases and version brackets (no network)."""

from __future__ import annotations

from scgraph.symbols.entry import aliases, dotted_names, entry_points
from scgraph.symbols.source import Release, bracket

REQ = {
    "requests/__init__.py": "from .api import get, post\nfrom .sessions import Session\n",
    "requests/api.py": (
        "from . import sessions\n\n"
        "def request(method, url):\n    with sessions.Session() as s:\n        return s.request(method, url)\n\n"
        "def get(url):\n    return request('get', url)\n\n"
        "def post(url):\n    return request('post', url)\n"
    ),
    "requests/sessions.py": (
        "class SessionRedirectMixin:\n"
        "    def resolve_redirects(self, resp):\n        return self.rebuild_proxies(resp, None)\n"
        "    def rebuild_proxies(self, req, proxies):\n        return 1\n\n"
        "class Session(SessionRedirectMixin):\n"
        "    def request(self, method, url):\n        return self.send(method)\n"
        "    def send(self, r):\n        return self.resolve_redirects(r)\n"
        "    def _private(self):\n        return self.rebuild_proxies(1, 2)\n"
    ),
    "tests/test_x.py": "def test_a():\n    rebuild_proxies()\n",
}


def rel() -> Release:
    return Release("PyPI", "requests", "2.30.0", dict(REQ))


def test_find_tolerates_repository_prefixes() -> None:
    r = rel()
    assert r.find("requests.sessions", "Session.send") is not None
    assert r.find("src.requests.sessions", "Session.send") is not None
    assert r.find("requests.sessions", "Nope.x") is None
    assert all(not p.startswith("tests/") for _, p, _f in r.functions())


def test_entry_points_climb_to_the_public_api() -> None:
    eps = entry_points(rel(), "requests.sessions", "SessionRedirectMixin.rebuild_proxies")
    names = [f"{m}.{q}" for m, q in eps]
    assert names[0] == "requests.sessions.SessionRedirectMixin.rebuild_proxies"
    assert "requests.sessions.SessionRedirectMixin.resolve_redirects" in names
    assert "requests.sessions.Session.send" in names
    assert "requests.sessions.Session.request" in names
    assert "requests.sessions.Session._private" not in names  # private: not an entry point


def test_cross_module_callers_need_an_import() -> None:
    files = dict(REQ)
    files["other/mod.py"] = "def unrelated():\n    return x.rebuild_proxies()\n"
    eps = entry_points(
        Release("PyPI", "requests", "1", files),
        "requests.sessions",
        "SessionRedirectMixin.rebuild_proxies",
    )
    assert ("other.mod", "unrelated") not in eps


def test_reexports_become_aliases() -> None:
    r = rel()
    al = aliases(r)
    assert al["requests.api.get"] == {"requests.get"}
    assert al["requests.sessions.Session"] == {"requests.Session"}
    names = dotted_names(r, [("requests.api", "get"), ("requests.sessions", "Session.request")])
    assert names == [
        "requests.api.get",
        "requests.get",
        "requests.sessions.Session.request",
        "requests.Session.request",
    ]


def test_go_entry_points_follow_the_package_and_its_importers() -> None:
    files = {
        "wal/decoder.go": "package wal\n\nfunc (d *decoder) decodeRecord(r *Record) error {\n\treturn nil\n}\n",
        "wal/wal.go": "package wal\n\nfunc Create(dir string) error {\n\treturn d.decodeRecord(nil)\n}\n",
        "server/s.go": 'package server\n\nimport "go.etcd.io/etcd/wal"\n\nfunc Start() error {\n\treturn wal.Create("x")\n}\n',
        "other/o.go": "package other\n\nfunc Unrelated() error {\n\treturn Create(nil)\n}\n",
    }
    r = Release("Go", "go.etcd.io/etcd", "3.4.9", files, module="go.etcd.io/etcd")
    eps = entry_points(r, "go.etcd.io/etcd/wal", "decoder.decodeRecord")
    assert eps == [("go.etcd.io/etcd/wal", "Create"), ("go.etcd.io/etcd/server", "Start")]


def test_bracket_finds_last_affected_and_first_fixed() -> None:
    rec = {
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}
                ],
            }
        ]
    }
    vs = ["2.2.0", "2.3.0", "2.29.0", "2.30.0", "2.31.0", "2.32.0"]
    assert bracket(rec, "PyPI", "requests", vs) == ("2.30.0", "2.31.0")
    assert bracket(rec, "PyPI", "other", vs) == ("", "")
