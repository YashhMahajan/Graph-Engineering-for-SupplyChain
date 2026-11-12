"""Engine A: fix diff -> candidates -> ranking, with no model and no network."""

from __future__ import annotations

from test_symbols_code import REQUESTS_FIX

from scgraph.symbols.candidates import (
    build_candidates,
    go_package,
    is_test_path,
    py_module,
)
from scgraph.symbols.diff import parse_unified
from scgraph.symbols.fetch import fix_refs
from scgraph.symbols.rank import HEURISTIC, Ranker, features, rank

SESSIONS_PY = "\n" * 300 + (
    "class SessionRedirectMixin:\n"  # line 301
    + "    def resolve_redirects(self, resp, req):\n"  # 302
    + "        return self.rebuild_proxies(req, None)\n"  # 303
    + "\n" * 16  # 304-319
    + "    def rebuild_proxies(self, prepared_request, proxies):\n"  # 320
    + "        headers = prepared_request.headers\n" * 3  # 321-323
    + "        try:\n"  # 324
    + "            username, password = get_auth(new_proxies[scheme])\n"
    + "        except KeyError:\n"
    + "            username, password = None, None\n"
    + "\n"
    + "        # urllib3 handles proxy authorization for us in the standard adapter.\n"
    + "        # Avoid appending this to TLS tunneled requests where it may be leaked.\n"
    + "        if not scheme.startswith('https') and username and password:\n"
    + '            headers["Proxy-Authorization"] = _basic_auth_str(username, password)\n'
    + "\n"
    + "        return new_proxies\n"
)
ADVISORY = (
    "Unintended leak of Proxy-Authorization header in requests. Requests forwards "
    "proxy-authorization headers to destination servers when following HTTPS redirects."
)


def test_paths_tests_and_module_names() -> None:
    assert is_test_path("tests/test_requests.py")
    assert is_test_path("pkg/foo_test.go")
    assert is_test_path("docs/conf.py") and is_test_path("vendor/x/y.go")
    assert not is_test_path("requests/sessions.py")
    assert py_module("src/pkg/sub/mod.py") == "pkg.sub.mod"
    assert py_module("lib/yaml/__init__.py") == "yaml"
    assert py_module("requests/sessions.py") == "requests.sessions"
    assert go_package("go.etcd.io/etcd", "wal/decoder.go") == "go.etcd.io/etcd/wal"
    assert go_package("github.com/a/b", "b.go") == "github.com/a/b"


def test_the_requests_fix_yields_rebuild_proxies_and_its_caller() -> None:
    cs = build_candidates(
        parse_unified(REQUESTS_FIX), {"requests/sessions.py": SESSIONS_PY}, ADVISORY
    )
    by = {c.qualname: c for c in cs.candidates}
    assert set(by) == {
        "SessionRedirectMixin.rebuild_proxies",
        "SessionRedirectMixin.resolve_redirects",
    }
    patched = by["SessionRedirectMixin.rebuild_proxies"]
    assert patched.symbol == "requests.sessions.SessionRedirectMixin.rebuild_proxies"
    assert (patched.added, patched.removed) == (3, 1)
    assert patched.test_refs == 1  # the fix's test calls session.rebuild_proxies
    assert patched.adds_check and not patched.new_function and patched.public
    caller = by["SessionRedirectMixin.resolve_redirects"]
    assert caller.via_caller and caller.callee == "rebuild_proxies" and caller.changed == 0
    assert cs.code_files == 1 and cs.test_files == 1
    assert "Proxy-Authorization" in cs.excerpt(patched)
    best = rank(cs.candidates, Ranker(weights=dict(HEURISTIC)))
    assert best[0] is patched and best[0].score > best[1].score


def test_a_missing_source_falls_back_to_the_hunk_header() -> None:
    cs = build_candidates(parse_unified(REQUESTS_FIX), {}, ADVISORY)
    assert [c.qualname for c in cs.candidates] == ["rebuild_proxies"]
    assert cs.missing_sources == 1


def test_a_function_the_fix_introduces_is_flagged_and_ranked_down() -> None:
    diff = (
        "--- a/pkg/m.py\n+++ b/pkg/m.py\n@@ -1,2 +1,6 @@\n"
        "+def _sanitize(x):\n+    return x.replace('..', '')\n+\n+\n"
        " def load(path):\n-    return open(path)\n+    return open(_sanitize(path))\n"
    )
    src = "def _sanitize(x):\n    return x.replace('..', '')\n\n\ndef load(path):\n    return open(_sanitize(path))\n"
    cs = build_candidates(parse_unified(diff), {"pkg/m.py": src}, "path traversal in load")
    by = {c.qualname: c for c in cs.candidates}
    assert by["_sanitize"].new_function and not by["load"].new_function
    assert by["load"].name_in_advisory
    assert rank(cs.candidates, Ranker(weights=dict(HEURISTIC)))[0].qualname == "load"


GO_DIFF = """\
--- a/wal/decoder.go
+++ b/wal/decoder.go
@@ -8,3 +8,6 @@ func (d *decoder) decodeRecord(rec *Record) error {
 	x := 1
+	if len(rec.Data) > maxSize {
+		return ErrMaxSize
+	}
 	return nil
"""
GO_SRC = """\
package wal

func Create(dir string) error {
	var d decoder
	return d.decodeRecord(nil)
}
func (d *decoder) decodeRecord(rec *Record) error {
	x := 1
	if len(rec.Data) > maxSize {
		return ErrMaxSize
	}
	return nil
}
"""


def test_go_callers_are_candidates_with_the_package_path() -> None:
    cs = build_candidates(
        parse_unified(GO_DIFF),
        {"wal/decoder.go": GO_SRC},
        "etcd WAL decodeRecord",
        "go.etcd.io/etcd",
    )
    by = {c.qualname: c for c in cs.candidates}
    assert by["decoder.decodeRecord"].symbol == "go.etcd.io/etcd/wal.decoder.decodeRecord"
    assert not by["decoder.decodeRecord"].public
    assert by["Create"].via_caller and by["Create"].public


def test_feature_vector_length_and_fit_roundtrip() -> None:
    cs = build_candidates(
        parse_unified(REQUESTS_FIX), {"requests/sessions.py": SESSIONS_PY}, ADVISORY
    )
    groups = [cs.candidates] * 3
    labels = [[c.qualname.endswith("rebuild_proxies") for c in cs.candidates]] * 3
    r = Ranker.fit(groups, labels, trained_on="unit")
    assert len(features(cs.candidates[0])) == len(r.weights)
    again = Ranker.from_json(r.to_json())
    assert again.weights == r.weights and again.trained_on == "unit"
    assert rank(cs.candidates, again)[0].qualname.endswith("rebuild_proxies")


def test_fix_refs_prefer_fix_commits_and_dedupe() -> None:
    rec = {
        "references": [
            {
                "type": "WEB",
                "url": "https://github.com/psf/requests/commit/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5",
            },
            {"type": "FIX", "url": "https://github.com/gin-gonic/gin/pull/2237"},
            {"type": "FIX", "url": "https://github.com/psf/requests/commit/74ea7cf7a6a2"},
            {"type": "WEB", "url": "https://github.com/a/b/pull/3/commits/abcdef1234567"},
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-1"},
        ]
    }
    refs = fix_refs(rec)
    assert [(r.repo, r.kind) for r in refs] == [
        ("requests", "commit"),
        ("b", "commit"),
        ("gin", "pull"),
    ]
    assert refs[0].diff_url.endswith("/psf/requests/commit/74ea7cf7a6a2.diff")
