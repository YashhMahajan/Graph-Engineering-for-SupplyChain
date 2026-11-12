"""Diff parsing and function spans: the model-free base of vulnerable-symbol inference."""

from __future__ import annotations

from scgraph.symbols.code import enclosing, go_functions, identifier_tokens, py_functions
from scgraph.symbols.diff import parse_unified

REQUESTS_FIX = """\
diff --git a/requests/sessions.py b/requests/sessions.py
index 6cb3b4dae3..becb21cd93 100644
--- a/requests/sessions.py
+++ b/requests/sessions.py
@@ -324,7 +324,9 @@ def rebuild_proxies(self, prepared_request, proxies):
         except KeyError:
             username, password = None, None

-        if username and password:
+        # urllib3 handles proxy authorization for us in the standard adapter.
+        # Avoid appending this to TLS tunneled requests where it may be leaked.
+        if not scheme.startswith('https') and username and password:
             headers["Proxy-Authorization"] = _basic_auth_str(username, password)

         return new_proxies
diff --git a/tests/test_requests.py b/tests/test_requests.py
index 1b2c3d..4e5f6a 100644
--- a/tests/test_requests.py
+++ b/tests/test_requests.py
@@ -647,2 +647,4 @@ def test_x(self):
         assert True
+        session.rebuild_proxies(prep, proxies)
+        assert x
         pass
"""


def test_unified_diff_lines_are_numbered_on_both_sides() -> None:
    files = parse_unified(REQUESTS_FIX)
    assert [f.path for f in files] == ["requests/sessions.py", "tests/test_requests.py"]
    h = files[0].hunks[0]
    assert (h.old_start, h.old_len, h.new_start, h.new_len) == (324, 7, 324, 9)
    assert h.removed == [327]
    assert h.added == [327, 328, 329]
    assert h.context.startswith("def rebuild_proxies")
    assert files[1].added_text() == [
        "        session.rebuild_proxies(prep, proxies)",
        "        assert x",
    ]


def test_new_and_deleted_files_and_binary_sections() -> None:
    text = (
        "diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n"
        "@@ -0,0 +1,2 @@\n+def f():\n+    pass\n"
        "diff --git a/old.py b/old.py\ndeleted file mode 100644\n--- a/old.py\n+++ /dev/null\n"
        "@@ -1 +0,0 @@\n-x = 1\n"
        "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
    )
    new, old, img = parse_unified(text)
    assert new.is_new and new.hunks[0].added == [1, 2]
    assert old.is_deleted and old.hunks[0].removed == [1]
    assert img.binary and not img.hunks


def test_a_pure_deletion_is_anchored_where_the_text_used_to_be() -> None:
    text = "--- a/m.py\n+++ b/m.py\n@@ -10,3 +10,2 @@\n a\n-b\n c\n"
    (f,) = parse_unified(text)
    assert f.hunks[0].removed == [11]
    assert f.hunks[0].anchors == [11]


PY = '''\
import os

def top(a, b):
    """Top doc."""
    return helper(a) + os.path.join(b)

def _private():
    def inner():
        return 1
    return inner()

class Session:
    @property
    def name(self):
        return self._name

    def rebuild_proxies(self, req, proxies):
        x = 1
        return self.merge(x)

    class Inner:
        def deep(self):
            pass

if True:
    def conditional():
        pass
'''


def test_python_functions_methods_and_spans() -> None:
    fs = {f.qualname: f for f in py_functions(PY)}
    assert set(fs) == {
        "top",
        "_private",
        "Session.name",
        "Session.rebuild_proxies",
        "Session.Inner.deep",
        "conditional",
    }
    assert fs["top"].doc == "Top doc." and fs["top"].public and not fs["top"].is_method
    assert fs["top"].calls == {"helper", "join"}
    assert not fs["_private"].public
    assert fs["Session.name"].start == 13  # the decorator line
    assert fs["Session.rebuild_proxies"].is_method
    assert "merge" in fs["Session.rebuild_proxies"].calls
    # inner() belongs to _private: it cannot be called from outside
    assert enclosing(list(fs.values()), 9) is fs["_private"]
    assert enclosing(list(fs.values()), 2) is None


def test_python_body_hash_ignores_moves_but_not_edits() -> None:
    a = py_functions("def f(x):\n    return x + 1\n")[0]
    moved = py_functions("\n\n\ndef f(x):\n    return x + 1\n")[0]
    edited = py_functions("def f(x):\n    return x + 2\n")[0]
    assert a.body_hash == moved.body_hash != edited.body_hash


def test_unparseable_python_yields_nothing() -> None:
    assert py_functions("def broken(:\n") == []


GO = """\
package wal

// Create creates a WAL.
func Create(dirpath string) (*WAL, error) {
	w := &WAL{}
	return w, w.decoder.decodeRecord(nil)
}

func (d *decoder) decodeRecord(rec *Record) error {
	if len(rec) > 0 { // check
		return nil
	}
	return validate(rec)
}

func (w WAL) ReadAll() error { return nil }

func Map[K comparable, V any](m map[K]V) {}

func asmStub(x int) int
"""


def test_go_functions_receivers_generics_and_one_liners() -> None:
    fs = {f.qualname: f for f in go_functions(GO)}
    assert set(fs) == {"Create", "decoder.decodeRecord", "WAL.ReadAll", "Map", "asmStub"}
    assert fs["Create"].doc == "Create creates a WAL." and fs["Create"].public
    assert (fs["Create"].start, fs["Create"].end) == (4, 7)
    assert "decodeRecord" in fs["Create"].calls
    assert not fs["decoder.decodeRecord"].public and fs["decoder.decodeRecord"].is_method
    assert fs["decoder.decodeRecord"].calls >= {"validate"}
    assert "if" not in fs["decoder.decodeRecord"].calls
    assert fs["WAL.ReadAll"].start == fs["WAL.ReadAll"].end == 16
    assert fs["asmStub"].start == fs["asmStub"].end


def test_identifier_tokens_split_snake_and_camel_case() -> None:
    assert identifier_tokens("rebuild_proxies") == ["rebuild", "proxies"]
    assert identifier_tokens("ParseHTTPVersion") == ["parse", "http", "version"]
    assert identifier_tokens("decoder.decodeRecord") == ["decoder", "decode", "record"]
