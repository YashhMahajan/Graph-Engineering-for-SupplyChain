"""Run real library scenarios under a profiler and print the functions that executed.

Run with the interpreter of an environment that has requests and flask installed (it does not
need scgraph). Output: JSON {"scenario": [[file, qualname], ...]} of every function defined
under site-packages that ran. Used by eval_transitive.py as dynamic ground truth.
"""

from __future__ import annotations

import http.server
import json
import sys
import threading

executed: dict[str, set[tuple[str, str]]] = {}
current: list[str] = [""]


def prof(frame, event, arg):
    if event == "call":
        co = frame.f_code
        if "site-packages" in co.co_filename:
            executed.setdefault(current[0], set()).add((co.co_filename, co.co_qualname))


def run(name, fn):
    current[0] = name
    sys.setprofile(prof)
    threading.setprofile(prof)
    try:
        fn()
    finally:
        sys.setprofile(None)
        threading.setprofile(None)


def requests_scenario():
    import requests

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_GET  # noqa: N815

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    r = requests.get(base + "/a", params={"q": "é", "n": 1}, headers={"X-T": "1"}, timeout=5)
    r.json()
    requests.post(base + "/b", json={"a": 1}, timeout=5)
    requests.post(base + "/c", data={"a": "1"}, timeout=5)
    s = requests.Session()
    s.auth = ("u", "p")
    _ = s.get(base + "/d", timeout=5).text
    s.close()
    srv.shutdown()


def flask_scenario():
    import flask

    app = flask.Flask(__name__)
    app.secret_key = "k"

    @app.route("/")
    def index():
        flask.session["x"] = 1
        return flask.render_template_string("Hello {{ name|title }} {{ '<b>'|e }}", name="world")

    @app.route("/j", methods=["POST"])
    def j():
        return flask.jsonify(flask.request.get_json())

    c = app.test_client()
    c.get("/")
    c.post("/j", json={"a": [1, 2]})
    c.get("/missing")


if __name__ == "__main__":
    run("requests", requests_scenario)
    run("flask", flask_scenario)
    print(json.dumps({k: sorted(v) for k, v in executed.items()}))
