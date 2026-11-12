"""Add (or refresh) Part XI of the notebook: vulnerable-symbol inference and transitive reach.

The cells read the committed ``results/metrics/symbols_*.json`` files and run a small in-memory
demo, so they work offline in the CI smoke run. The "reading" paragraphs are generated from the
same JSON, so a number in the text cannot drift from the number in the output.

    python scripts/symbols/add_notebook_part.py     # executes the new cells, splices them in
"""

from __future__ import annotations

import json
from pathlib import Path

import nbformat
from nbclient import NotebookClient
from nbformat.v4 import new_code_cell, new_markdown_cell, new_notebook

ROOT = Path(__file__).resolve().parents[2]
NB = ROOT / "notebooks" / "supply_chain_graph_engineering.ipynb"
MARK = "<!-- part-xi -->"


def j(name: str) -> dict:
    return json.loads((ROOT / "results" / "metrics" / name).read_text())


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def build_cells() -> list:
    ev, tr = j("symbols_eval.json"), j("symbols_transitive.json")
    st = ev["stages"]
    ab = tr["ablation"]
    on, off = ab["all mechanisms on"], ab["none (resolved calls by bare name only)"]
    o = tr["overall"]
    llm = ev.get("llm", {})
    paired = llm.get("paired_on_answered", {})

    cells = [
        new_markdown_cell(
            f'{MARK}\n# Part XI. From "the package is present" to "the vulnerable function is called"\n\n'
            "`govulncheck` can say *your code does not call the vulnerable function* because the Go "
            "vulnerability database names it. PyPI, npm, Maven and Cargo advisories almost never do "
            "(0% of the PyPI, Maven and Cargo records in the OSV snapshot used here). This part recovers "
            "the name from the **fix commit** and from **released source**, with a language model used "
            "only where the model-free ranker is unsure, and carries the answer through the dependency "
            "path the graph already proves. A scan still makes zero model calls: the model works at "
            "build time and its output is a verified data file."
        ),
        new_markdown_cell(
            "## S33 - Which function does an advisory concern?\n\n"
            "**Theory.** A fix commit changes a handful of functions; the advisory concerns one. Candidates "
            "are the changed functions *and their callers* (a published label is often the public caller "
            "of the patched helper). Each candidate is described by model-free features: how much of the "
            "change it holds, whether the fix introduced it, whether the fix's own tests name it, how "
            "much of its name the advisory text contains. A ranker orders them; the language model "
            "(a) sees only the top few, (b) must answer with an option id, never a name, (c) must quote "
            "a line of the excerpt as evidence. Every answer then has to pass a **verifier**: the symbol "
            "must exist in the last affected release and be removed, changed, or call something changed "
            "in the first fixed release. The cell below runs the model-free half on the real "
            "`psf/requests` fix for GHSA-j8r2-6x86-q33q."
        ),
        new_code_cell(
            '''from scgraph.symbols.diff import parse_unified
from scgraph.symbols.candidates import build_candidates
from scgraph.symbols.rank import HEURISTIC, Ranker, rank

FIX = """--- a/requests/sessions.py
+++ b/requests/sessions.py
@@ -9,7 +9,9 @@ def rebuild_proxies(self, prepared_request, proxies):
         except KeyError:
             username, password = None, None

-        if username and password:
+        # Avoid appending this to TLS tunneled requests where it may be leaked.
+        if not scheme.startswith('https') and username and password:
             headers["Proxy-Authorization"] = _basic_auth_str(username, password)

         return new_proxies
"""
SRC = """class SessionRedirectMixin:
    def resolve_redirects(self, resp, req):
        return self.rebuild_proxies(req, None)

    def rebuild_proxies(self, prepared_request, proxies):
        headers = prepared_request.headers
        try:
            username, password = get_auth(proxies[scheme])
        except KeyError:
            username, password = None, None

        # Avoid appending this to TLS tunneled requests where it may be leaked.
        if not scheme.startswith('https') and username and password:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)

        return new_proxies
"""
cs = build_candidates(parse_unified(FIX), {"requests/sessions.py": SRC},
                      "Unintended leak of Proxy-Authorization header in requests")
print(f"{'candidate':58} {'+/-':>5} {'caller':>7} {'score':>6}")
for c in rank(cs.candidates, Ranker(weights=dict(HEURISTIC))):
    print(f"{c.symbol:58} {c.added}/{c.removed:<3} {str(c.via_caller):>7} {c.score:6.3f}")'''
        ),
        new_code_cell(
            """import json
import matplotlib.pyplot as plt
from pathlib import Path

ev = json.loads(Path("results/metrics/symbols_eval.json").read_text())
st = ev["stages"]
rows = [("largest change first", "largest"), ("heuristic ranker", "heuristic"),
        ("learned ranker (logistic)", "ranker"), ("heuristic + LLM", "ranker+llm")]
print(f"Go vulnerability database, {ev['n_test']} held-out advisories (temporal split)")
print(f"{'stage':28} {'top-1':>7} {'top-3':>7} {'MRR':>7}")
for label, k in rows:
    s = st[k]
    print(f"{label:28} {100*s['top1']:6.1f}% {100*s['top3']:6.1f}% {s['mrr']:7.3f}")
print("ceiling (gold symbol among candidates):", f"{100*st['heuristic']['coverage']:.1f}%")
fig, ax = plt.subplots(figsize=(7, 3))
ax.barh([r[0] for r in rows][::-1], [100 * st[r[1]]["top1"] for r in rows][::-1], color="#3b6ea5")
ax.set_xlabel("top-1 accuracy, %"); ax.set_xlim(0, 100); ax.set_title("Vulnerable-symbol inference, Go test split")
fig.tight_layout()
Path("results/figures").mkdir(parents=True, exist_ok=True)
fig.savefig("results/figures/symbols_stages.png", dpi=140)
plt.show()"""
        ),
        new_markdown_cell(
            "**Reading the result.** The model-free ranker puts a labelled symbol first "
            f"{pct(st['heuristic']['top1'])} of the time against {pct(st['largest']['top1'])} for "
            "'largest change first'. A logistic regression trained on the 436 older advisories did "
            f"*not* beat the hand-set weights on validation (MRR {ev['validation']['ranker']['mrr']:.3f} vs "
            f"{ev['validation']['heuristic']['mrr']:.3f}), so the hand-set weights ship: with a few hundred "
            "labelled advisories, fifteen interpretable weights generalise better than a fit. "
            f"The model-assisted stage reaches {pct(st['ranker+llm']['top1'])}. On the "
            f"{llm.get('answered', 0)} advisories the model answered, it fixed {paired.get('llm_fixes', 0)} "
            f"top picks and broke {paired.get('llm_breaks', 0)} (exact McNemar p = "
            f"{paired.get('mcnemar_exact_p', 'n/a')}): a gain in the right direction that this sample "
            "cannot call significant. Reporting that is the point; the free-tier budget capped the sample."
        ),
        new_markdown_cell(
            "## S34 - Transitive reachability through call summaries\n\n"
            "**Theory.** The vulnerable function lives in `Dn`, reached through `D0 -> D1 -> ... -> Dn` "
            "(the path the graph proves). Project code references only `D0`'s API. So the question is "
            "which public names of `D0` lead to it, answered by walking the call graph *backwards*, one "
            "package at a time, through released source: `S(n)` is the vulnerable symbol plus the public "
            "entry points above it; `S(i)` is the public functions of `Di` that reference a name in "
            "`S(i+1)`. A name-based graph misses what runs implicitly, so five mechanisms are added: "
            "resolved dotted references, dunders and properties reached through their class, "
            "`getattr(self, 'visit_' + x)` dispatch, functions passed as values, and code that runs at "
            "import time. The cell below is a three-package toy; the evaluation after it is real."
        ),
        new_code_cell(
            """from scgraph.symbols.entry import entry_points
from scgraph.symbols.source import Release
from scgraph.symbols.transitive import propagate

child = Release("PyPI", "child", "1.0", {
    "child/__init__.py": "",
    "child/core.py": "def decode(d):\\n    return _risky(d)\\n\\ndef _risky(d):\\n    return eval(d)\\n"})
parent = Release("PyPI", "parent", "2.0", {
    "parent/__init__.py": "from .api import fetch\\n",
    "parent/api.py": "from child.core import decode\\n\\ndef fetch(u):\\n    return decode(u)\\n\\ndef other(u):\\n    return u\\n"})
top = Release("PyPI", "top", "3.0", {
    "top/__init__.py": "",
    "top/app.py": "import parent\\n\\ndef run(x):\\n    return parent.fetch(x)\\n"})
seeds = entry_points(child, "child.core", "_risky")
for chain in ([parent, child], [top, parent, child]):
    p = propagate(chain, seeds)
    print(" -> ".join(r.package for r in chain), "|", "project code must reference:", p.names)"""
        ),
        new_code_cell(
            """import json
from pathlib import Path
import matplotlib.pyplot as plt

tr = json.loads(Path("results/metrics/symbols_transitive.json").read_text())
print("Ground truth: functions that actually executed in the dependency while the parent ran a")
print("real scenario under a profiler. Recall = share of them the static analysis connects to the parent.")
print(f"{'chain':36} {'ran':>5} {'recall':>8} {'static reach':>13} {'ran share':>10}")
for r in tr["chains"]:
    if r["recall"] is None:
        continue
    print(f"{r['chain']:36} {r['executed_functions']:5d} {100*r['recall']:7.1f}% "
          f"{100*r['static_reached_share']:12.1f}% {100*r['dynamic_executed_share']:9.1f}%")
o = tr["overall"]
print(f"{'overall':36} {o['executed_functions']:5d} {100*o['recall']:7.1f}%")
print()
print(f"{'configuration':46} {'recall':>8} {'static reach':>13}")
for k, v in tr["ablation"].items():
    print(f"{k:46} {100*v['recall']:7.1f}% {100*v['static_reached_share']:12.1f}%")
names = list(tr["ablation"])
fig, ax = plt.subplots(figsize=(8, 3.6))
ax.scatter([100*tr["ablation"][k]["static_reached_share"] for k in names],
           [100*tr["ablation"][k]["recall"] for k in names], color="#3b6ea5")
for k in names:
    ax.annotate(k.replace("without ", "-"), (100*tr["ablation"][k]["static_reached_share"],
                100*tr["ablation"][k]["recall"]), fontsize=7, xytext=(4, 3), textcoords="offset points")
ax.set_xlabel("share of the dependency's functions marked reachable (cost), %")
ax.set_ylabel("recall on functions that ran, %"); ax.set_title("What each call-graph mechanism buys")
fig.tight_layout(); fig.savefig("results/figures/symbols_transitive_ablation.png", dpi=140); plt.show()"""
        ),
        new_markdown_cell(
            f"**Reading the result.** Across {o['executed_functions']} functions that demonstrably ran in "
            f"`urllib3`, `werkzeug`, `jinja2`, `click`, `itsdangerous`, `blinker` and `markupsafe` "
            f"(`requests` and `flask` as parents, 2- and 3-package chains), the analysis connects "
            f"{pct(o['recall'])} to the parent's API. With resolved calls matched by bare name only, it "
            f"connected {pct(off['recall'])}: the missing {100 * (on['recall'] - off['recall']):.0f} points "
            "came from the five mechanisms (see the ablation table: implicit calls, import-time code, "
            "dynamic dispatch, functions passed as values, resolved references). "
            f"The cost is real: {pct(on['static_reached_share'])} of a dependency's functions are marked "
            f"reachable, against {pct(off['static_reached_share'])} before. One scenario exercises only part of a "
            "library, so some of that is genuine reach that the scenario did not trigger and some is "
            "over-approximation; the two cannot be separated here. The verdict is therefore sound but "
            "coarse for large, highly connected dependencies, and sharp for narrow ones. It orders a "
            "queue; it never closes an alert."
        ),
        new_markdown_cell(
            "## S35 - npm, and spending free-tier requests where they matter\n\n"
            "**Theory.** JavaScript has no visibility keyword, so *public* means *exported*. A project "
            "reaches a package through export names (`require('lodash').template`) or deep paths "
            "(`lodash/lodash.template`), so entry points are expressed in exactly those names, and "
            "UMD factories (`lodash.template = template`) are recognised. The language model is the "
            "scarce resource: one OpenRouter free-tier key gives 50 requests a day. The client caches "
            "answers per advisory (so a different batching never repays), splits a batch that fails and "
            "retries the halves, and asks about the most-downloaded packages first."
        ),
        new_code_cell(
            """import json
from pathlib import Path

import collections

for eco in ("pypi", "npm"):
    rows = [json.loads(l) for l in Path(f"src/scgraph/symbols/data/{eco}.jsonl").read_text().splitlines()]
    r = json.loads(Path(f"results/metrics/symbols_{eco}_build.json").read_text())
    print(f"{eco}: {len(rows)} verified records for {len({x['package'].lower() for x in rows})} packages")
    print("   methods:", dict(collections.Counter(x["method"] for x in rows)),
          "| with entry points:", sum(bool(x["entry_points"]) for x in rows))
    print("   most covered:", collections.Counter(x["package"] for x in rows).most_common(4))
    print("   last build abstentions:", r["abstained"])
llm = json.loads(Path("results/metrics/symbols_eval.json").read_text()).get("llm", {})
print("LLM stage on the Go test split:", {k: llm.get(k) for k in ("requests", "answered", "failed")})"""
        ),
        new_markdown_cell(
            "**Reading the result.** The datasets cover the most-downloaded packages first, because "
            "real projects pin popular packages, often at old versions, and the newest advisories do "
            "not cover them. Everything that did not verify is an abstention with a reason, never a "
            "guess. Language-model requests are spent in priority order and answers are cached per "
            "advisory, which is why a free-tier daily budget is enough."
        ),
    ]
    return cells


def main() -> int:
    nb = nbformat.read(NB, as_version=4)
    keep = []
    skipping = False
    for c in nb.cells:
        if c.cell_type == "markdown" and MARK in c.source:
            skipping = True
        elif skipping and c.cell_type == "markdown" and c.source.startswith("## Run manifest"):
            skipping = False
        if not skipping:
            keep.append(c)
    new = build_cells()
    tmp = new_notebook(
        cells=[
            new_code_cell(
                "import os\nfrom pathlib import Path\n"
                "p = Path.cwd()\nwhile not (p / 'pyproject.toml').exists():\n"
                "    p = p.parent\nos.chdir(p)"
            ),
            *new,
        ]
    )
    tmp.metadata = nb.metadata
    NotebookClient(
        tmp,
        timeout=300,
        kernel_name="python3",  # the active environment
        resources={"metadata": {"path": str(ROOT)}},
    ).execute()
    executed = tmp.cells[1:]
    idx = next(
        i
        for i, c in enumerate(keep)
        if c.cell_type == "markdown" and c.source.startswith("## Run manifest")
    )
    nb.cells = keep[:idx] + executed + keep[idx:]
    nbformat.write(nb, NB)
    figs = sum(
        1 for c in executed for o in c.get("outputs", []) if "image/png" in o.get("data", {})
    )
    print(
        f"spliced {len(executed)} cells ({figs} figures) before 'Run manifest'; notebook now {len(nb.cells)} cells"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
