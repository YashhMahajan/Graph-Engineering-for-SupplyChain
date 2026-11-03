#!/usr/bin/env python3
"""Make the figures for `scgraph scan` and `scgraph check` from the sample lockfiles.

    scgraph fetch-osv --dir osv npm pypi
    python scripts/make_scan_figures.py --osv osv

Writes to results/figures/ and docs/figures/:

    scan_terminal.png    the real terminal output of one scan
    guard_terminal.png   the real terminal output of the pre-install guard
    scan_noise.png       advisory records -> findings -> alerts -> fix actions

and the numbers behind them to results/metrics/scan_examples.json. The terminal images
come from the actual CLI output (ANSI colors converted to HTML, then a headless
Chromium screenshot), not from a mock-up. Needs matplotlib and playwright.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "figures"
DOCS = ROOT / "docs" / "figures"
METRICS = ROOT / "results" / "metrics"
EXAMPLES = ROOT / "examples"

C1, C2, C3, C4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
C7, C8 = "#4a3aa7", "#e34948"
INK, INK2, MUTED, GRID, SURF = "#0b0b0b", "#52514e", "#8a8880", "#e6e5e1", "#fcfcfb"
mpl.rcParams.update(
    {
        "figure.facecolor": SURF,
        "axes.facecolor": SURF,
        "savefig.facecolor": SURF,
        "font.size": 9,
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": INK2,
        "ytick.color": INK2,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.6,
        "axes.axisbelow": True,
        "legend.frameon": False,
        "figure.dpi": 120,
    }
)

# ------------------------------------------------------------------ terminal images
_ANSI = {
    "1": "font-weight:700",
    "2": "opacity:.62",
    "31": "color:#ff7b72",
    "32": "color:#56d364",
    "33": "color:#e3b341",
    "36": "color:#79c0ff",
    "97": "color:#ffffff",
    "41": "background:#da3633",
}


def ansi_to_html(text: str) -> str:
    out, open_spans = [], 0
    for part in re.split(r"(\x1b\[[0-9;]*m)", text):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if not m:
            out.append(html.escape(part))
            continue
        codes = [c for c in m.group(1).split(";") if c]
        if not codes or codes == ["0"]:
            out.append("</span>" * open_spans)
            open_spans = 0
            continue
        style = ";".join(_ANSI[c] for c in codes if c in _ANSI)
        out.append(f'<span style="{style}">')
        open_spans += 1
    out.append("</span>" * open_spans)
    return "".join(out)


PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:{surf};}}
.win{{display:inline-block;margin:18px;border-radius:10px;background:#0d1117;
box-shadow:0 8px 28px rgba(0,0,0,.25);overflow:hidden;}}
.bar{{height:30px;background:#161b22;display:flex;align-items:center;padding:0 12px;gap:7px;}}
.dot{{width:11px;height:11px;border-radius:50%;}}
.ttl{{color:#8b949e;font:12px ui-monospace,Menlo,monospace;margin-left:10px;}}
pre{{margin:0;padding:14px 20px 18px;color:#e6edf3;
font:13px/1.45 "DejaVu Sans Mono",ui-monospace,Menlo,monospace;}}
</style></head><body><div class="win" id="w"><div class="bar">
<span class="dot" style="background:#ff5f56"></span>
<span class="dot" style="background:#ffbd2e"></span>
<span class="dot" style="background:#27c93f"></span>
<span class="ttl">{title}</span></div><pre>{body}</pre></div></body></html>"""


_NODE_SHOT = """
const { chromium } = require('playwright');
(async () => {
  const [src, dest] = process.argv.slice(1);
  const b = await chromium.launch();
  const pg = await b.newPage({ viewport: { width: 1400, height: 900 }, deviceScaleFactor: 2 });
  await pg.setContent(require('fs').readFileSync(src, 'utf8'));
  await pg.locator('#w').screenshot({ path: dest });
  await b.close();
})();
"""


def terminal_png(commands: list[str], outputs: list[str], dest: Path, title: str) -> None:
    """Screenshot the output in a terminal frame: Python playwright if installed, else
    the Node one (``npm i -g playwright``)."""
    body = ""
    for cmd, out in zip(commands, outputs):
        body += f'<span style="color:#56d364">$</span> {html.escape(cmd)}\n' + ansi_to_html(out)
    page_html = PAGE.format(surf=SURF, title=html.escape(title), body=body.rstrip())
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        src = dest.with_suffix(".html")
        src.write_text(page_html, encoding="utf-8")
        try:
            subprocess.run(["node", "-e", _NODE_SHOT, str(src), str(dest)], check=True)
        finally:
            src.unlink()
        return
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1400, "height": 900}, device_scale_factor=2)
        pg.set_content(page_html)
        pg.locator("#w").screenshot(path=str(dest))
        b.close()


def run(args: list[str], env: dict) -> str:
    r = subprocess.run(
        [sys.executable, "-m", "scgraph.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=False,
    )
    return r.stdout + r.stderr


# --------------------------------------------------------------------- noise chart
def noise_numbers(osv_dir: str) -> list[dict]:
    from scgraph.scan import Policy, parse
    from scgraph.scan.engine import scan_graph
    from scgraph.scan.sources import OSVOffline, Signals, http_json

    rows = []
    src = OSVOffline(osv_dir)
    for f in sorted(EXAMPLES.glob("*.*")):
        if f.suffix == ".md":
            continue
        res = scan_graph(parse(f), src, Signals(enabled=False), Policy(), registry=http_json)
        covered = {p for b in res.parent_upgrades for p in b["clears_packages"]}
        direct_bumped = {b["direct"] for b in res.parent_upgrades}
        actions = len(res.parent_upgrades) + sum(
            1 for a in res.remediation if a["package"] not in covered | direct_bumped
        )
        rows.append(
            {
                "lockfile": f.name,
                "packages": res.n_packages,
                "advisory_records": sum(len(x.ids) for x in res.findings),
                "findings": len(res.findings),
                "alerts": len(res.alerts),
                "abstained": res.abstention_counts(),
                "fix_actions": actions,
                "parent_bumps": res.parent_upgrades,
            }
        )
    return rows


def noise_figure(rows: list[dict], dest: Path) -> None:
    stages = [
        ("advisory records", "advisory_records", MUTED),
        ("findings (ids merged)", "findings", C1),
        ("alerts (after the gates)", "alerts", C2),
        ("fix actions", "fix_actions", C3),
    ]
    fig, axes = plt.subplots(1, len(rows), figsize=(4.2 * len(rows), 3.2), squeeze=False)
    for ax, row in zip(axes[0], rows):
        vals = [row[k] for _, k, _ in stages]
        y = range(len(stages))[::-1]
        ax.barh(list(y), vals, color=[c for *_, c in stages], height=0.62)
        for yi, v in zip(y, vals):
            ax.text(v + max(vals) * 0.02, yi, str(v), va="center", color=INK, fontsize=9)
        ax.set_yticks(list(y), [s for s, *_ in stages])
        ax.set_xlim(0, max(vals) * 1.18 + 1)
        ax.grid(axis="y", visible=False)
        name = row["lockfile"].split(".")[0]
        ax.set_title(f"{name}  ({row['packages']} packages)", loc="left", color=INK2, fontsize=9)
        if ax is not axes[0][0]:
            ax.set_yticklabels([])
    fig.suptitle(
        "From advisory noise to a short list of fixes",
        x=0.01,
        y=0.98,
        ha="left",
        fontsize=12,
        fontweight="bold",
    )
    fig.text(
        0.01,
        0.83,
        "Same issue under several ids is merged; dev-only and withdrawn findings abstain; "
        "one direct bump can clear many transitive alerts",
        ha="left",
        color=INK2,
        fontsize=9,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.80))
    fig.savefig(dest, dpi=120)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--osv", required=True, help="directory with OSV all.zip dumps (fetch-osv)")
    ap.add_argument(
        "--skip-guard", action="store_true", help="no registry access: skip guard image"
    )
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)
    METRICS.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "FORCE_COLOR": "1", "SCGRAPH_OSV_DIR": a.osv, "COLUMNS": "120"}

    lock = "examples/sept-2025-npm-compromise.package-lock.json"
    cmd = f"scgraph scan {lock} --no-signals"
    out = run(["scan", lock, "--no-signals"], env)
    out = re.sub(r"\[\d+ ms\]", "", out)
    terminal_png([cmd], [out], OUT / "scan_terminal.png", "scgraph scan")

    if not a.skip_guard:
        cmds = [
            ["check", "npm", "chalk@5.6.1", "reactt", "react-dom-helpers-pro-max"],
            ["check", "pypi", "reqeusts", "requests"],
        ]
        outs = [run(c, env) for c in cmds]
        terminal_png(
            ["scgraph " + " ".join(c) for c in cmds],
            outs,
            OUT / "guard_terminal.png",
            "scgraph check",
        )

    rows = noise_numbers(a.osv)
    noise_figure(rows, OUT / "scan_noise.png")
    (METRICS / "scan_examples.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    for name in ("scan_terminal.png", "guard_terminal.png", "scan_noise.png"):
        if (OUT / name).exists():
            shutil.copy(OUT / name, DOCS / name)
    print(json.dumps([{k: r[k] for k in r if k != "parent_bumps"} for r in rows], indent=2))


if __name__ == "__main__":
    main()
