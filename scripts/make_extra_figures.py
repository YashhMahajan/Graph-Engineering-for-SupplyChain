#!/usr/bin/env python3
"""Make the extra figures from the committed metric files in results/metrics/.

    python scripts/make_extra_figures.py

Writes dag_levels.png, community_sizes.png, and external_validation.png to
results/figures/. Needs only matplotlib. Uses the notebook style.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
METRICS = ROOT / "results" / "metrics"
OUT = ROOT / "results" / "figures"

C1, C2, C3, C4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
C5, C6, C7, C8 = "#e87ba4", "#008300", "#4a3aa7", "#e34948"
INK, INK2, MUTED, GRID, SURF = "#0b0b0b", "#52514e", "#8a8880", "#e6e5e1", "#fcfcfb"
ECO_COLOR = {
    "npm": C8,
    "pypi": C1,
    "maven": C2,
    "cargo": C4,
    "go": C3,
    "rubygems": C5,
    "packagist": C7,
    "nuget": C6,
}
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


def _load(name: str) -> dict:
    return json.loads((METRICS / f"{name}.json").read_text())


def finish(fig, name: str, title: str, sub: str | None = None) -> None:
    h = fig.get_size_inches()[1]
    fig.suptitle(
        title, x=0.02, y=1 - 0.16 / h, ha="left", va="top", fontsize=11, color=INK, weight="bold"
    )
    if sub:
        fig.text(0.02, 1 - 0.42 / h, sub, ha="left", va="top", fontsize=8.5, color=INK2)
    fig.tight_layout(rect=[0, 0, 1, 1 - (0.60 if sub else 0.34) / h])
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[fig] {name}.png")


def dag_levels() -> None:
    gs = _load("graph_shape")
    levels = gs["dag"]["level_sizes"]
    deg = gs["degree"]
    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 3.6), gridspec_kw={"width_ratios": [1.6, 1]})
    a.bar(range(len(levels)), levels, color=C7, width=0.8)
    a.set_yscale("log")
    a.set_xlabel("topological level (hops from a leaf)")
    a.set_ylabel("packages (log)")
    a.set_title(
        f"longest chain = {gs['dag']['max_depth']} hops", loc="left", color=INK2, fontsize=9
    )
    stats = ["median", "p90", "p99", "max"]
    x = range(len(stats))
    w = 0.38
    b.bar(
        [i - w / 2 for i in x],
        [max(deg["in"][s], 0.5) for s in stats],
        w,
        color=C1,
        label="in-degree",
    )
    b.bar(
        [i + w / 2 for i in x],
        [max(deg["out"][s], 0.5) for s in stats],
        w,
        color=C2,
        label="out-degree",
    )
    b.set_yscale("log")
    b.set_xticks(list(x), [f"{st}\nin {deg['in'][st]:g} / out {deg['out'][st]:g}" for st in stats])
    b.set_ylabel("degree (log)")
    b.legend(loc="upper left")
    b.set_title(
        f"{deg['in']['zero_frac']:.1%} of packages have no dependents",
        loc="left",
        color=INK2,
        fontsize=9,
    )
    finish(
        fig,
        "dag_levels",
        "Most packages are shallow, a long tail is deep",
        "Package count at each topological level, and the in/out degree spread",
    )


def community_sizes() -> None:
    cm = _load("community")
    top = sorted(cm["communities"], key=lambda c: c["size"], reverse=True)[:15]
    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 4.0), gridspec_kw={"width_ratios": [1.6, 1]})
    labels = [f"#{i + 1} {c['dominant_ecosystem']}" for i, c in enumerate(top)][::-1]
    sizes = [c["size"] for c in top][::-1]
    colors = [ECO_COLOR.get(c["dominant_ecosystem"], MUTED) for c in top][::-1]
    a.barh(labels, sizes, color=colors)
    a.set_xscale("log")
    a.set_xlabel("packages in the community (log)")
    a.set_title(
        f"Q = {cm['modularity']:.3f}, {cm['n_communities']:,} communities",
        loc="left",
        color=INK2,
        fontsize=9,
    )
    inside = 1 - cm["cross_community_edge_frac"]
    b.pie(
        [inside, cm["cross_community_edge_frac"]],
        colors=[C3, C8],
        startangle=90,
        labels=[f"inside {inside:.1%}", f"between {cm['cross_community_edge_frac']:.1%}"],
        wedgeprops={"width": 0.38, "edgecolor": SURF},
        textprops={"color": INK2},
    )
    b.set_title("dependency edges", loc="left", color=INK2, fontsize=9)
    finish(
        fig,
        "community_sizes",
        "Communities follow ecosystem lines",
        f"The {len(top)} largest label-propagation communities, by dominant ecosystem",
    )


def external_validation() -> None:
    vs = _load("vs_osvscanner_big")
    rf = _load("resolver_fidelity")
    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 3.6))
    parts = [
        ("both", vs["both"], C3),
        ("only scgraph", vs["only_us"], C1),
        ("only osv-scanner", vs["only_scanner"], C2),
    ]
    left = 0
    for name, n, col in parts:
        a.barh([0], [n], left=left, color=col, label=f"{name}: {n:,}")
        left += n
    a.set_yticks([])
    a.set_xlabel("findings over 150 generated lockfiles")
    a.legend(loc="upper center", bbox_to_anchor=(0.5, -0.32), ncol=3)
    a.set_title(
        f"agreement with osv-scanner = {vs['agreement_pct']}%", loc="left", color=INK2, fontsize=9
    )
    ecos = [e for e in ("npm", "cargo", "pypi", "maven") if e in rf]
    raw = [rf[e]["raw_match_pct"] for e in ecos]
    ins = [rf[e]["in_snapshot_match_pct"] or 0 for e in ecos]
    x = range(len(ecos))
    w = 0.38
    b.bar([i - w / 2 for i in x], raw, w, color=MUTED, label="raw match")
    b.bar([i + w / 2 for i in x], ins, w, color=C7, label="in-snapshot match")
    for i, e in enumerate(ecos):
        b.text(
            i + w / 2,
            ins[i] + 2,
            f"n={rf[e]['in_snapshot_pairs']}",
            ha="center",
            fontsize=7.5,
            color=INK2,
        )
    b.set_xticks(list(x), ecos)
    b.set_ylim(0, 112)
    b.set_ylabel("% same version as deps.dev")
    b.legend(loc="upper right")
    b.set_title(
        "resolver fidelity (2020 snapshot vs live deps.dev)", loc="left", color=INK2, fontsize=9
    )
    finish(
        fig,
        "external_validation",
        "Two independent references agree with the graph",
        "Advisory match against osv-scanner, and version resolution against deps.dev",
    )


if __name__ == "__main__":
    dag_levels()
    community_sizes()
    external_validation()
