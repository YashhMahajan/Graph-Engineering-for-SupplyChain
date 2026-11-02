"""A 10-second demo: build a tiny graph and print one exposure path and one abstention.

    python scripts/demo.py

Record it for the README GIF with, for example:
    asciinema rec -c "python scripts/demo.py" demo.cast   # then agg demo.cast demo.gif
"""

from __future__ import annotations

import time

from scgraph.adapters import software
from scgraph.core import EdgeBatch, TypedGraph

APP = "ver:maven/com.example:app@1.0.0"


def main() -> None:
    nodes = [
        (APP, "version"),
        ("ver:maven/com.example:web-framework@2.1.0", "version"),
        ("ver:maven/org.apache.logging.log4j:log4j-core@2.12.1", "version"),
        ("adv:CVE-2021-44228|GHSA-jfh8-c2jp-5v3q", "advisory"),
    ]
    g = TypedGraph.build(
        nodes,
        {
            "resolves_to": EdgeBatch([0, 1], [1, 2], source="lockfile"),
            "affects": EdgeBatch([2], [3], valid_from=[1639094400], source="osv"),
        },
    )
    advs = {
        nodes[3][0]: software.Advisory(
            nodes[3][0], "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", 10.0, False, 1639094400
        )
    }
    software.audit(g, advs, APP)  # warm up: first call imports Arrow kernels
    for as_of in ("2021-12-09", "2021-12-10"):
        t = time.perf_counter()
        r = software.audit(g, advs, APP, as_of=as_of)
        ms = (time.perf_counter() - t) * 1e3
        print(f"\n$ scgraph audit {APP} --as-of {as_of}   ({ms:.2f} ms)")
        if not r["findings"]:
            print("  ABSTAIN  no advisory reaching this tree was published yet")
        for f in r["findings"]:
            tag = "EXPOSED" if f["alert"] else f"ABSTAIN ({f['verdict']})"
            print(f"  {tag}  {f['advisory']}  cvss={f['severity']:.1f}")
            print(f"  path     {f['path']}")
            for hop in f["evidence"]:
                print(
                    f"    {hop['src']} -[{hop['relation']}]-> {hop['dst']}  source={hop['source']}"
                )


if __name__ == "__main__":
    main()
