# Reproduce the results

There are three tiers. Tier 1 reads the committed results. Tier 3 builds the graph again
from the Zenodo dump. Select the tier that agrees with how much you must verify.

| Tier | Result | Time | Disk | GPU |
|---|---|---|---|---|
| 1. Read only | All figures, metrics, reports, SBOMs, and the notebook with full-run outputs | None | None (this repository) | No |
| 2. Smoke | The full pipeline on a small real corpus, on a laptop | Approximately 3 minutes | Less than 1 GB | No |
| 3a. Full, from artifacts | The full CPU pipeline (structure, grounding, ladder, remediation) | Approximately 10 minutes | Approximately 3 GB | No |
| 3b. Full, model layer | Embeddings, GraphSAGE, and the judge, on top of 3a | Approximately 6 hours | Approximately 25 GB | Yes |
| 3c. Full, from the Zenodo dump | Parquet built again from Libraries.io v1.6.0 | Approximately 2 hours, plus download | Approximately 150 GB | No |

You must have Python 3.11 or newer.

---

## Tier 1: read only

All the data that you need to examine the results is in the repository:

- [`../results/run_manifest.json`](../results/run_manifest.json) and
  [`../results/scorecard.json`](../results/scorecard.json): the headline numbers.
- [`../results/metrics/`](../results/metrics): approximately 25 metric files, one for
  each experiment.
- [`../results/figures/`](../results/figures): the figures. Copies are also in
  [`figures/`](figures) for the docs.
- [`../results/reports/`](../results/reports): 11 exposure reports. Each report shows the
  paths that prove each finding.
- [`../results/sbom/`](../results/sbom): one CycloneDX SBOM for each report, and the
  portfolio SBOM.
- [`../notebooks/supply_chain_graph_engineering.ipynb`](../notebooks/supply_chain_graph_engineering.ipynb):
  the notebook, with all outputs and figures from the full run.

Read [results.md](results.md) together with the notebook. You do not need an install,
data, or a network connection.

---

## Tier 2: smoke (laptop, approximately 3 minutes)

This tier runs on a small real corpus. The corpus is the live OSV advisory feed for five
ecosystems and a resolved dependency graph from the deps.dev API. The graph has
approximately 50 seed packages for each ecosystem, plus known vulnerable version pins.
Thus Log4Shell and the lodash prototype-pollution advisories occur in the results. The
download is small. You must have outbound HTTPS.

```bash
git clone https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain.git
cd Graph-Engineering-for-SupplyChain
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 1. Get the smoke corpus (live OSV and deps.dev, approximately 3 minutes)
python scripts/acquire_smoke.py

# 2. Run the pipeline: parse, materialise OSV, build the CSR store
python scripts/run_pipeline.py --profile smoke
```

You can also use the notebook. The notebook finds the repository root automatically.

```bash
pip install -e ".[notebook]"
jupyter lab notebooks/supply_chain_graph_engineering.ipynb
```

The `make` shortcuts are `make smoke` (acquire and pipeline) and `make notebook` (run the
notebook on the smoke profile).

One parameter cell at the top of the notebook controls it: `SMOKE_TEST` (default
`True`), `DATA_DIR` (default `./data`), `ECOSYSTEMS`, the model names, and the traversal
limits `MAX_DEPTH` and `MAX_PATHS`. If you set `SMOKE_TEST = False`, the notebook uses
the full profile. The full Parquet must then be available (tier 3a).

**Smoke output**, in `data/`:

| Path | Contents |
|---|---|
| `data/raw/osv/*.zip` | The OSV `all.zip` for each ecosystem, kept as zip files |
| `data/raw/depsdev/*.jsonl` | The deps.dev resolved-graph sample |
| `data/parquet/` | The columnar edge tables |
| `data/graph/*.npy` | The CSR memmap store |
| `data/out/` | `run_manifest.json`, `exposure_report.md`, `sbom.cdx.json`, `figures/*.png`, and one JSON file for each experiment |

Limits of the smoke tier: the network-science numbers come from a graph of approximately
68,000 version nodes. Thus the power-law exponent, modularity, and densification values
are smoke-scale values, not full-run values. The GPU sections stop with a clear message.
All code paths run, and the data is real (live OSV feed and real deps.dev resolutions).

---

## Tier 3: full run

### 3a. The CPU pipeline, from published artifacts

The full run uses the parsed Parquet tables (approximately 550 MB). You do **not** need
the 25 GB Zenodo download. `scripts/fetch_artifacts.py` downloads the parsed tables and
the embeddings from the GitHub Release.

```bash
python scripts/fetch_artifacts.py --set full     # Parquet tables and embeddings
python scripts/build_graph.py                    # build the CSR store (approximately 2 GB, 2.3 minutes)
python scripts/run_pipeline.py --profile full --skip-parse
```

`make graph` is the shortcut for `build_graph.py`. Then you can run the notebook with
`SMOKE_TEST=False`. The CPU sections run directly. The GPU sections load the cached
results from `--set full`.

Where each notebook part runs:

| Notebook part | Requirement |
|---|---|
| I data thesis, II graph shape, III grounding and traversal | CPU only |
| IV model layer (S15 embeddings, S16 semantic relevance, S17 reachability) | GPU (or cache) |
| V remediation, VI system intelligence | CPU only |
| VII representation learning (S24b GraphSAGE) | GPU (or cache) |
| VIII evaluation (S25 judge) | GPU for S25 (or cache), other sections CPU |
| IX figures, X performance and scaling | CPU only |

Approximate CPU times on the full graph
([`costs.json`](../results/metrics/costs.json),
[`timing.json`](../results/metrics/timing.json)): CSR build 2.3 minutes, KGStore load 13
seconds, reverse PageRank 4 seconds, articulation points 8 seconds, label propagation 3.5
minutes, sampled betweenness 3 minutes. The full notebook ran in approximately 16 minutes.

### 3b. The model layer, on a GPU machine

The embeddings, the temporal GraphSAGE, and the judge check need a CUDA GPU with
approximately 40 GB of VRAM. The published run used one L40 (48 GB) on Ubuntu 24.04 with
CUDA 12.8.

Install PyTorch from the index that agrees with your driver first. The scripts use CUDA
12.8:

```bash
pip install torch==2.11.0 --index-url https://download.pytorch.org/whl/cu128
pip install -e ".[gpu,fast]"
```

Caution: the cu13 wheels import on a 12.8 driver, but `cuda.is_available()` gives
`False` and shows no error. Transformers is sufficient for these volumes. You do not need
vLLM.

The full pipeline on a GPU machine:

```bash
# On the machine: git clone, cd into the repository, then
sudo apt-get install -y python3.12-venv pigz aria2      # aria2 and pigz make the download faster
python -m venv .venv && . .venv/bin/activate
pip install torch==2.11.0 --index-url https://download.pytorch.org/whl/cu128
pip install -e ".[gpu,fast,notebook]"
python -m ipykernel install --user --name scgraph

python scripts/acquire_full.py --dest data              # 25 GB download, 100 GB extracted, resumable
python scripts/run_pipeline.py --profile full           # parse, materialise, build (approximately 90 minutes)

# Set SMOKE_TEST = False in notebooks/supply_chain_graph_engineering.ipynb, then
python scripts/_run_notebook.py notebooks/supply_chain_graph_engineering.ipynb scgraph 36000 --allow-errors
python scripts/run_evaluation.py --all
```

On a remote machine, use `nohup ... &` or `tmux`. Each stage is idempotent. If you run
it again, it continues from the last completed stage. The repository does not start or
stop the machine. The embedding stage takes the most time: approximately 5 hours on an
L40-class card ([`costs.json`](../results/metrics/costs.json)). The GraphSAGE and judge
stages take minutes.

### 3c. Build the Parquet from the Zenodo dump

Use a GPU machine or a workstation with approximately 150 GB of free disk. Do not use a
laptop.

```bash
python scripts/acquire_full.py --dest /path/with/150GB
python scripts/run_pipeline.py --profile full
```

`acquire_full.py` downloads the pinned Libraries.io Open Data v1.6.0 tarball (Zenodo
record 3626071, `libraries-1.6.0-2020-01-12.tar.gz`, 24,890,021,718 bytes, MD5
`4f2275284b86827751bb31ce74238b15`). It verifies the size and the MD5, then extracts
approximately 100 GB of CSV. It also downloads the live OSV feed for eight ecosystems and
makes a shallow clone of the GitHub Advisory Database. The download is resumable. The
script uses `aria2c` and `pigz` if they are on PATH. The MD5 check takes approximately 3
minutes. The extraction takes 10 to 25 minutes.

`run_pipeline.py --profile full` then runs `build_full_tables` (Libraries.io CSV to
Parquet), `osv.materialise`, and `build_graph`. On a 28-core machine, the full build
takes approximately 90 minutes. The result is the same Parquet tables that `--set full`
downloads.

---

## Verify your result

Compare your `data/out/run_manifest.json` with the committed
[`../results/run_manifest.json`](../results/run_manifest.json). For a full run from the
same Zenodo dump, the graph values (`version_nodes`, `package_nodes`, `advisories`,
`resolves_edges`) must be the same. The advisory count changes when OSV publishes new
records. All values that come only from Libraries.io are deterministic.

---

## Problems and solutions

| Problem | Cause and solution |
|---|---|
| GPU sections stop with "no CUDA" | Usual on a CPU machine. The notebook loads cached GPU results if you downloaded `--set full`. |
| `igraph` import error in the structure sections | Install the `fast` extra: `pip install -e ".[fast]"` |
| `cuda.is_available()` is `False` after you install torch | Incorrect CUDA index. Install torch again from the `cu128` index that agrees with your driver. |
| Resolver disagreement with deps.dev is high | Usual. The corpus is a 2020 snapshot. Refer to [evaluation.md](evaluation.md), section 3. |
| MD5 mismatch on the Zenodo tarball | The download is not complete. `acquire_full.py` continues it. Or delete the file and download it again. |

Refer to [architecture.md](architecture.md) for the function of each stage, and to
[data-sources.md](data-sources.md) for the downloads.
