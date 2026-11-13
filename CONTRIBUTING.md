# Contributing to scgraph

This file gives the development setup, the quality gate, and the project rules.

## Development setup

```bash
git clone https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain.git
cd Graph-Engineering-for-SupplyChain
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev,notebook]"
pre-commit install
```

`make setup` does all of these steps. If you use Windows and do not have GNU make, use
these commands. Use `.venv\Scripts\` instead of `.venv/bin/`.

| Task | Command |
|---|---|
| Lint | `ruff check . && ruff format --check . && mypy src/scgraph` |
| Auto-fix | `ruff check --fix . && ruff format .` |
| Test | `pytest -m "not network"` |
| Coverage | `pytest -m "not network" --cov=scgraph --cov-report=term-missing` |
| Notebook | Edit it in Jupyter. Then run `python scripts/_run_notebook.py notebooks/supply_chain_graph_engineering.ipynb scgraph 1500` to fill the outputs again. |

## Quality gate

CI does these checks on each pull request. All checks must pass.

1. **`ruff check`** with the rules in `pyproject.toml`. The scripts in
   `scripts/evaluation/` have fewer rules, because they are one-time scripts.
2. **`ruff format --check`**. Run `ruff format .` before you commit. The pre-commit hook
   does this step for you.
3. **`mypy src/scgraph`** with no errors. Add type annotations to all new public
   functions.
4. **`pytest -m "not network"`**. Add a test for each new behavior. Graph tests use the
   `tiny_graph` fixture in `tests/conftest.py`. This fixture builds a real CSR store from
   a synthetic corpus of six packages.

## Rules

- **Do not use a language model to build the graph.** Each edge must come from a
  published field: a manifest range, a lockfile pin, or an OSV affected range. Use
  models only in the model layer (`embed`, `reach`, `gnn`, `judge`). Measure each model
  output against independent ground truth. We do not merge a change that adds a model
  call to graph construction.
- **Each alert must have a path.** Do not make a finding that has no resolvable
  dependency path. If reachability is not known, the system abstains.
- **A failed lookup is never a pass.** In `scgraph scan` and `scgraph check`, a network
  or data error gives an error or an `unverified` result. It never gives "safe".
- **Be polite to public services.** New network calls must use the cache in
  `scgraph.scan.sources`, send the scgraph `User-Agent`, and work offline when possible.
  Unit tests must not use the network.
- **Use sample lockfiles that other scanners do not read.** Give them a prefix, for
  example `examples/name.package-lock.json`.
- **Report negative results.** If a method does not help, write this in the notebook
  and in the docs.
- **Text in docs and comments:** write Simplified Technical English (ASD-STE100): short
  sentences, active voice, no contractions, no em dashes. Read `docs/AGENTS.md` and `CLAUDE.md`
  if you use an AI agent.
- **Result numbers** are in `results/run_manifest.json` and `results/scorecard.json`.
  If a change moves a headline number, make the related `results/` files again and
  update the numbers in `README.md` and `docs/SYMBOLS.md` in the same pull request.

## Commits and pull requests

- Make a branch from `main`. Keep each pull request to one subject.
- Write what changed, why, and how you tested it.
- For a change that users can see, update `CHANGELOG.md` below `## [Unreleased]`.

## Add an ecosystem

Add an entry to the resolver (`resolve.py`), to version ordering (`versions.py`), and to
the Libraries.io platform map (`acquire_full.py`). Add unit tests for version comparison
and range match. Refer to `docs/ARCHITECTURE.md`.

## Responsible use

Read [`docs/RESPONSIBLE-USE.md`](docs/RESPONSIBLE-USE.md). Do not add features whose main
use is attack, for example a list of names to squat or a crawler that lists exposed
third-party repositories.

## Security issues

Do not open a public issue. Refer to [`SECURITY.md`](SECURITY.md).
