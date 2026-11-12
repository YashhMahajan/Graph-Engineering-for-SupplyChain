# Instructions for AI agents

Any AI coding agent must read this page before it changes the repository. It follows the
ASD-STE100 rules for Simplified Technical English.

## Commands

Run these from the repository root. Use the project environment (`.venv`).

```bash
make setup                         # create .venv and install the dev extras
.venv/bin/pytest -q -m "not network"   # unit tests, no network, about 5 s
.venv/bin/pytest -q                # all tests, including the network smoke test (about 2.5 min)
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy src/scgraph
make symbols-eval                  # Go evaluation of the symbols work, model-free
make symbols-refresh               # spends LLM requests: read "Free-tier budget" first
.venv/bin/python -m scgraph.cli symbols budget   # today's LLM budget
```

A change is complete only when tests, ruff and mypy all pass. Run all three before you commit.

## What the project does

scgraph finds vulnerable dependencies and proves each alert with a dependency path. It also says
whether your code calls the vulnerable function. Read [PRD.md](PRD.md) for the goals and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Rules

1. **Do not call a model in a scan.** A model may run only in the build pipeline of the symbols
   datasets. A scan reads data files.
2. **Do not hide an alert.** A reachability verdict orders the queue. It must not close an alert
   or change the exit code.
3. **Prefer an abstention to a guess.** If you cannot prove a result, return a reason.
4. **Keep changes small.** Change only what the task needs. Do not refactor code that the task
   does not touch. Do not add a dependency without a reason.
5. **Write the test with the change.** A bug fix needs a test that fails before the fix.
6. **Measure before you claim.** Put a number in the docs only if a script in `scripts/` produces
   it. Report a negative result as it is.
7. **Never commit a secret.** `.env` and the signing key stay out of Git. Do not print a key,
   not even in a log.
8. **Do not publish for the user.** Do not create a tag, a release or a package upload. Do not
   send a patch to another project. Ask first.
9. **Keep the docs lean.** The files in `docs/` are the only docs. Add a file only if a reader
   needs it. Write in Simplified Technical English.

## Free-tier budget (LLM)

One OpenRouter key gives 50 free requests a day. The limit resets at 00:00 UTC.

- Read the key from `OPENROUTER_API_KEY` in `.env`. The default model is
  `baidu/ernie-5.5-flash-preview:free`. `SCGRAPH_LLM_MODELS` sets a different order.
- Check the budget before you start: `scgraph symbols budget`.
- Always pass a request cap (`--llm-requests N`). The client also stops at the daily limit.
- Use `--llm-cache-only` to replay answers. This mode cannot send a request.
- Answers are cached per advisory in `~/.cache/scgraph/llm`. Do not delete this cache.
- Do not change a prompt (`symbols/select.py`) without a reason. A changed prompt makes old
  answers miss the cache. They cost requests again.

## Where things are

| Path | Content |
|---|---|
| `src/scgraph/scan/` | Lockfile parsing, the scan engine, guard, history, audit, `ask` |
| `src/scgraph/symbols/` | Vulnerable-function inference, reachability, datasets, signing |
| `src/scgraph/symbols/data/` | Shipped datasets, manifests, signatures, public key |
| `src/scgraph/core/` | Typed graph, gates, ledger |
| `scripts/symbols/` | Build, evaluation and notebook scripts for the symbols work |
| `results/metrics/` | Measured results (JSON). The docs quote these files. |
| `tests/unit/` | Unit tests. `tests/integration/` has the network smoke test. |
| `notebooks/` | The research notebook (11 parts) |

## Conventions

- Python 3.11 or later. Line length 100. Ruff and mypy settings are in `pyproject.toml`.
- Data files use LF line endings. Do not edit them by hand: the signature will not match.
  After a dataset change, run `scgraph symbols sign` (needs the private key).
- Test files for the symbols work are `tests/unit/test_symbols_*.py`. They may have long lines.
- Cross-platform: tests run on Linux and Windows. Do not assume Unix file modes or `\n` in text
  that you write in text mode.
- Commit messages use the form `type(scope): subject`. Add the co-author line that the session
  gives you.
- Open a pull request for each logical change. Merge only when all CI checks pass.

## When you are not sure

Read [ISSUES.md](ISSUES.md). It lists open work, known limits and past bugs. Then ask the user.
