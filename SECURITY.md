# Security Policy

## Scope

`scgraph` is an analysis tool. It reads public advisory data and dependency data, and it
writes reports. It does not run dependency code. It does not use the network during
graph construction. Know these items:

- The evaluation and acquisition scripts run `git clone`, `curl` or `aria2c`, `tar`, and
  (for the osv-scanner comparison) a downloaded binary. These scripts run only when you
  start them. They do not keep credentials.
- `scripts/fetch_artifacts.py` downloads release assets over HTTPS only and checks each
  against a sha256 pinned in the script before extracting it. An asset without a pinned
  hash is refused unless you pass `--allow-unverified`. Archives are extracted with
  tarfile's `data` filter (no absolute paths, `..`, links out of the tree or devices).

## Threat model for data files

Graph directories and ledgers are data you may download or share, so loading them never
executes code:

- **No pickle anywhere on the load path.** Every `.npy` is opened with
  `allow_pickle=False`; strings are stored as a UTF-8 blob plus offsets. A graph
  directory written by scgraph 1.0 (pickled object arrays) is refused with an error.
  Convert it once with `python -m scgraph.kgstore --migrate DIR`, and only for a
  directory you built or verified, because that one step does unpickle.
- **Tamper evidence.** `scgraph.core.TypedGraph` snapshots are content-addressed and
  verified against their SHA-256 fingerprint on load, including the key lookup index.
  The `Ledger` log is hash-chained, so editing, reordering or deleting history fails
  `verify()`. The chain proves integrity relative to its head: someone who can rewrite
  the whole directory can forge a consistent new history, so anchor `Ledger.head`
  somewhere outside your control when that matters.
- **Path safety.** Relation names are restricted to `[A-Za-z0-9_-]` before they become
  file names.

## The scanner and the guard

- `scgraph scan` and `scgraph check` only read lockfiles and public metadata. They do
  not run package code and do not install anything.
- A guard bypass is a security issue. Examples: a command form that the hook does not
  read, or a malicious release that `check` allows when OSV has a `MAL-` record for it.
  Report it in private, as below.
- Rules for fair use of the tool and the data: [`docs/DATA-SOURCES.md`](docs/DATA-SOURCES.md) (section 12).

## Report a vulnerability

Use GitHub
[private vulnerability reporting](https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain/security/advisories/new).
Do not open a public issue.

Give the version, a description, and the steps to reproduce the problem. We reply in a
few days. For a confirmed issue, we supply a fix or a mitigation plan.

## Supported versions

Only the latest tagged release gets fixes. This project uses semantic versioning.
