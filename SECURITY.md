# Security Policy

## Scope

`scgraph` is an analysis tool. It reads public advisory data and dependency data, and it
writes reports. It does not run dependency code. It does not use the network during
graph construction. Know these items:

- The evaluation and acquisition scripts run `git clone`, `curl` or `aria2c`, `tar`, and
  (for the osv-scanner comparison) a downloaded binary. These scripts run only when you
  start them. They do not keep credentials.
- `scripts/fetch_artifacts.py` downloads release assets. When a release exists, the
  script compares each asset with a recorded sha256.

## Report a vulnerability

Use GitHub
[private vulnerability reporting](https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain/security/advisories/new).
Do not open a public issue.

Give the version, a description, and the steps to reproduce the problem. We reply in a
few days. For a confirmed issue, we supply a fix or a mitigation plan.

## Supported versions

Only the latest tagged release gets fixes. This project uses semantic versioning.
