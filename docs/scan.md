# The `scgraph` command

`scgraph` checks the dependencies that a project really installs. It reads the
lockfile, not a guess of the tree. Each alert shows the dependency path that proves
it. Each finding that is not an alert shows the reason.

```bash
pipx install scgraph-cli             # or: uvx --from scgraph-cli scgraph scan .
scgraph scan .
```

## `scgraph scan`

```bash
scgraph scan [PATH ...] [options]
```

`PATH` is a lockfile or a directory. In a directory, scgraph finds every lockfile. It
does not go into `node_modules`, `.venv`, `vendor`, `target` or hidden directories.

| lockfile | ecosystem | edges |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) | npm | yes |
| `yarn.lock` (classic and Berry) | npm | yes |
| `poetry.lock`, `uv.lock` | PyPI | yes |
| `requirements*.txt`, `Pipfile.lock` | PyPI | no (flat) |
| `Cargo.lock` | crates.io | yes |
| `Gemfile.lock` | RubyGems | yes |
| `composer.lock` | Packagist | yes |
| `go.mod` | Go | no (flat) |

A prefixed name also works, for example `api.uv.lock` or `web.package-lock.json`.

### What happens

1. scgraph parses the lockfile into a graph. The root has edges to the direct
   dependencies. Each edge is a field in the lockfile.
2. scgraph asks OSV which package versions have advisories. OSV includes the
   OpenSSF malicious-packages data as `MAL-` records.
3. Records that name the same issue (GHSA, PYSEC, CVE) become one finding.
4. A breadth-first search finds the shortest path from the root to each finding.
   A path through production dependencies has priority over a dev path.
5. Each finding goes through the gates. The first gate that stops it is the reason.
6. scgraph calculates the smallest safe upgrade. For npm, it also finds the smallest
   upgrade of the direct dependency that removes the vulnerable child.

### The gates

| gate | the finding stops when |
|---|---|
| `withdrawn` | the advisory is withdrawn |
| `path` | no path from a declared root reaches the package |
| `scope` | only dev dependencies reach the package. Malicious packages do not stop here, because install scripts run in CI and on laptops. |
| `severity` | the CVSS score is below `--min-severity`. Malicious and CISA KEV findings do not stop here. |
| `ignored` | an entry in the ignore file matches and is not expired |

### Priorities

| priority | meaning |
|---|---|
| P0 | a malicious release |
| P1 | actively exploited (CISA KEV) |
| P2 | critical (CVSS 9.0 or more) or EPSS 0.1 or more |
| P3 | high (CVSS 7.0 or more) |
| P4 | all other alerts |

### Options

| option | effect |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown`, `openvex` |
| `-o, --output FILE` | write the report to a file |
| `--fail-on LEVEL` | exit 1 at this priority or worse: `P0` to `P4`, `any` (default), `never` |
| `--min-severity N` | CVSS floor |
| `--include-dev` | alert on dev-only dependencies |
| `--advisory ID` | incident mode: report only this advisory. Use it more than once for a list. |
| `--ignore-file FILE` | ignore list. The default is `.scgraph-ignore` if it exists. |
| `--offline DIR` | use OSV dumps in `DIR`, not the OSV API |
| `--no-signals` | do not get CISA KEV and EPSS |
| `--no-registry` | do not get registry data for the direct-dependency bump |
| `--summary FILE`, `--github-summary` | also write a Markdown summary |
| `-v` | show each abstention and each advisory |

Exit codes: `0` no alert at the `--fail-on` level, `1` alerts, `2` error.

### Incident mode

An advisory is public. You must know which repositories it reaches.

```bash
scgraph scan ~/src --advisory CVE-2021-44228 --advisory GHSA-jfh8-c2jp-5v3q
```

The last section of the output lists each package and each lockfile that it reaches.
`--format json` gives the full list.

### The ignore file

```text
# .scgraph-ignore
GHSA-29mw-wpgm-hmr9  until=2027-01-31  # not reachable: we never call _.template
CVE-2024-45590                         # fixed by our proxy limits
```

An entry with `until=` stops after that date. Then the alert comes back. This
prevents old ignores that nobody reads again.

### Offline and air-gapped use

```bash
scgraph fetch-osv --dir osv npm pypi cargo
scgraph scan . --offline osv
export SCGRAPH_OSV_DIR=$PWD/osv     # use the dumps for check, hook and mcp too
```

The first offline scan of an ecosystem builds an index next to the dump. Later
scans read only the records they need.

## `scgraph check`

```bash
scgraph check npm left-pad@1.3.0 lodash
scgraph check pypi requests==2.32.3
```

Use it before you add a dependency. The result is `ALLOW`, `WARN` or `BLOCK`.

| result | reason |
|---|---|
| BLOCK | the name is not in the registry (a hallucinated name, the target of slopsquatting) |
| BLOCK | the version is a known malicious release |
| BLOCK | the version is not in the registry |
| WARN | the release is younger than `--cooldown` hours (default 48) |
| WARN | the package is younger than 30 days |
| WARN | the name is one edit from a popular package |
| WARN | npm install scripts, or a PyPI version with no wheel |
| WARN | deprecated, yanked, or known vulnerabilities |
| WARN | scgraph cannot check the registry or OSV (`unverified`) |

scgraph does not change "cannot check" into "safe". Exit codes: `0` allow, `1` warn,
`2` block.

## AI coding agents

### Claude Code hook

Add this to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "scgraph hook claude-code"}]}
    ]
  }
}
```

The hook reads each shell command before it runs. It finds the packages that the
command installs or runs: `npm`, `pnpm`, `yarn`, `bun`, `npx`, `pip`, `uv`, `uvx`,
`poetry`, `pipx`, `cargo`, `gem`, `composer` and `go get`. A `BLOCK` denies the
command. A `WARN` asks you. An `ALLOW` does nothing, so your usual permissions apply.

### MCP server

```bash
claude mcp add scgraph -- scgraph mcp
```

The server has no extra dependencies. It has three tools:

| tool | use |
|---|---|
| `check_package` | before the agent adds or runs a package |
| `scan_lockfile` | scan a lockfile or a directory, with paths and a fix plan |
| `explain_advisory` | summary, affected ranges, fixed versions, KEV and EPSS for one id |

## CI

### GitHub Action

```yaml
name: dependencies
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  scgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: YashhMahajan/Graph-Engineering-for-SupplyChain@v1.2.1
        with:
          fail-on: P2
```

The action uploads SARIF to code scanning and writes a summary to the job page.

### pre-commit

```yaml
repos:
  - repo: https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain
    rev: v1.2.1
    hooks:
      - id: scgraph-scan
```

The hook runs only when a lockfile changes. It blocks malicious and exploited
dependencies (`--fail-on P1`).

## Python API

```python
from scgraph.scan import scan, Policy

for result in scan(".", policy=Policy(min_severity=7.0)):
    for f in result.alerts:
        print(f.priority, f.id, " -> ".join(f.path), f.fix)
```

## Limits

- `requirements.txt`, `Pipfile.lock` and `go.mod` have no edges. Each package shows
  as a direct dependency.
- `pnpm-lock.yaml` is not supported yet.
- The direct-dependency bump is for npm only.
- A path shows that the package is installed. It does not show that your code calls
  the vulnerable function.


## VEX output

`scgraph scan . --format openvex` writes an [OpenVEX](https://openvex.dev) 0.2.0 document,
so the "why is this not an alert" answers travel with your SBOM.

| scgraph verdict | VEX statement |
|---|---|
| alert | `affected`, with the fix and the dependency path as the action statement |
| abstained: `path` (no path from a declared root) | `not_affected`, `component_not_present` |
| abstained: `scope` (dev dependencies only) | `not_affected`, `vulnerable_code_not_in_execute_path` |
| abstained: `withdrawn`, `severity`, `ignored` | no statement |

Only abstentions that make a claim about exploitability become `not_affected`. A severity
floor and an ignore entry are policy (an ignore can mean "accepted risk"), and a withdrawn
advisory is not a vulnerability, so none of those three is written as a VEX claim. The
`scope` justification is inferred from the lockfile graph, not from a call graph, and the
statement says so.
