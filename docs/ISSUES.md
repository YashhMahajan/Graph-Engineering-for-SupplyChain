# Issues, limits and open work

This page lists what is open, what is known to be weak, and what went wrong before. It follows
the ASD-STE100 rules for Simplified Technical English. When you find a new issue, add it here.

## Open work

| Item | State | What to do |
|---|---|---|
| npm code-search records | Open | Run `make symbols-refresh` after the daily LLM reset (00:00 UTC). Search records need an LLM confirmation. |
| 17 stale Go LLM answers | Open | The same command refreshes them. They need about 4 requests. |
| Wider datasets | Open | Run the two `build_dataset.py` commands in [DATA-SOURCES.md](DATA-SOURCES.md) (`--popular 5000` and `3000`). It takes hours and loads the machine. Then run `scgraph symbols sign`. |
| Release 1.4.0 | Ready, not published | The version, the changelog and the citation are set. Create the tag when you want the release. |
| Scan-side support for Maven and Cargo | Not planned | There is no parser and no dataset for them. Maven and Cargo scans still work. They do not check the function. |
| Upstream OSV patches | Not sent | `scgraph symbols export` writes the patches. A person must send them to an advisory database. |
| Transitive reachability: second path | Open | `--deep` follows the shortest path only. |

## Limits of the symbols work

- `not_called` means "no reference found". It is not proof. A call through `getattr`, `eval`, a
  plugin registry, an unnamed class instance, or another package's wrapper is not seen.
- The call graph is name-based. It marks 81% of a dependency's functions reachable. A profiler saw
  5% to 53% of them run in one scenario. The verdict is sound but coarse for large dependencies.
- `getattr` dispatch showed no gain in the measured benchmark. It stays because visitor-style code
  needs it. It costs 0.4 points of reach.
- A fix that changes only a constant (for example a regular expression) leaves the function
  unchanged. The verifier abstains.
- npm: *public* means *exported*. A minified bundle cannot be verified, because the names are
  changed. A TypeScript fix is matched to the compiled release by function name.
- The LLM stage has a small sample. The gain on 37 Go advisories is not significant (p = 0.625).
- The free tier gives 50 requests a day. The model `ernie-5.5-flash-preview` reasons at length.
  About 1 batch in 5 loops until its token limit. The client splits a failed batch and retries.
- `thinkingmachines/inkling-2-small:free` answers HTTP 403 to an ordinary API key.
- The signature proves that the key holder approved the data. It does not prove that the data is
  correct. The private key is on one machine. Back it up.

## Limits of the research results

**Three metrics are partly circular.**

1. "100% path retention" is a tautology. The parser writes an edge only when both ends exist.
   The useful number is parse retention: 96.64% of declared dependencies found a version.
2. The ablation curve is a consistency check. It shows that the system does not alert on what it
   cannot trace. It does not prove cause.
3. The semantic-relevance AUROC of 0.955 is partly string match. Advisory summaries often name
   the package.

**Other limits.**

- The model layer needs a CUDA GPU. The CPU layers run everywhere.
- The corpus is a snapshot of 2020-01-12. The advisory feed is live. The resolver comparison uses
  only versions that exist in the snapshot.
- scgraph does not claim zero false negatives. It claims that each alert has a path.
- The grounder cannot resolve informal names, renamed packages and vendored copies.
- Reachability is not decidable in general. For the full run, 79% of alerts were `undetermined`
  before the symbols work.

## Bugs that gave good-looking wrong results

Each bug made the system look better than it was. None gave an error.

1. Advisory rows were not indexed by advisory id when a record occurred in several zip files.
2. Alias-to-CVE canonicalisation did not find the CVE. `CVE-2021-44228` grounded to nothing.
3. The grounder matched removed malware packages (more than 200,000 `MAL-` records).
4. Remediation selected prerelease versions as the fix.
5. A KS distance alone was called a power law. The Clauset test rejects it (p = 0.0).
6. Betweenness ran for more than 25 minutes. A degree limit and a timeout now stop it.
7. A function that the fix edited on one line was marked "added by the fix". A function now counts
   as new only when its whole span is added and nothing is deleted in it.
8. Dataset signing failed on Windows because text mode changed the line endings. The files are
   now written with LF on every platform.

Lesson: each layer needs its own ground truth. An end-to-end score hides all of these bugs.

## Rejected changes

- A multi-agent coordination layer lowered alerts from 12,717 to 12,316 and cleared fewer
  advisories (273 to 178). It stays as a measured negative result.
- The structural reachability prior lowered alerts from 9,853 to 9,789. We report this effect.
  We did not tune it.
- A trained ranker for symbols did not beat the hand-set weights on validation.
- A chat interface over the documents was rejected. It changes no decision. `scgraph ask` answers
  from the scan only, with a citation on every sentence.

## What helped

Grounding (a name-to-package resolver that indexes only real packages) and the provenance gates
(withdrawn, as-of date, not installable) give the gains. The model layer and the agent loop do
not.
