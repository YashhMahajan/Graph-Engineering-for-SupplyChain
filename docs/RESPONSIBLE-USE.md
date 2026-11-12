# Responsible use

scgraph is a defensive tool. These rules apply to all users and contributors. This page
follows the ASD-STE100 rules for Simplified Technical English.

## Use it to protect what you own or maintain

- Scan your own projects, or projects that you have permission to examine.
- Use the results to fix, upgrade or remove dependencies.
- Report a new malicious package to the registry and to
  [ossf/malicious-packages](https://github.com/ossf/malicious-packages).

## Do not misuse it

- Do not use the guard data to choose names for squatting. The typosquat list and
  the "does not exist" result are for defence only.
- Do not use exposure paths to attack a project that has not fixed a vulnerability.
  Follow the [security policy](../SECURITY.md) of that project. Give the
  maintainers time to fix it.
- Do not publish a list of exposed third-party repositories. Tell the maintainers in
  private first.
- Do not use scgraph output as the only proof that a system is safe. An abstention is
  a reason, not a guarantee.
- Do not send the OSV patches from `scgraph symbols export` to a third party in a bulk or
  automatic way. A person must read each patch first.

## Be a good client of public services

scgraph uses OSV, CISA KEV, FIRST EPSS and the public package registries. These are
free services.

- Keep the cache (`~/.cache/scgraph`). scgraph keeps OSV records by id and modified
  time, and KEV and EPSS for one day.
- For many repositories or frequent CI runs, use `scgraph fetch-osv` and
  `--offline`. Download the dumps once per day.
- Do not remove the `User-Agent` that identifies scgraph.
- Do not run many scans in parallel against the public APIs.

## Respect the data licenses

| source | license |
|---|---|
| OSV and the GitHub Advisory Database | CC BY 4.0 |
| Libraries.io Open Data | CC BY-SA 4.0 |
| CISA KEV | public domain (US government) |
| FIRST EPSS | free use with attribution |

If you publish results, name the sources.

## Know the limits

- `not_called` means that scgraph found no reference to the vulnerable function. It is not proof.
  Do not close an alert because of it.
- A path shows that a vulnerable version is installed. It does not show that the
  vulnerable code runs.
- The guard can be wrong. A new attack can pass it. A safe package can get a warning.
- OSV can be late. A malicious release can be live for hours before a `MAL-` record
  exists. The release cooldown in `scgraph check` covers part of this time.
