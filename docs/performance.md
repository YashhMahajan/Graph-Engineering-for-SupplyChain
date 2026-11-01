# Performance and security changes

This page gives the measured results of the change. It also tells you how to measure
them again. The text follows the ASD-STE100 rules for Simplified Technical English.

## How to measure

Run this command:

```bash
make bench
```

The benchmark makes a synthetic graph. The graph has 2,000,000 versions and
8,000,000 edges. The in-degree of the graph is heavy-tailed, as in the real graph.
The benchmark measures three operations:

- **Build.** The time to change the Parquet tables into the CSR store.
- **Load.** The time to open the store with `KGStore()`.
- **Audit.** The time for one exposure-path search from one root version.

## Results

We ran each version two times on the same machine, in the same session. The table
gives the mean of the two runs.

| Operation | Before (`main`) | After | Change |
|---|---|---|---|
| Build the store | 21.7 s | 7.7 s | **2.8x faster (-65%)** |
| Load the store | 1.34 s | 0.020 s | **67x faster (-98.5%)** |
| Project the store onto the core graph (`from_kgstore`) | 29.0 s | 12.5 s | **2.3x faster (-57%)** |
| First package lookup (`pkg_id`), loaded store | builds a dict of all packages | binary search | **no start-up cost** |
| First core key lookup (`node`), loaded graph | 1.4 s | less than 1 ms | **more than 1,000x faster** |
| Verified load of a core snapshot (1M nodes, 5M edges) | 1.2 s | 0.6 s | **2x faster (-50%)** |
| Access one string by index | 2.9 µs | 0.7 µs | **4x faster** |
| Audit, warm cache, p50 | 0.102 ms | 0.103 ms | no change (in the noise) |

At the full scale of 21.4M versions, the load time was 13 s before the change. The
load time does not increase with the number of strings now, because no string is
decoded at load.

## Security results

| Risk | Before | After |
|---|---|---|
| Load a graph directory from an unknown source | `np.load(allow_pickle=True)` can run code from the file | No pickle on the load path. A 1.0 directory gives an error, not code execution. |
| Download release artifacts | Extracted with no hash check | A pinned sha256 is necessary. HTTPS only. Downloads stop after 120 s with no data. |
| Edit the key index of a core snapshot | Not detected | The fingerprint includes the index. A damaged index gives an error, also with `verify=False`. |

## How I did it

> I removed every pickled array and kept strings as one UTF-8 block plus offsets, so
> the store opens with memory maps and no code runs. I then replaced each per-row
> Python loop on the build and load paths with one NumPy or Arrow operation.

The specific changes:

1. **Strings.** A `StrColumn` keeps a column of strings as one `uint8` array and one
   `int64` offset array. Both arrays are memory-mapped. A string is decoded only when
   you read it. Arrow keeps strings in the same layout, so the encode step copies two
   buffers and does no work per string.
2. **Package to versions.** The build step writes this map as a CSR. Before, the load
   step made the map with a Python loop over all versions.
3. **CSR construction.** `np.bincount` and `np.cumsum` make the index pointer in one
   pass. Before, `np.add.at` did an unbuffered scatter.
4. **Package-pair deduplication.** Each pair becomes one `int64` code, and one 1-D sort
   removes duplicates. Before, `np.unique(axis=0)` sorted structured rows. That sort
   used most of the build time.
5. **Key lookup.** The build step saves the sort order of the keys. A lookup is a binary
   search over that order. No dictionary of all keys is necessary.
6. **Dates.** Arrow parses the date columns in C. Python parses only the rows with a
   time zone offset.

## Known limits

- The benchmark graph is synthetic. Real trees are deeper, so real audit times are
  longer. The comparison between the two versions stays valid.
- Python decodes a string from a `StrColumn` more slowly than it reads an item from an
  object array (0.7 µs against 0.4 µs). The audit time does not change, because an
  audit reads few strings.
