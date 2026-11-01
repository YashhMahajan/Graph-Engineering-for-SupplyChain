"""Pickle-free, memory-mapped string columns (UTF-8 blob + int64 offsets)."""

from __future__ import annotations

from pathlib import Path

import numpy as np


class StrColumn:
    """An immutable string column stored as one UTF-8 blob plus int64 offsets.

    Replaces pickled ``dtype=object`` arrays. Two reasons:

    * **Security.** ``np.load(..., allow_pickle=True)`` executes whatever the file says.
      Graph directories are downloaded as release artifacts, so a tampered artifact was
      arbitrary code execution on load. This format is plain bytes; nothing executes.
    * **Speed and memory.** Both arrays are memory-mapped: opening a 21M-entry column
      costs two ``mmap`` calls instead of unpickling 21M Python objects, and strings
      are decoded only when touched.

    Behaves like the object array it replaces for the ways the code base uses it:
    ``col[i] -> str``, ``len(col)``, iteration, ``np.asarray(col)``, and fancy/slice
    indexing (returns an object ndarray).
    """

    __slots__ = ("_blob", "_off", "_bv", "_ov", "_n")

    def __init__(self, blob: np.ndarray, offsets: np.ndarray):
        if offsets.ndim != 1 or len(offsets) == 0 or int(offsets[0]) != 0:
            raise ValueError("offsets must be 1-D and start at 0")
        if int(offsets[-1]) != len(blob):
            raise ValueError("offsets do not match the blob length")
        self._blob, self._off = blob, offsets
        # memoryviews: indexing one yields a plain Python int / bytes slice, ~5x faster
        # per element than indexing a (memory-mapped) numpy array
        self._ov = memoryview(np.ascontiguousarray(offsets, np.int64))
        self._bv = memoryview(np.ascontiguousarray(blob, np.uint8))
        self._n = len(offsets) - 1

    @staticmethod
    def encode(values) -> tuple[np.ndarray, np.ndarray]:
        enc = [("" if v is None else str(v)).encode("utf-8") for v in values]
        off = np.zeros(len(enc) + 1, np.int64)
        if enc:
            np.cumsum([len(b) for b in enc], out=off[1:])
        return np.frombuffer(b"".join(enc), np.uint8).copy(), off

    @staticmethod
    def encode_arrow(col) -> tuple[np.ndarray, np.ndarray]:
        """Zero-Python encode of an Arrow string column: Arrow already stores strings as
        a UTF-8 data buffer plus offsets, which is exactly this format."""
        import pyarrow as pa

        arr = col.combine_chunks() if isinstance(col, pa.ChunkedArray) else col
        arr = arr.cast(pa.large_string()).fill_null("")
        _, ob, db = arr.buffers()
        n = len(arr)
        off = np.frombuffer(ob, np.int64, count=n + 1, offset=arr.offset * 8).copy()
        base = int(off[0])
        off -= base
        blob = (
            np.frombuffer(db, np.uint8, count=int(off[-1]), offset=base).copy()
            if db is not None and off[-1]
            else np.zeros(0, np.uint8)
        )
        return blob, off

    @classmethod
    def save(cls, base: Path, values) -> None:
        import pyarrow as pa

        if isinstance(values, StrColumn):
            blob, off = np.asarray(values._blob), np.asarray(values._off)
        elif isinstance(values, pa.Array | pa.ChunkedArray):
            blob, off = cls.encode_arrow(values)
        else:
            blob, off = cls.encode(values)
        np.save(base.with_name(base.name + ".utf8.npy"), blob)
        np.save(base.with_name(base.name + ".off.npy"), off)

    @classmethod
    def load(cls, base: Path) -> StrColumn:
        blob = np.load(base.with_name(base.name + ".utf8.npy"), mmap_mode="r", allow_pickle=False)
        off = np.load(base.with_name(base.name + ".off.npy"), mmap_mode="r", allow_pickle=False)
        return cls(blob, off)

    @staticmethod
    def exists(base: Path) -> bool:
        return base.with_name(base.name + ".off.npy").exists()

    def __len__(self) -> int:
        return self._n

    def _one(self, i: int) -> str:
        n = self._n
        if i < 0:
            i += n
        if not 0 <= i < n:
            raise IndexError(f"index {i} out of range for column of length {n}")
        o = self._ov
        return str(self._bv[o[i] : o[i + 1]], "utf-8")

    def __getitem__(self, key):
        if type(key) is int:  # hot path: skip the isinstance chain
            return self._one(key)
        if isinstance(key, np.integer):
            return self._one(int(key))
        idx = np.atleast_1d(np.arange(len(self))[key])
        if len(idx) > 64:
            return np.array(self.to_arrow().take(idx).to_pylist(), dtype=object)
        return np.array([self._one(int(i)) for i in idx], dtype=object)

    def to_arrow(self):
        """Zero-copy view as an Arrow ``large_string`` array."""
        import pyarrow as pa

        return pa.LargeStringArray.from_buffers(
            len(self), pa.py_buffer(np.asarray(self._off)), pa.py_buffer(np.asarray(self._blob))
        )

    def tolist(self) -> list[str]:
        """Decode everything at once (in C, via Arrow): ~50x faster than per-item."""
        return self.to_arrow().to_pylist()

    def __iter__(self):
        return iter(self.tolist())

    def __array__(self, dtype=None, copy=None):
        return np.array(self.tolist(), dtype=object if dtype is None else dtype)

    @classmethod
    def concat(cls, head, tail: list[str]) -> StrColumn:
        """``head`` (a StrColumn or any sequence of str) followed by ``tail``, built from
        buffers: the existing strings are never decoded."""
        if isinstance(head, StrColumn):
            hb, ho = np.asarray(head._blob), np.asarray(head._off)
        else:
            hb, ho = cls.encode(head)
        tb, to = cls.encode(tail)
        return cls(np.concatenate([hb, tb]), np.concatenate([ho, to[1:] + ho[-1]]))

    def sort_order(self) -> np.ndarray:
        """Indices that sort the column by UTF-8 bytes (== code point order), in C."""
        import pyarrow.compute as pc

        return pc.sort_indices(self.to_arrow()).to_numpy().astype(np.int64)

    def find(self, key: str, order: np.ndarray) -> int:
        """Index of ``key`` given ``order`` from :meth:`sort_order`, or -1. Binary search:
        O(log n) string decodes, no index to build."""
        lo, hi = 0, len(order)
        while lo < hi:
            mid = (lo + hi) // 2
            v = self._one(int(order[mid]))
            if v < key:
                lo = mid + 1
            else:
                hi = mid
        if lo < len(order) and self._one(int(order[lo])) == key:
            return int(order[lo])
        return -1
