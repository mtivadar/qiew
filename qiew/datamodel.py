"""Data sources: memory mapped files and in-memory buffers.

Changes are tracked as merged byte intervals so that

* saving only writes the modified ranges back (instead of the whole file),
* views can colour modified bytes cheaply,
* a version counter lets views know when cached renders are stale.
"""
from __future__ import annotations

import bisect
import mmap
import os
import struct


class IntervalSet:
    """Sorted, merged, half-open [a, b) intervals."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def add(self, a: int, b: int) -> None:
        if b <= a:
            return
        i = bisect.bisect_left(self._ends, a)
        j = bisect.bisect_right(self._starts, b)
        if i < j:
            a = min(a, self._starts[i])
            b = max(b, self._ends[j - 1])
        self._starts[i:j] = [a]
        self._ends[i:j] = [b]

    def overlapping(self, a: int, b: int):
        """Yield intervals intersecting [a, b), clipped."""
        i = bisect.bisect_right(self._ends, a)
        while i < len(self._starts) and self._starts[i] < b:
            yield max(a, self._starts[i]), min(b, self._ends[i])
            i += 1

    def clear(self) -> None:
        self._starts.clear()
        self._ends.clear()

    def __iter__(self):
        return iter(zip(self._starts, self._ends))

    def __bool__(self) -> bool:
        return bool(self._starts)

    def __len__(self) -> int:
        return len(self._starts)


class DataModel:
    """Byte container with typed little-endian accessors and change tracking."""

    def __init__(self, data, name: str = "") -> None:
        self._data = data
        self._name = name
        self.modified = IntervalSet()
        self.version = 0

    # -- identity -----------------------------------------------------------
    @property
    def source(self) -> str:
        return self._name

    @property
    def data(self):
        """Raw buffer (mmap or bytearray). Supports slicing / find / rfind."""
        return self._data

    def __len__(self) -> int:
        return len(self._data)

    size = __len__

    # -- reading -------------------------------------------------------------
    def read(self, a: int, b: int) -> bytes:
        a = max(0, a)
        b = min(len(self._data), b)
        if b <= a:
            return b""
        return bytes(self._data[a:b])

    def byte(self, off: int) -> int | None:
        if 0 <= off < len(self._data):
            return self._data[off]
        return None

    def _unpack(self, fmt: str, off: int, n: int):
        if off < 0 or off + n > len(self._data):
            return None
        return struct.unpack_from(fmt, self._data, off)[0]

    def u16(self, off: int):
        return self._unpack("<H", off, 2)

    def u32(self, off: int):
        return self._unpack("<I", off, 4)

    def u64(self, off: int):
        return self._unpack("<Q", off, 8)

    def find(self, needle: bytes, start: int = 0, end: int | None = None) -> int:
        end = len(self._data) if end is None else end
        return self._data.find(needle, start, end)

    def rfind(self, needle: bytes, start: int = 0, end: int | None = None) -> int:
        end = len(self._data) if end is None else end
        return self._data.rfind(needle, start, end)

    # -- writing -------------------------------------------------------------
    @property
    def writable(self) -> bool:
        return True

    def write(self, off: int, data: bytes | bytearray) -> bool:
        if not data or off < 0:
            return False
        end = min(len(self._data), off + len(data))
        if end <= off:
            return False
        self._data[off:end] = bytes(data[: end - off])
        self.modified.add(off, end)
        self.version += 1
        return True

    def set_byte(self, off: int, value: int) -> bool:
        return self.write(off, bytes([value & 0xFF]))

    @property
    def dirty(self) -> bool:
        return bool(self.modified)

    def save(self) -> bool:
        return False

    def save_as(self, path: str) -> bool:
        with open(path, "wb") as f:
            # write in chunks to keep memory bounded for big files
            step = 1 << 22
            for a in range(0, len(self._data), step):
                f.write(self._data[a:a + step])
        return True

    def close(self) -> None:
        pass


class BufferDataModel(DataModel):
    """In-memory buffer (e.g. a file extracted from an archive)."""

    def __init__(self, data: bytes | bytearray, name: str = "<buffer>") -> None:
        super().__init__(bytearray(data), name)


class FileDataModel(DataModel):
    """Copy-on-write memory mapped file. Edits stay in memory until save()."""

    def __init__(self, filename: str) -> None:
        self._filename = os.path.abspath(filename)
        self._f = open(self._filename, "rb")
        size = os.fstat(self._f.fileno()).st_size
        if size == 0:
            data = bytearray()  # mmap refuses empty files on every platform
        else:
            data = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_COPY)
        super().__init__(data, self._filename)

    def save(self) -> bool:
        """Write only modified ranges back to the file."""
        if not self.modified:
            return True
        try:
            with open(self._filename, "r+b") as out:
                for a, b in self.modified:
                    out.seek(a)
                    out.write(self._data[a:b])
                out.flush()
        except OSError:
            return False
        self.modified.clear()
        self.version += 1
        return True

    def close(self) -> None:
        try:
            if isinstance(self._data, mmap.mmap):
                self._data.close()
        finally:
            self._f.close()
