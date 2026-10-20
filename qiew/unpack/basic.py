"""XOR / ROL / ROR / ADD / SUB with optional evolving key (vectorised with numpy)."""
from __future__ import annotations

import numpy as np
from PySide6 import QtWidgets

from .base import DecryptPlugin, HexValidator, combo, form, parse_key

OPS = ["XOR", "ROL", "ROR", "ADD", "SUB"]
KEY_OPS = ["---", "ROL", "ROR", "ADD", "SUB", "XOR"]


def _scalar(op: str, v: int, k: int, size: int) -> int:
    bits = size * 8
    mask = (1 << bits) - 1
    if op == "ROL":
        k %= bits
        return ((v << k) | (v >> (bits - k))) & mask
    if op == "ROR":
        k %= bits
        return ((v >> k) | (v << (bits - k))) & mask
    if op == "ADD":
        return (v + k) & mask
    if op == "SUB":
        return (v - k) & mask
    if op == "XOR":
        return (v ^ k) & mask
    return v


def _keysize(k: int) -> int:
    return max(1, (k.bit_length() + 7) // 8)


def transform(data: bytes, op: str, key: int, size: int = 1, skip: int = 0,
              keyop: str = "---", delta: int = 0) -> bytes:
    """Apply ``op`` with ``key`` on little-endian words of ``size`` bytes.

    Words start every ``size + skip`` bytes. After each word the key is updated
    with ``keyop(key, delta)`` (key width = its own byte length). Only full words
    inside ``data`` are transformed.
    """
    if size < 1 or size > 8:
        raise ValueError("size must be 1..8")
    n = len(data)
    stride = size + max(0, skip)
    starts = np.arange(0, n - size + 1, stride, dtype=np.int64)
    if not starts.size:
        return bytes(data)
    arr = np.frombuffer(bytes(data), dtype=np.uint8).copy()
    idx = starts[:, None] + np.arange(size)
    b = arr[idx].astype(np.uint64)                       # (m, size)
    shifts = (np.arange(size, dtype=np.uint64) * np.uint64(8))
    v = (b << shifts).sum(axis=1, dtype=np.uint64)       # (m,)

    bits = size * 8
    mask = np.uint64((1 << bits) - 1)
    m = starts.size
    if keyop == "---":
        keys = None
        kmod = key
    else:
        ks, k = [], key
        for _ in range(m):
            ks.append(k)
            k = _scalar(keyop, k, delta, _keysize(k))
        keys = np.array(ks, dtype=object)
        kmod = None

    if op in ("ROL", "ROR"):
        kk = (np.uint64(kmod % bits) if kmod is not None
              else np.array([x % bits for x in keys], dtype=np.uint64))
        inv = (np.uint64(bits) - kk) % np.uint64(bits)
        if op == "ROL":
            r = ((v << kk) | np.where(kk == 0, np.uint64(0), v >> inv)) & mask
        else:
            r = ((v >> kk) | np.where(kk == 0, np.uint64(0), v << inv)) & mask
    else:
        km = (np.uint64(kmod & int(mask)) if kmod is not None
              else np.array([x & int(mask) for x in keys], dtype=np.uint64))
        with np.errstate(over="ignore"):
            if op == "ADD":
                r = (v + km) & mask
            elif op == "SUB":
                r = (v - km) & mask
            else:
                r = (v ^ km) & mask

    out_b = ((r[:, None] >> shifts) & np.uint64(0xFF)).astype(np.uint8)
    arr[idx] = out_b
    return arr.tobytes()


class Basic(DecryptPlugin):
    name = "basic"
    priority = 0

    def build_ui(self, parent):
        self.op = combo(OPS)
        self.key = QtWidgets.QLineEdit("0")
        self.key.setValidator(HexValidator(self.key))
        self.keyop = combo(KEY_OPS)
        self.delta = QtWidgets.QLineEdit("0")
        self.delta.setValidator(HexValidator(self.delta))
        self.size = QtWidgets.QSpinBox()
        self.size.setRange(1, 8)
        self.skip = QtWidgets.QSpinBox()
        self.skip.setRange(0, 1 << 20)
        self.key.textChanged.connect(lambda t: self.size.setValue(min(8, _keysize(parse_key(t)))))
        return form(parent, [("Operation", self.op), ("Key", self.key), ("Key operation", self.keyop),
                             ("Value", self.delta), ("Bytes", self.size), ("Skip", self.skip)])

    def proceed(self, doc, rng, parent):
        a, b = rng
        data = doc.dm.read(a, b)
        out = transform(data, self.op.currentText(), parse_key(self.key.text()), self.size.value(),
                        self.skip.value(), self.keyop.currentText(), parse_key(self.delta.text()))
        doc.dm.write(a, out)
        return f"{self.op.currentText()} applied to {b - a} bytes"
