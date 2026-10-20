"""AES-CBC encrypt/decrypt in place (pure python ``pyaes``, optional)."""
from __future__ import annotations

import pyaes  # optional dependency; plugin is skipped if missing
from PySide6 import QtWidgets

from .base import DecryptPlugin, HexValidator, combo, form, key_bytes


def aes_cbc(data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
    """Process whole 16-byte blocks; a trailing partial block is left as is."""
    n = len(data) // 16 * 16
    mode = pyaes.AESModeOfOperationCBC(key, iv=iv)
    fn = mode.encrypt if encrypt else mode.decrypt
    out = bytearray(data)
    for i in range(0, n, 16):
        out[i:i + 16] = fn(bytes(data[i:i + 16]))
    return bytes(out)


class AES(DecryptPlugin):
    name = "aes"
    priority = 2

    def build_ui(self, parent):
        self.key = QtWidgets.QLineEdit()
        self.key_kind = combo(["String", "Hex"])
        self.iv = QtWidgets.QLineEdit()
        self.iv_kind = combo(["String", "Hex"])
        self.op = combo(["decrypt", "encrypt"])
        for edit, kind in ((self.key, self.key_kind), (self.iv, self.iv_kind)):
            kind.currentTextChanged.connect(
                lambda t, e=edit: (e.clear(), e.setValidator(HexValidator(e) if t == "Hex" else None)))
        return form(parent, [("Key (16/24/32 bytes)", self.key), ("Key type", self.key_kind),
                             ("IV (16 bytes)", self.iv), ("IV type", self.iv_kind),
                             ("Mode: CBC", self.op)])

    def proceed(self, doc, rng, parent):
        key = key_bytes(self.key.text(), self.key_kind.currentText() == "Hex")
        iv = key_bytes(self.iv.text(), self.iv_kind.currentText() == "Hex")
        if len(key) not in (16, 24, 32):
            return f"key must be 16/24/32 bytes (got {len(key)})"
        if len(iv) != 16:
            return f"IV must be 16 bytes (got {len(iv)})"
        a, b = rng
        doc.dm.write(a, aes_cbc(doc.dm.read(a, b), key, iv, self.op.currentText() == "encrypt"))
        return f"aes-cbc {self.op.currentText()}ed {(b - a) // 16} blocks"
