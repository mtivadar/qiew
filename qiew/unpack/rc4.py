"""RC4 (symmetric: encrypt == decrypt)."""
from __future__ import annotations

from PySide6 import QtWidgets

from .base import DecryptPlugin, HexValidator, combo, form, key_bytes


def rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty key")
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n, c in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = c ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


class RC4(DecryptPlugin):
    name = "rc4"
    priority = 1

    def build_ui(self, parent):
        self.key = QtWidgets.QLineEdit()
        self.kind = combo(["String", "Hex"])
        self.kind.currentTextChanged.connect(self._kind)
        return form(parent, [("Key", self.key), ("Type", self.kind)])

    def _kind(self, text):
        self.key.clear()
        self.key.setValidator(HexValidator(self.key) if text == "Hex" else None)

    def proceed(self, doc, rng, parent):
        key = key_bytes(self.key.text(), self.kind.currentText() == "Hex")
        if not self.key.text():
            return "enter a key"
        a, b = rng
        doc.dm.write(a, rc4(doc.dm.read(a, b), key))
        return f"rc4 applied to {b - a} bytes"
