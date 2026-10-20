"""Base64 decode/encode the selection into a new window (or a file)."""
from __future__ import annotations

import base64
import binascii

from PySide6 import QtWidgets

from .base import DecryptPlugin, combo, form


class Base64(DecryptPlugin):
    name = "base64"
    priority = 3

    def build_ui(self, parent):
        self.op = combo(["decode", "encode"])
        self.dest = combo(["open in new window", "write <file>.base64"])
        return form(parent, [("Type", self.op), ("Result", self.dest)])

    def proceed(self, doc, rng, parent):
        a, b = rng
        data = doc.dm.read(a, b)
        try:
            if self.op.currentText() == "decode":
                out = base64.b64decode(b"".join(data.split()), validate=False)
            else:
                out = base64.b64encode(data)
        except (binascii.Error, ValueError) as e:
            return f"error: {e}"
        name = f"{doc.dm.source or 'buffer'}.base64"
        if self.dest.currentIndex() == 0 and doc.open_buffer:
            doc.open_buffer(out, name)
            return f"{len(out)} bytes opened"
        try:
            with open(name, "wb") as f:
                f.write(out)
        except OSError as e:
            return f"error: {e}"
        QtWidgets.QMessageBox.information(parent, "Qiew", f"Done:\n{name}")
        return "written"
