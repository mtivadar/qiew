"""Base class + helpers for decrypt/encrypt plugins."""
from __future__ import annotations

from PySide6 import QtGui, QtWidgets


class DecryptPlugin:
    name = ""
    priority = 0
    needs_selection = True

    def build_ui(self, parent) -> QtWidgets.QWidget:
        return QtWidgets.QWidget(parent)

    def proceed(self, doc, rng: tuple[int, int] | None, parent) -> str:
        """Apply the transformation. Return a short status message."""
        return ""


def parse_key(s: str) -> int:
    """``0x1234`` / ``1234`` / ``12 34 56`` (bytes, little-endian) -> int."""
    s = s.strip()
    if not s:
        return 0
    if " " not in s:
        try:
            return int(s, 0)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                return 0
    x = 0
    for i, part in enumerate(s.split()):
        try:
            x |= int(part, 16) << (8 * i)
        except ValueError:
            return 0
    return x


def key_bytes(text: str, as_hex: bool) -> bytes:
    if not as_hex:
        return text.encode("utf-8")
    t = text.strip()
    if " " in t:
        try:
            return bytes(int(p, 16) for p in t.split())
        except ValueError:
            return b""
    k = parse_key(t)
    return k.to_bytes(max(1, (k.bit_length() + 7) // 8), "little")


class HexValidator(QtGui.QValidator):
    """Accepts ints (0x.., decimal) or 'xx xx xx'; tints the line edit yellow while incomplete."""

    def validate(self, text, pos):
        ok = QtGui.QValidator.State.Acceptable
        bad = all(c in " 0123456789abcdefABCDEFx" for c in text)
        if not bad:
            return QtGui.QValidator.State.Invalid, text, pos
        complete = True
        if " " in text:
            complete = all(len(p) == 2 for p in text.split(" ") if p != "")
        elif text:
            try:
                int(text, 0)
            except ValueError:
                try:
                    int(text, 16)
                except ValueError:
                    complete = False
        w = self.parent()
        if isinstance(w, QtWidgets.QLineEdit):
            w.setStyleSheet("" if complete else "QLineEdit { background-color: #fff79a; color: black }")
        return ok, text, pos


def form(parent, rows) -> QtWidgets.QWidget:
    w = QtWidgets.QWidget(parent)
    lay = QtWidgets.QFormLayout(w)
    for label, widget in rows:
        lay.addRow(label, widget)
    return w


def combo(items) -> QtWidgets.QComboBox:
    c = QtWidgets.QComboBox()
    c.addItems(items)
    return c
