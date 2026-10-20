"""File format plugin interface (replaces the yapsy based FileFormat)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from PySide6 import QtGui, QtWidgets
from PySide6.QtCore import Qt

from .. import disasm, highlight

if TYPE_CHECKING:  # pragma: no cover
    from ..datamodel import DataModel
    from ..document import Document

_STR_RE = re.compile(rb"[a-zA-Z0-9 .;':=\"?\-!()/\\_%*<>,@#$&+\[\]{}|~^`]+")
_WSTR_RE = re.compile(rb"(?:[a-zA-Z0-9 .;':=\"?\-!()/\\_%*<>,@#$&+\[\]{}|~^`]\x00)+")


def read_string(dm: "DataModel", off: int | None, limit: int = 256) -> str:
    """ASCII or UTF-16LE string at ``off`` (empty if nothing printable)."""
    if off is None or off < 0 or off >= len(dm):
        return ""
    buf = dm.read(off, off + limit)
    m = _WSTR_RE.match(buf)
    if m and len(m.group()) >= 8:
        return m.group()[::2].decode("ascii", "replace")
    m = _STR_RE.match(buf)
    return m.group().decode("ascii", "replace") if m else ""


@dataclass
class Action:
    text: str
    shortcut: str | None
    callback: Callable[[], None]
    # letter-only shortcuts are suspended automatically while editing


class FileFormat:
    """Base class. Subclass, set ``name``/``priority`` and override what you need.

    Format plugins are discovered from ``qiew/formats/*.py`` and from
    ``~/.qiew/plugins/*.py``; any ``FileFormat`` subclass found is registered.
    """

    name = "binary"
    priority = 0
    description = "Unknown binary"
    address_modes: tuple[str, ...] = ("FileAddr",)
    left_width = 10        # characters of the left (address) banner

    def __init__(self, dm: "DataModel") -> None:
        self.dm = dm
        self.doc: "Document | None" = None
        self.mode = 0

    # ---------------------------------------------------------------- detection
    @classmethod
    def recognize(cls, dm: "DataModel") -> bool:
        return False

    # ---------------------------------------------------------------- setup
    def setup(self, doc: "Document") -> None:
        """Install highlight rules / permanent marks. Called once."""
        doc.hl.rules = highlight.default_rules()

    # ---------------------------------------------------------------- addresses
    def va(self, offset: int) -> int | None:
        return offset

    def fa(self, va: int) -> int | None:
        return va if 0 <= va < len(self.dm) else None

    def disasm_arch(self):
        return disasm.X86_32

    def symbol(self, va: int) -> str | None:
        return None

    def string_at_va(self, va: int) -> str:
        return read_string(self.dm, self.fa(va))

    # ---------------------------------------------------------------- banners
    @property
    def address_mode(self) -> str:
        return self.address_modes[self.mode % len(self.address_modes)]

    def cycle_address_mode(self) -> None:
        self.mode = (self.mode + 1) % len(self.address_modes)

    def address_label(self, offset: int) -> str:
        return f"{offset:08x}"

    def top_label(self) -> str:
        return self.address_mode

    def status_hint(self, offset: int) -> str:
        return ""

    def status_extra(self) -> list[str]:
        return []

    # ---------------------------------------------------------------- goto
    def goto_spaces(self) -> dict[str, Callable[[int], int | None]]:
        return {"FileAddress": lambda x: x}

    def goto_constants(self, space: str) -> dict[str, int]:
        return {"END": len(self.dm)}

    # ---------------------------------------------------------------- actions
    def actions(self) -> list[Action]:
        return [
            Action("Skip run of same byte", "S", self.skip_chars),
            Action("Skip to next zero block", "E", self.skip_block),
        ]

    def goto(self, offset: int | None) -> None:
        if offset is not None and self.doc is not None:
            self.doc.goto(offset)

    @property
    def cursor(self) -> int:
        return self.doc.cursor() if self.doc else 0

    def skip_chars(self) -> None:
        """Jump past the run of bytes equal to the byte under cursor."""
        off = self.cursor
        size = len(self.dm)
        b = self.dm.byte(off)
        if b is None:
            return
        pat = bytes([b])
        x = off + 1
        step = 1 << 16
        while x < size:
            chunk = self.dm.read(x, x + step)
            rest = chunk.lstrip(pat)
            x += len(chunk) - len(rest)
            if rest:
                break
        self.goto(min(x, size - 1))

    def skip_block(self) -> None:
        """Jump to the next run of 8 zero bytes."""
        off = self.cursor
        size = len(self.dm)
        if off >= size:
            return
        x = self.dm.find(b"\x00" * 8, off)
        if x in (-1, off):
            x = min(off + 1, size - 1)
        self.goto(x)


# ------------------------------------------------------------------ UI helpers
OFFSET_ROLE = Qt.ItemDataRole.UserRole
SIZE_ROLE = Qt.ItemDataRole.UserRole + 1

PURPLE = QtGui.QColor(183, 72, 197)
GREEN = QtGui.QColor("green")


def tree_item(texts, offset: int | None = None, size: int | None = None,
              colors: dict[int, QtGui.QColor] | None = None) -> QtWidgets.QTreeWidgetItem:
    it = QtWidgets.QTreeWidgetItem([str(t) for t in texts])
    if offset is not None:
        it.setData(0, OFFSET_ROLE, int(offset))
    if size is not None:
        it.setData(0, SIZE_ROLE, int(size))
    for col, c in (colors or {}).items():
        it.setForeground(col, c)
    return it


class NavTree(QtWidgets.QTreeWidget):
    """Tree whose items may carry (offset, size). Enter/double click jumps,
    F9 jumps and selects the range."""

    def __init__(self, doc: "Document", headers: list[str], parent=None):
        super().__init__(parent)
        self.doc = doc
        self.setHeaderLabels(headers)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.itemDoubleClicked.connect(lambda it, _c: self._jump(it, False))

    def keyPressEvent(self, ev):
        it = self.currentItem()
        if it is not None and ev.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._jump(it, False)
            return
        if it is not None and ev.key() == Qt.Key.Key_F9:
            self._jump(it, True)
            return
        super().keyPressEvent(ev)

    def _jump(self, it, select: bool):
        off = it.data(0, OFFSET_ROLE)
        if off is None:
            return
        size = it.data(0, SIZE_ROLE)
        if select and size:
            self.doc.sel.set(off, off + size)
        self.doc.goto(off)


class InfoDialog(QtWidgets.QDialog):
    """Non-modal tool window with tabs; ``toggle(tab)`` mimics old behaviour."""

    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlag(Qt.WindowType.Tool, True)
        self.tabs = QtWidgets.QTabWidget(self)
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.addWidget(self.tabs)
        self.resize(760, 460)

    def toggle(self, index: int = 0) -> None:
        if self.isVisible() and self.tabs.currentIndex() == index:
            self.hide()
            return
        self.tabs.setCurrentIndex(index)
        if not self.isVisible():
            par = self.parentWidget()
            if par is not None:
                g = par.window().geometry()
                self.move(g.right() - self.width() - 20, g.bottom() - self.height() - 40)
            self.show()
        self.raise_()
        self.activateWindow()
        w = self.tabs.currentWidget()
        if w is not None:
            w.setFocus()
