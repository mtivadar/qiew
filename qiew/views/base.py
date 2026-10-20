"""View base classes.

A view turns the document into a ``TextGrid`` (rendered by the numpy grid
renderer and cached until something relevant changes) and paints cheap
overlays (cursor, selections, separators) with QPainter on top.  Cursor
movement therefore never re-renders the page.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6 import QtCore, QtGui
from PySide6.QtCore import Qt

from .. import theme
from ..render import GridRenderer, TextGrid

if TYPE_CHECKING:  # pragma: no cover
    from ..document import Document

Key = Qt.Key
MOVE_KEYS = {Key.Key_Left, Key.Key_Right, Key.Key_Up, Key.Key_Down, Key.Key_Home,
             Key.Key_End, Key.Key_PageUp, Key.Key_PageDown}


def ctrl(mods) -> bool:
    # Qt maps Cmd to ControlModifier on macOS: Ctrl+arrows == Cmd+arrows there.
    return bool(mods & Qt.KeyboardModifier.ControlModifier)


class View:
    name = "view"
    editable = False

    def __init__(self, doc: "Document") -> None:
        self.doc = doc
        self.dm = doc.dm
        self.sel = doc.sel
        self.offset = 0          # first byte shown
        self.cursor = 0          # absolute byte offset under cursor
        self.rows = 1            # available grid rows
        self.cols = 1            # available grid columns
        self.edit = False
        self._img: QtGui.QImage | None = None
        self._img_key = None
        self._hl_cache_key = None
        self._hl_cache: list[tuple[int, int]] = []

    # ---------------------------------------------------------------- geometry
    def resize(self, rows: int, cols: int) -> None:
        self.rows, self.cols = max(1, rows), max(1, cols)
        self.clamp()

    def clamp(self) -> None:
        pass

    @property
    def x_margin(self) -> int:
        """Pixels reserved left of the grid (disasm branch arrows)."""
        return 0

    # ---------------------------------------------------------------- content
    def build_grid(self) -> TextGrid:  # pragma: no cover - abstract
        raise NotImplementedError

    def cache_key(self):
        return (self.offset, self.rows, self.cols, self.dm.version, self.doc.hl.version)

    def image(self, renderer: GridRenderer) -> QtGui.QImage:
        key = (self.cache_key(), id(renderer))
        if key != self._img_key or self._img is None:
            grid = self.build_grid()
            self._img = renderer.render(grid.chars, grid.fg, grid.bg)
            self._img_key = key
        return self._img

    def invalidate(self) -> None:
        self._img_key = None

    # ---------------------------------------------------------------- info
    def header(self) -> str:
        return ""

    def row_offsets(self) -> list[int]:
        return []

    def page_end(self) -> int:
        return self.offset

    def cursor_offset(self) -> int:
        return self.cursor

    def range_rects(self, a: int, b: int) -> list[tuple[float, float, float]]:
        """(x, y, w) cell rectangles (height 1) covering bytes [a, b)."""
        return []

    # ---------------------------------------------------------------- overlays
    def paint_overlays(self, p: QtGui.QPainter, cw: int, ch: int) -> None:
        mx = self.x_margin
        cur = self.cursor_offset()
        # highlight-all of the current selection
        for a, b in self._highlight_all(cur):
            self._fill(p, self.range_rects(a, b), theme.SELECTION, 0.25, cw, ch, mx)
        for s in self.sel.visible(cur):
            self._fill(p, self.range_rects(s.a, s.b), s.color, s.opacity, cw, ch, mx)
        self.paint_extra(p, cw, ch)
        self.paint_cursor(p, cw, ch)

    def paint_extra(self, p, cw, ch) -> None:
        pass

    def paint_cursor(self, p, cw, ch) -> None:
        pass

    @staticmethod
    def _fill(p, rects, color, opacity, cw, ch, mx=0) -> None:
        if not rects:
            return
        p.setOpacity(opacity)
        for x, y, w in rects:
            p.fillRect(QtCore.QRectF(mx + x * cw, y * ch, w * cw, ch), color)
        p.setOpacity(1.0)

    def _highlight_all(self, cur: int) -> list[tuple[int, int]]:
        """Other occurrences of the selected bytes inside the current page."""
        rng = self.sel.current(cur)
        if not rng or rng[1] - rng[0] > 4096:
            return []
        key = (rng, self.offset, self.page_end(), self.dm.version)
        if key == self._hl_cache_key:
            return self._hl_cache
        a, b = rng
        needle = self.dm.read(a, b)
        start, end = self.offset, self.page_end()
        out = []
        if needle:
            i = self.dm.find(needle, start, end)
            while i != -1 and len(out) < 512:
                if i != a:
                    out.append((i, i + len(needle)))
                i = self.dm.find(needle, i + len(needle), end)
        self._hl_cache_key, self._hl_cache = key, out
        return out

    # ---------------------------------------------------------------- navigation
    def goto(self, off: int) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def key_press(self, ev: QtGui.QKeyEvent) -> bool:
        return False

    def click(self, cx: float, cy: float) -> None:
        pass

    def wheel(self, rows: int) -> None:
        pass

    def set_edit(self, on: bool) -> None:
        self.edit = on and self.editable and self.dm.writable

    # selection helper: shift + movement extends the selection
    def _selection_key(self, ev: QtGui.QKeyEvent) -> None:
        shift = bool(ev.modifiers() & Qt.KeyboardModifier.ShiftModifier)
        if ev.key() in MOVE_KEYS:
            if shift:
                self.sel.start(self.cursor_offset())
            elif self.sel.anchor is not None:
                self.sel.stop(self.cursor_offset())

    def key_release(self, ev: QtGui.QKeyEvent) -> bool:
        if ev.key() == Key.Key_Shift and self.sel.anchor is not None:
            self.sel.stop(self.cursor_offset())
            return True
        return False
