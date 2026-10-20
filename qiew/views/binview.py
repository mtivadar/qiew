"""Binary (text) view: one CP437 glyph per byte, filling the whole window."""
from __future__ import annotations

import numpy as np
from PySide6 import QtGui

from .. import theme
from ..render import TextGrid
from .byteview import ByteView, is_plain_text


class BinView(ByteView):
    name = "Binary"

    @property
    def bpr(self) -> int:
        return self.cols

    def header(self) -> str:
        return "Binary"

    def build_grid(self) -> TextGrid:
        rows, cols = self.rows, self.cols
        n = rows * cols
        colors = self.doc.hl.colorize(self.dm, self.offset, n)
        L = len(colors.fg)
        chars = np.zeros(n, dtype=np.uint8)
        fg = np.full(n, theme.FG, dtype=np.uint8)
        bg = np.full(n, theme.BG, dtype=np.uint8)
        chars[:L] = colors.display
        fg[:L] = colors.fg
        bg[:L] = colors.bg
        g = TextGrid.__new__(TextGrid)
        g.rows, g.cols = rows, cols
        g.chars, g.fg, g.bg = chars.reshape(rows, cols), fg.reshape(rows, cols), bg.reshape(rows, cols)
        return g

    def range_rects(self, a, b):
        cols = self.cols
        a = max(a, self.offset) - self.offset
        b = min(b, self.page_end()) - self.offset
        out = []
        while a < b:
            row, col = divmod(a, cols)
            w = min(cols - col, b - a)
            out.append((col, row, w))
            a += w
        return out

    def paint_cursor(self, p, cw, ch):
        d = self.cursor - self.offset
        if 0 <= d < self.page_len:
            row, col = divmod(d, self.cols)
            self._draw_cursor_rect(p, col, row, 1, cw, ch)

    def click(self, cx, cy):
        off = self.offset + int(cy) * self.cols + int(cx)
        if 0 <= off < len(self.dm):
            self.cursor = off

    def edit_key(self, ev: QtGui.QKeyEvent) -> bool:
        if not is_plain_text(ev):
            return False
        data = ev.text().encode("cp437", errors="replace")[:1]
        if self.dm.write(self.cursor, data):
            self.cursor = min(len(self.dm) - 1, self.cursor + 1)
            self.ensure_visible()
        return True
