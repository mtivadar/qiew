"""Hex view: ``xx xx xx ...   text`` with nibble editing."""
from __future__ import annotations

import numpy as np
from PySide6 import QtCore, QtGui
from PySide6.QtCore import Qt

from .. import theme
from ..render import TextGrid
from .byteview import ByteView, Key

HEX_DIGITS = np.frombuffer(b"0123456789abcdef", dtype=np.uint8)
HEX_TABLE = np.stack([HEX_DIGITS[np.arange(256) >> 4], HEX_DIGITS[np.arange(256) & 15]], axis=1)
HEX_KEYS = {getattr(Key, f"Key_{c}"): int(c, 16) for c in "0123456789ABCDEF"}
GAP = 5


class HexView(ByteView):
    name = "Hex"
    COLUMN_CHOICES = [1, 4, 8, 16, 32, 36, 40]

    def __init__(self, doc):
        self._ncols = 16
        self._want = 16          # user preference; shrinks only if it doesn't fit
        self.highpart = True
        super().__init__(doc)

    @property
    def bpr(self) -> int:
        return self._ncols

    @property
    def text_x(self) -> int:
        return 3 * self._ncols + GAP

    def fits(self, n: int) -> bool:
        return 4 * n + GAP <= self.cols

    def resize(self, rows, cols):
        self.rows, self.cols = max(1, rows), max(1, cols)
        fitting = [n for n in self.COLUMN_CHOICES if n <= self._want and self.fits(n)] or [1]
        self._ncols = fitting[-1]
        self.clamp()

    def cycle_columns(self) -> None:
        choices = self.COLUMN_CHOICES
        i = choices.index(self._ncols) if self._ncols in choices else 0
        for k in range(1, len(choices) + 1):
            n = choices[(i + k) % len(choices)]
            if self.fits(n):
                self._ncols = self._want = n
                break
        self.offset -= self.offset % self._ncols
        self.clamp()

    def page_start_for(self, off: int) -> int:
        return off - off % self.bpr

    def cache_key(self):
        return super().cache_key() + (self._ncols,)

    def header(self) -> str:
        return " ".join(f"{i:02x}" for i in range(self._ncols)) + " " * (GAP + 1) + "Text"

    # ----------------------------------------------------------------- grid
    def build_grid(self) -> TextGrid:
        R, C = self.rows, self._ncols
        n = R * C
        colors = self.doc.hl.colorize(self.dm, self.offset, n)
        L = len(colors.fg)
        raw = np.zeros(n, dtype=np.uint8)
        raw[:L] = np.frombuffer(self.dm.read(self.offset, self.offset + L), dtype=np.uint8)
        fg = np.full(n, theme.FG, dtype=np.uint8)
        bg = np.full(n, theme.BG, dtype=np.uint8)
        fg[:L], bg[:L] = colors.fg, colors.bg
        valid = np.arange(n) < L

        width = 4 * C + GAP
        g = TextGrid(R, width)
        # hex part: (R, C, 3) blocks of "xx "
        hx = np.full((n, 3), 0x20, dtype=np.uint8)
        hx[valid, :2] = HEX_TABLE[raw[valid]]
        hfg = np.repeat(fg[:, None], 3, axis=1)
        hbg = np.full((n, 3), theme.BG, dtype=np.uint8)
        hbg[:, :2] = bg[:, None]          # no background on the separating space
        g.chars[:, :3 * C] = hx.reshape(R, 3 * C)
        g.fg[:, :3 * C] = hfg.reshape(R, 3 * C)
        g.bg[:, :3 * C] = hbg.reshape(R, 3 * C)
        # text part
        tx = self.text_x
        txt = np.where(valid, raw, 0x20).astype(np.uint8)
        g.chars[:, tx:tx + C] = txt.reshape(R, C)
        g.fg[:, tx:tx + C] = fg.reshape(R, C)
        g.bg[:, tx:tx + C] = bg.reshape(R, C)
        return g

    def range_rects(self, a, b):
        C = self._ncols
        a = max(a, self.offset) - self.offset
        b = min(b, self.page_end()) - self.offset
        out = []
        while a < b:
            row, col = divmod(a, C)
            w = min(C - col, b - a)
            out.append((3 * col, row, 3 * w - 1))
            out.append((self.text_x + col, row, w))
            a += w
        return out

    def paint_extra(self, p, cw, ch):
        p.setPen(QtGui.QPen(theme.SEPARATOR, 1))
        h = self.rows * ch
        for i in range(1, self._ncols // 4):
            x = (12 * i) * cw - cw / 2
            p.drawLine(QtCore.QPointF(x, 0), QtCore.QPointF(x, h))

    def paint_cursor(self, p, cw, ch):
        d = self.cursor - self.offset
        if not (0 <= d < self.page_len):
            return
        row, col = divmod(d, self._ncols)
        self._draw_cursor_rect(p, self.text_x + col, row, 1, cw, ch, 0.5 if self.edit else 0.8)
        if not self.edit:
            self._draw_cursor_rect(p, 3 * col, row, 2, cw, ch)
        else:
            self._draw_cursor_rect(p, 3 * col + (0 if self.highpart else 1), row, 1, cw, ch)

    def click(self, cx, cy):
        row, x = int(cy), int(cx)
        C = self._ncols
        if x < 3 * C:
            col = min(C - 1, x // 3)
        elif self.text_x <= x < self.text_x + C:
            col = x - self.text_x
        else:
            return
        off = self.offset + row * C + col
        if 0 <= off < len(self.dm):
            self.cursor = off
            self.highpart = True

    def on_move(self):
        self.highpart = True

    def set_edit(self, on):
        super().set_edit(on)
        self.highpart = True

    # ----------------------------------------------------------------- edit
    def edit_key(self, ev: QtGui.QKeyEvent) -> bool:
        z = HEX_KEYS.get(ev.key())
        if z is None:
            return False
        mods = ev.modifiers()
        sel = self.sel.current()
        block = bool(mods & Qt.KeyboardModifier.AltModifier) and sel is not None

        def nib(b: int) -> int:
            return ((z << 4) | (b & 0x0F)) if self.highpart else ((b & 0xF0) | z)

        if block:
            u, v = sel
            data = bytes(nib(b) for b in self.dm.read(u, v))
            self.dm.write(u, data)
        else:
            b = self.dm.byte(self.cursor)
            if b is None:
                return True
            self.dm.set_byte(self.cursor, nib(b))
            if not self.highpart:
                self.cursor = min(len(self.dm) - 1, self.cursor + 1)
                self.ensure_visible()
        self.highpart = not self.highpart
        return True
