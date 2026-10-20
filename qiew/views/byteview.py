"""Common navigation for views where every row shows ``bpr`` consecutive bytes."""
from __future__ import annotations

from PySide6 import QtCore, QtGui
from PySide6.QtCore import Qt

from .. import theme
from .base import Key, View, ctrl


class ByteView(View):
    editable = True

    @property
    def bpr(self) -> int:
        """Bytes per row."""
        raise NotImplementedError

    @property
    def page_len(self) -> int:
        return self.bpr * self.rows

    def page_end(self) -> int:
        return min(len(self.dm), self.offset + self.page_len)

    def row_offsets(self) -> list[int]:
        return [self.offset + r * self.bpr for r in range(self.rows)]

    # -------------------------------------------------------------- limits
    def max_offset(self) -> int:
        """Last page start that keeps the current row alignment."""
        size = len(self.dm)
        if size <= self.page_len:
            return 0
        bpr = self.bpr
        align = self.offset % bpr
        last_row = align + ((size - 1 - align) // bpr) * bpr if size - 1 >= align else 0
        return max(0, last_row - (self.rows - 1) * bpr)

    def clamp(self) -> None:
        size = len(self.dm)
        self.cursor = max(0, min(self.cursor, size - 1)) if size else 0
        self.offset = max(0, min(self.offset, self.max_offset()))
        self.ensure_visible()

    def ensure_visible(self) -> None:
        bpr = self.bpr
        if self.cursor < self.offset:
            rows_up = -(-(self.offset - self.cursor) // bpr)
            self.offset = max(0, self.offset - rows_up * bpr)
        elif self.cursor >= self.offset + self.page_len:
            rows_dn = (self.cursor - (self.offset + self.page_len)) // bpr + 1
            self.offset += rows_dn * bpr

    # -------------------------------------------------------------- moves
    def goto(self, off: int) -> None:
        size = len(self.dm)
        if not size:
            return
        off = max(0, min(off, size - 1))
        self.cursor = off
        if not (self.offset <= off < self.offset + self.page_len):
            self.offset = self.page_start_for(off)
            self.offset = max(0, min(self.offset, max(self.max_offset(), 0)))
            self.ensure_visible()

    def page_start_for(self, off: int) -> int:
        return off

    def move(self, key, mods) -> None:
        size = len(self.dm)
        if not size:
            return
        bpr = self.bpr
        c = self.cursor
        if ctrl(mods):
            if key == Key.Key_Right and self.offset + 1 < size:
                self.offset += 1
                self.cursor = min(size - 1, c + 1)
            elif key == Key.Key_Left and self.offset > 0:
                self.offset -= 1
                self.cursor = c - 1
            elif key == Key.Key_Down and self.offset + bpr <= self.max_offset():
                self.offset += bpr
                self.cursor = min(size - 1, c + bpr)
            elif key == Key.Key_Up and self.offset > 0:
                d = min(bpr, self.offset)
                self.offset -= d
                self.cursor = c - d
            elif key == Key.Key_Home:
                self.offset, self.cursor = 0, 0
            elif key == Key.Key_End:
                self.cursor = size - 1
                self.offset = self.max_offset()
            self.ensure_visible()
            return

        if key == Key.Key_Left:
            self.cursor = max(0, c - 1)
        elif key == Key.Key_Right:
            self.cursor = min(size - 1, c + 1)
        elif key == Key.Key_Down:
            self.cursor = c + bpr if c + bpr < size else size - 1
        elif key == Key.Key_Up:
            self.cursor = c - bpr if c - bpr >= 0 else c
        elif key == Key.Key_PageDown:
            step = min(self.page_len, max(0, self.max_offset() - self.offset))
            if step == 0:
                self.cursor = size - 1
            else:
                self.offset += step
                self.cursor = min(size - 1, c + step)
        elif key == Key.Key_PageUp:
            step = min(self.page_len, self.offset)
            if step == 0:
                self.cursor = c % bpr if self.offset == 0 else 0
            else:
                self.offset -= step
                self.cursor = c - step
        elif key == Key.Key_Home:
            # classic qiew: top-left of the page
            self.cursor = self.offset
        elif key == Key.Key_End:
            self.cursor = min(size - 1, self.offset + self.page_len - 1)
        self.ensure_visible()

    def key_press(self, ev: QtGui.QKeyEvent) -> bool:
        key, mods = ev.key(), ev.modifiers()
        if key in (Key.Key_Left, Key.Key_Right, Key.Key_Up, Key.Key_Down, Key.Key_Home,
                   Key.Key_End, Key.Key_PageUp, Key.Key_PageDown):
            self._selection_key(ev)
            self.on_move()
            self.move(key, mods)
            return True
        if self.edit and self.edit_key(ev):
            return True
        return False

    def on_move(self) -> None:
        pass

    def edit_key(self, ev: QtGui.QKeyEvent) -> bool:
        return False

    def wheel(self, rows: int) -> None:
        bpr = self.bpr
        if rows > 0:
            d = min(rows * bpr, self.offset)
            self.offset -= d
            self.cursor -= d
        else:
            d = min(-rows * bpr, max(0, self.max_offset() - self.offset))
            self.offset += d
            self.cursor = min(len(self.dm) - 1, self.cursor + d)
        self.cursor = max(0, self.cursor)

    def _draw_cursor_rect(self, p: QtGui.QPainter, x: float, y: float, w: float, cw: int, ch: int,
                          opacity: float = 0.8) -> None:
        p.setOpacity(opacity)
        p.fillRect(QtCore.QRectF(self.x_margin + x * cw, y * ch, w * cw, ch),
                   theme.CURSOR_EDIT if self.edit else theme.CURSOR)
        p.setOpacity(1.0)


def is_plain_text(ev: QtGui.QKeyEvent) -> bool:
    mods = ev.modifiers() & ~(Qt.KeyboardModifier.ShiftModifier | Qt.KeyboardModifier.KeypadModifier)
    t = ev.text()
    return bool(t) and t.isprintable() and mods == Qt.KeyboardModifier.NoModifier
