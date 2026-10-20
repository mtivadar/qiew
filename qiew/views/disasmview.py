"""Disassembly view (capstone) with token cursor, branch arrows and xrefs."""
from __future__ import annotations

from PySide6 import QtCore, QtGui
from PySide6.QtCore import Qt

from .. import theme
from ..disasm import MAX_HEX_BYTES, MNEMONIC_COLUMN, OPERAND_COLUMN, Disassembler, Line
from ..render import TextGrid
from .base import Key, View, ctrl

TOKEN_COLORS = {"reg": theme.WHITE, "num": theme.NUMBER}
ARROW_CELLS = 5


class DisasmView(View):
    name = "Disasm"

    def __init__(self, doc):
        super().__init__(doc)
        self.cw = self.ch = 1
        self.crow = 0
        self.ccol = 0
        self.history: list[int] = []
        self._trail: list[int] = []     # offsets we scrolled down from (exact way back up)
        self._dis: Disassembler | None = None
        self._lines: list[Line] = []
        self._lines_key = None

    # ------------------------------------------------------------- engine
    @property
    def dis(self) -> Disassembler:
        if self._dis is None:
            self._dis = Disassembler(self.doc.fmt.disasm_arch(), self.doc.fmt)
        return self._dis

    def reset_engine(self) -> None:
        self._dis = None
        self._lines_key = None
        self.invalidate()

    @property
    def lines(self) -> list[Line]:
        key = (self.offset, self.rows, self.dm.version, id(self._dis))
        if key != self._lines_key:
            self._lines = self.dis.decode(self.dm, self.offset, self.rows) if len(self.dm) else []
            self._lines_key = key
            self.crow = min(self.crow, max(0, len(self._lines) - 1))
        return self._lines

    @property
    def x_margin(self) -> int:
        return ARROW_CELLS * self.cw

    def cache_key(self):
        return super().cache_key() + (id(self._dis),)

    # ------------------------------------------------------------- info
    def header(self) -> str:
        return "Disasm listing"

    def row_offsets(self):
        return [ln.offset for ln in self.lines]

    def page_end(self):
        ls = self.lines
        return ls[-1].end if ls else self.offset

    def cursor_offset(self) -> int:
        ls = self.lines
        if not ls:
            return self.offset
        ln = ls[min(self.crow, len(ls) - 1)]
        if self.ccol < MNEMONIC_COLUMN:
            return ln.offset + min(self.ccol // 3, ln.size - 1)
        return ln.offset

    def _sync(self) -> None:
        self.cursor = self.cursor_offset()

    def clamp(self):
        size = len(self.dm)
        self.offset = max(0, min(self.offset, max(0, size - 1)))
        self._sync()

    # ------------------------------------------------------------- grid
    def build_grid(self) -> TextGrid:
        g = TextGrid(self.rows, self.cols)
        for row, ln in enumerate(self.lines):
            g.put(row, 0, ln.hex_text(), theme.FG)
            g.put(row, MNEMONIC_COLUMN, ln.mnemonic, theme.ORANGE if ln.is_branch else theme.FG)
            if ln.symbol:
                c = g.put(row, OPERAND_COLUMN, "[", theme.FG)
                c = g.put(row, c, ln.symbol, theme.YELLOW)
                end = g.put(row, c, "]", theme.FG)
            else:
                end = g.put(row, OPERAND_COLUMN, ln.op_str, theme.FG)
                for t in ln.tokens:
                    color = TOKEN_COLORS.get(t.kind)
                    if color is not None and t.col >= OPERAND_COLUMN:
                        g.put(row, t.col, t.text, color)
            if ln.refstr:
                g.put(row, max(end + 4, OPERAND_COLUMN + 30), f'; "{ln.refstr}"', theme.CYAN)
        return g

    def range_rects(self, a, b):
        out = []
        for row, ln in enumerate(self.lines):
            s, e = max(a, ln.offset), min(b, ln.end, ln.offset + MAX_HEX_BYTES)
            if s < e:
                out.append(((s - ln.offset) * 3, row, (e - s) * 3 - 1))
        return out

    # ------------------------------------------------------------- overlays
    def paint_cursor(self, p, cw, ch):
        ls = self.lines
        if not ls:
            return
        ln = ls[min(self.crow, len(ls) - 1)]
        tok = ln.token_at(self.ccol)
        w = len(tok.text) if tok else 1
        p.setOpacity(0.5)
        p.fillRect(QtCore.QRectF(self.x_margin + self.ccol * cw, self.crow * ch, w * cw, ch), theme.CURSOR)
        p.setOpacity(1.0)

    def paint_extra(self, p, cw, ch):
        ls = self.lines
        if not ls:
            return
        mx = self.x_margin
        cur = ls[min(self.crow, len(ls) - 1)]
        tok = cur.token_at(self.ccol)
        # same token elsewhere on the page
        if tok:
            p.setOpacity(0.4)
            for row, ln in enumerate(ls):
                for t in ln.tokens:
                    if t.text == tok.text and not (row == self.crow and t.col == self.ccol):
                        p.fillRect(QtCore.QRectF(mx + t.col * cw, row * ch, len(t.text) * cw, ch),
                                   theme.SELECTION)
            p.setOpacity(1.0)
        self._paint_branch(p, cw, ch, cur)

    def _paint_branch(self, p, cw, ch, ln: Line):
        if not ln.is_branch or ln.target is None:
            return
        ls = self.lines
        half = ch / 2
        y0 = self.crow * ch + half
        xr, xl = self.x_margin - 4, self.x_margin * 0.4
        target_fa = self.doc.fmt.fa(ln.target)
        green = QtGui.QColor(0, 192, 0)
        p.setBrush(QtGui.QColor(0, 128, 0))
        row = None
        if target_fa is not None:
            for i, other in enumerate(ls):
                if other.offset <= target_fa < other.end:
                    row = i
                    break
        if row is not None:
            y1 = row * ch + half
            p.setPen(QtGui.QPen(green, 1))
            p.drawPolyline([QtCore.QPointF(xr, y0), QtCore.QPointF(xl, y0),
                            QtCore.QPointF(xl, y1), QtCore.QPointF(xr - 8, y1)])
            p.drawPolygon([QtCore.QPointF(xr - 8, y1 - 4), QtCore.QPointF(xr - 8, y1 + 4),
                           QtCore.QPointF(xr, y1)])
        else:
            down = target_fa is not None and target_fa >= self.offset
            y1 = (len(ls) - 1) * ch if down else ch
            p.setPen(QtGui.QPen(green, 1, Qt.PenStyle.DotLine))
            p.drawPolyline([QtCore.QPointF(xr, y0), QtCore.QPointF(xl, y0), QtCore.QPointF(xl, y1)])
            tip = y1 + half if down else y1 - half
            p.setPen(QtGui.QPen(green, 1))
            p.drawPolygon([QtCore.QPointF(xl - 5, y1), QtCore.QPointF(xl + 5, y1), QtCore.QPointF(xl, tip)])

    # ------------------------------------------------------------- navigation
    def goto(self, off: int) -> None:
        size = len(self.dm)
        if not size:
            return
        off = max(0, min(off, size - 1))
        for row, ln in enumerate(self.lines):
            if ln.offset <= off < ln.end and row < self.rows - 1:
                self.crow = row
                d = off - ln.offset
                self.ccol = d * 3 if d < MAX_HEX_BYTES else 0
                self._sync()
                return
        self.offset, self.crow, self.ccol = off, 0, 0
        self._trail.clear()
        self._sync()

    def _scroll(self, n: int) -> bool:
        """Scroll by n lines (positive = down). Returns True if moved."""
        moved = False
        for _ in range(abs(n)):
            ls = self.lines
            if n > 0:
                if len(ls) < 2 or ls[-1].end >= len(self.dm):
                    break
                self._trail.append(self.offset)
                self.offset = ls[1].offset
            else:
                if self.offset == 0:
                    break
                if self._trail and self._trail[-1] < self.offset:
                    self.offset = self._trail.pop()
                else:
                    self._trail.clear()
                    self.offset = self.dis.prev_offset(self.dm, self.offset)
            moved = True
        return moved

    def move(self, key, mods) -> None:
        ls = self.lines
        if not ls:
            return
        if ctrl(mods):
            if key == Key.Key_Right and self.offset + 1 < len(self.dm):
                self.offset += 1
                self._trail.clear()
            elif key == Key.Key_Left and self.offset > 0:
                self.offset -= 1
                self._trail.clear()
            elif key == Key.Key_Down:
                self._scroll(1)
            elif key == Key.Key_Up:
                self._scroll(-1)
            elif key == Key.Key_Home:
                self.goto(0)
            elif key == Key.Key_End:
                self.offset = max(0, len(self.dm) - 1)
                self._scroll(-(self.rows - 1))
                self.crow = len(self.lines) - 1
            self._fix_col()
            return

        ln = ls[self.crow]
        if key == Key.Key_Down:
            if self.crow < min(len(ls), self.rows) - 1:
                self.crow += 1
            else:
                self._scroll(1)
            self._fix_col(self.ccol)
        elif key == Key.Key_Up:
            if self.crow > 0:
                self.crow -= 1
            else:
                self._scroll(-1)
            self._fix_col(self.ccol)
        elif key == Key.Key_Right:
            stops = ln.stops()
            nxt = [s for s in stops if s > self.ccol]
            if nxt:
                self.ccol = nxt[0]
            else:
                self.move(Key.Key_Down, Qt.KeyboardModifier.NoModifier)
                self.ccol = 0
        elif key == Key.Key_Left:
            stops = ln.stops()
            prv = [s for s in stops if s < self.ccol]
            if prv:
                self.ccol = prv[-1]
            else:
                self.move(Key.Key_Up, Qt.KeyboardModifier.NoModifier)
                self.ccol = self.lines[self.crow].stops()[-1]
        elif key == Key.Key_PageDown:
            self._scroll(self.rows)
            self._fix_col(self.ccol)
        elif key == Key.Key_PageUp:
            self._scroll(-self.rows)
            self._fix_col(self.ccol)
        elif key == Key.Key_Home:
            self.crow, self.ccol = 0, 0
        elif key == Key.Key_End:
            self.ccol = ln.stops()[-1]
        self._sync()

    def _fix_col(self, col: int | None = None) -> None:
        ls = self.lines
        if not ls:
            self.crow = self.ccol = 0
            return
        self.crow = max(0, min(self.crow, len(ls) - 1))
        self.ccol = ls[self.crow].nearest(self.ccol if col is None else col)
        self._sync()

    def follow_branch(self) -> None:
        ls = self.lines
        if not ls:
            return
        ln = ls[self.crow]
        if ln.is_branch and ln.target is not None:
            fa = self.doc.fmt.fa(ln.target)
            if fa is not None and 0 <= fa < len(self.dm):
                self.history.append(ln.offset)
                self.goto(fa)

    def back(self) -> None:
        if self.history:
            self.goto(self.history.pop())

    def key_press(self, ev):
        key = ev.key()
        if key in (Key.Key_Left, Key.Key_Right, Key.Key_Up, Key.Key_Down, Key.Key_Home,
                   Key.Key_End, Key.Key_PageUp, Key.Key_PageDown):
            self._selection_key(ev)
            self.move(key, ev.modifiers())
            return True
        if key in (Key.Key_Return, Key.Key_Enter):
            self.follow_branch()
            return True
        if key == Key.Key_Backspace or (key == Key.Key_Escape and self.history and not self.sel.normal):
            self.back()
            return True
        return False

    def click(self, cx, cy):
        row = int(cy)
        if 0 <= row < len(self.lines) and cx >= 0:
            self.crow = row
            self.ccol = self.lines[row].nearest(int(cx))
            self._sync()

    def wheel(self, rows):
        self._scroll(-rows)
        self._fix_col(self.ccol)
