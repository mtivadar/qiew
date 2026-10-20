"""Fast character-grid renderer.

The old Qiew drew every cell with ``QPainter.drawText`` and switched pens per
character, which costs tens of thousands of Python->Qt calls per page and was
the reason binary mode felt slow.  This module replaces that with:

* a **glyph atlas**: the 256 CP437 glyphs are rasterised once per font/DPI into
  a numpy alpha mask (also guarantees perfect grid alignment, even when a glyph
  comes from a fallback font with a different advance);
* **colour tiles**: for each (foreground, background) palette pair used on
  screen, the 256 glyphs are pre-blended into RGB tiles (cached);
* **one numpy gather** that assembles the whole page image from tiles:
  ``table[idx[:, None, :], rows[None, :, None]]`` produces the final
  ``(rows*h, cols*w, 3)`` pixel buffer in a single vectorised copy.

A full 200x60 page renders in a couple of milliseconds regardless of how many
colour changes it contains.
"""
from __future__ import annotations

import math

import numpy as np
from PySide6 import QtCore, QtGui

from . import theme

# --- CP437 -> Unicode (classic DOS glyphs, 0x00 rendered as blank) -----------
_LOW = (
    " ☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼"
)
CP437 = list(_LOW) + [chr(i) for i in range(0x20, 0x7F)] + ["⌂"] + [
    bytes([i]).decode("cp437") for i in range(0x80, 0x100)
]
assert len(CP437) == 256
CP437_STR = "".join(CP437)


def cp437(b: int) -> str:
    return CP437[b]


class GlyphAtlas:
    """Rasterised CP437 glyph masks for a given font and device pixel ratio."""

    def __init__(self, font: QtGui.QFont, dpr: float = 1.0):
        self.font = QtGui.QFont(font)
        self.dpr = float(dpr) if dpr and dpr > 0 else 1.0
        fm = QtGui.QFontMetricsF(self.font)
        # logical cell size (integers so overlays line up with the image)
        self.cw = max(1, math.ceil(fm.horizontalAdvance("M")))
        self.ch = max(1, math.ceil(fm.height()))
        self.ascent = fm.ascent()
        # physical (device) cell size
        self.pw = max(1, round(self.cw * self.dpr))
        self.ph = max(1, round(self.ch * self.dpr))
        self.masks = self._rasterise()

    def _rasterise(self) -> np.ndarray:
        img = QtGui.QImage(self.pw * 256, self.ph, QtGui.QImage.Format.Format_Grayscale8)
        img.fill(0)
        p = QtGui.QPainter(img)
        p.setRenderHint(QtGui.QPainter.RenderHint.TextAntialiasing, True)
        p.scale(self.pw / self.cw, self.ph / self.ch)
        p.setFont(self.font)
        p.setPen(QtGui.QColor(255, 255, 255))
        for i, ch in enumerate(CP437):
            if ch == " ":
                continue
            x = i * self.cw
            p.save()
            p.setClipRect(QtCore.QRectF(x, 0, self.cw, self.ch))
            p.drawText(QtCore.QPointF(x, self.ascent), ch)
            p.restore()
        p.end()

        bpl = img.bytesPerLine()
        buf = np.frombuffer(img.constBits(), dtype=np.uint8, count=bpl * self.ph)
        arr = buf.reshape(self.ph, bpl)[:, : self.pw * 256]
        # (ph, 256*pw) -> (256, ph, pw)
        return np.ascontiguousarray(arr.reshape(self.ph, 256, self.pw).transpose(1, 0, 2))


class GridRenderer:
    """Turns (chars, fg, bg) uint8 grids into a QImage using cached colour tiles."""

    def __init__(self, atlas: GlyphAtlas, palette: theme.Palette = theme.PALETTE):
        self.atlas = atlas
        self.palette = palette
        self._lut = np.full(65536, -1, dtype=np.int32)  # (fg<<8|bg) -> slot
        self._slots = 0
        self._table = np.zeros((32 * 256, atlas.ph, atlas.pw, 3), dtype=np.uint8)
        self._rows_idx = np.arange(atlas.ph, dtype=np.intp)
        self._colors = np.array(palette.colors() or [(0, 0, 0)], dtype=np.int32)
        self._pal_version = palette.version

    # -- tile management ---------------------------------------------------
    def _ensure_pairs(self, pairs: np.ndarray) -> None:
        missing = np.unique(pairs[self._lut[pairs] < 0])
        if not missing.size:
            return
        if self.palette.version != self._pal_version:
            self._colors = np.array(self.palette.colors(), dtype=np.int32)
            self._pal_version = self.palette.version
        need = self._slots + missing.size
        if need * 256 > self._table.shape[0]:
            cap = self._table.shape[0] // 256
            while cap < need:
                cap *= 2
            grown = np.zeros((cap * 256,) + self._table.shape[1:], dtype=np.uint8)
            grown[: self._slots * 256] = self._table[: self._slots * 256]
            self._table = grown
        m = self.atlas.masks.astype(np.int32)[..., None]  # (256, ph, pw, 1)
        for pair in missing.tolist():
            fg, bg = self._colors[pair >> 8], self._colors[pair & 0xFF]
            tile = bg + ((fg - bg) * m + 127) // 255
            s = self._slots
            self._table[s * 256:(s + 1) * 256] = tile.astype(np.uint8)
            self._lut[pair] = s
            self._slots += 1

    # -- public --------------------------------------------------------------
    def render(self, chars: np.ndarray, fg: np.ndarray, bg: np.ndarray) -> QtGui.QImage:
        rows, cols = chars.shape
        a = self.atlas
        if rows == 0 or cols == 0:
            img = QtGui.QImage(1, 1, QtGui.QImage.Format.Format_RGB888)
            img.fill(QtGui.QColor(*self.palette.colors()[theme.BG]))
            return img
        pairs = (fg.astype(np.int32) << 8) | bg.astype(np.int32)
        self._ensure_pairs(pairs)
        idx = self._lut[pairs] * 256 + chars.astype(np.int32)
        # single gather -> (rows, ph, cols, pw, 3)
        out = self._table[idx[:, None, :], self._rows_idx[None, :, None]]
        width, height = cols * a.pw, rows * a.ph
        out = out.reshape(height, width * 3)
        img = QtGui.QImage(out.data, width, height, width * 3, QtGui.QImage.Format.Format_RGB888)
        img._keepalive = out  # numpy buffer must outlive the QImage
        img.setDevicePixelRatio(a.dpr)
        return img


class TextGrid:
    """A rows x cols cell grid that views fill before rendering."""

    __slots__ = ("rows", "cols", "chars", "fg", "bg")

    def __init__(self, rows: int, cols: int, fg: int = theme.FG, bg: int = theme.BG):
        self.rows, self.cols = rows, cols
        self.chars = np.full((rows, cols), 0x20, dtype=np.uint8)
        self.fg = np.full((rows, cols), fg, dtype=np.uint8)
        self.bg = np.full((rows, cols), bg, dtype=np.uint8)

    def put(self, row: int, col: int, text: str | bytes, fg: int | None = None, bg: int | None = None) -> int:
        """Write text at (row, col); clipped to the grid. Returns the next column."""
        if row < 0 or row >= self.rows or col >= self.cols:
            return col + len(text)
        if isinstance(text, str):
            data = text.encode("cp437", errors="replace")
        else:
            data = bytes(text)
        end = min(self.cols, col + len(data))
        n = end - col
        if n > 0:
            self.chars[row, col:end] = np.frombuffer(data[:n], dtype=np.uint8)
            if fg is not None:
                self.fg[row, col:end] = fg
            if bg is not None:
                self.bg[row, col:end] = bg
        return col + len(data)
