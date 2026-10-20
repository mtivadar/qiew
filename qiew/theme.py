"""Colors, palette and font selection.

All colors used by the grid renderer live in a single palette (max 256
entries). Views and decorators refer to colors by palette index so the
renderer can work on compact ``uint8`` arrays.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6 import QtGui

RGB = tuple[int, int, int]


class Palette:
    """Maps RGB tuples to small integer indices (stable, append-only)."""

    def __init__(self) -> None:
        self._colors: list[RGB] = []
        self._index: dict[RGB, int] = {}
        self.version = 0

    def index(self, color) -> int:
        rgb = to_rgb(color)
        idx = self._index.get(rgb)
        if idx is None:
            if len(self._colors) >= 256:
                raise ValueError("palette full")
            idx = len(self._colors)
            self._colors.append(rgb)
            self._index[rgb] = idx
            self.version += 1
        return idx

    def __len__(self) -> int:
        return len(self._colors)

    def colors(self) -> list[RGB]:
        return list(self._colors)


def to_rgb(color) -> RGB:
    if isinstance(color, tuple):
        return tuple(int(c) for c in color[:3])  # type: ignore[return-value]
    if isinstance(color, str):
        color = QtGui.QColor(color)
    if isinstance(color, QtGui.QColor):
        return (color.red(), color.green(), color.blue())
    raise TypeError(f"unsupported color {color!r}")


PALETTE = Palette()

# --- core colors (index order matters only for readability) ----------------
BG = PALETTE.index((0, 0, 128))            # classic navy background
FG = PALETTE.index((192, 192, 192))        # normal text
RED = PALETTE.index((255, 0, 0))           # ascii strings
YELLOW = PALETTE.index((255, 255, 0))      # MZ/PE, wide strings
WHITE = PALETTE.index((255, 255, 255))
GRAY = PALETTE.index((128, 128, 128))
DARK_RED = PALETTE.index((128, 0, 0))      # MZ background
GREEN = PALETTE.index((0, 200, 0))         # IAT
BRIGHT_GREEN = PALETTE.index((0, 255, 0))
EDITED = PALETTE.index((218, 94, 242))     # modified bytes
ORANGE = PALETTE.index((255, 80, 0))       # branch mnemonics
CYAN = PALETTE.index((82, 192, 192))       # referenced strings
NUMBER = PALETTE.index((0, 128, 0))        # immediates

# --- overlay colors (drawn with QPainter, not palette based) ---------------
SELECTION = QtGui.QColor(125, 255, 0)
SEARCH_HIT = QtGui.QColor(125, 0, 100)
CURSOR = QtGui.QColor(255, 255, 0)
CURSOR_EDIT = QtGui.QColor(255, 102, 179)
EP_MARK = QtGui.QColor(51, 153, 255)
BANNER_TEXT = QtGui.QColor(192, 192, 192)
BANNER_HILITE = QtGui.QColor(255, 255, 0)
SEPARATOR = QtGui.QColor(0, 255, 0)


# --- fonts ------------------------------------------------------------------
PREFERRED_FAMILIES = ["Terminus (TTF)", "Terminus", "xos4 Terminus", "Terminus TTF"]
_FALLBACKS = {
    "darwin": ["Menlo", "Monaco", "SF Mono"],
    "win32": ["Consolas", "Lucida Console", "Courier New"],
}
_fonts_loaded = False


def _load_bundled_fonts() -> None:
    """Register any .ttf/.otf dropped in qiew/resources/fonts or ~/.qiew/fonts."""
    global _fonts_loaded
    if _fonts_loaded:
        return
    _fonts_loaded = True
    dirs = [Path(__file__).parent / "resources" / "fonts", Path.home() / ".qiew" / "fonts"]
    if getattr(sys, "frozen", False):  # PyInstaller
        dirs.append(Path(getattr(sys, "_MEIPASS", ".")) / "qiew" / "resources" / "fonts")
    for d in dirs:
        if d.is_dir():
            for f in d.iterdir():
                if f.suffix.lower() in (".ttf", ".otf"):
                    QtGui.QFontDatabase.addApplicationFont(str(f))


def pick_font(family: str | None = None, size: int | None = None) -> QtGui.QFont:
    """Return a monospaced font. Prefers Terminus, falls back per platform."""
    _load_bundled_fonts()
    size = size or int(os.environ.get("QIEW_FONT_SIZE", "11"))
    families = set(QtGui.QFontDatabase.families())
    candidates = ([family] if family else []) + PREFERRED_FAMILIES
    plat = "darwin" if sys.platform == "darwin" else ("win32" if sys.platform.startswith("win") else "linux")
    candidates += _FALLBACKS.get(plat, ["DejaVu Sans Mono", "Liberation Mono", "Monospace"])

    font = None
    for fam in candidates:
        if fam in families:
            font = QtGui.QFont(fam, size)
            break
    if font is None:
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(size)

    font.setStyleHint(QtGui.QFont.StyleHint.TypeWriter)
    font.setFixedPitch(True)
    font.setKerning(False)
    return font
