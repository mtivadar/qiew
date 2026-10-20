"""Byte-range selections shared by all views of a document."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from PySide6 import QtGui

from . import theme


class SelType(Enum):
    NORMAL = auto()        # the user selection (max one)
    PERMANENT = auto()     # plugin marks, annotations
    CONDITIONAL = auto()   # visible only while cursor is inside


@dataclass
class Sel:
    a: int
    b: int
    color: QtGui.QColor
    opacity: float = 0.4


class Selections:
    def __init__(self) -> None:
        self.normal: Sel | None = None
        self.permanent: list[Sel] = []
        self.conditional: list[Sel] = []
        self.anchor: int | None = None   # selection in progress (shift held)
        self.version = 0

    # -- user selection --------------------------------------------------------
    def start(self, cursor: int) -> None:
        if self.anchor is None:
            self.anchor = cursor
            self.normal = None

    def stop(self, cursor: int) -> None:
        if self.anchor is not None:
            a, b = self._span(self.anchor, cursor)
            self.anchor = None
            if b > a:
                self.normal = Sel(a, b, theme.SELECTION)
            self.version += 1

    @staticmethod
    def _span(anchor: int, cursor: int) -> tuple[int, int]:
        return (anchor, cursor + 1) if anchor <= cursor else (cursor, anchor + 1)

    def current(self, cursor: int | None = None) -> tuple[int, int] | None:
        """Selection in progress (needs cursor) or the committed one."""
        if self.anchor is not None and cursor is not None:
            return self._span(self.anchor, cursor)
        if self.normal:
            return self.normal.a, self.normal.b
        return None

    def set(self, a: int, b: int, color: QtGui.QColor | None = None, opacity: float = 0.4) -> None:
        if b > a:
            self.normal = Sel(a, b, color or theme.SELECTION, opacity)
            self.version += 1

    def clear(self) -> None:
        self.normal = None
        self.anchor = None
        self.version += 1

    # -- marks ----------------------------------------------------------------
    def add(self, a: int, b: int, color: QtGui.QColor, opacity: float = 0.4,
            kind: SelType = SelType.PERMANENT) -> bool:
        if b <= a:
            return False
        lst = self.permanent if kind is SelType.PERMANENT else self.conditional
        if any(s.a == a and s.b == b for s in lst):
            return False
        lst.append(Sel(a, b, QtGui.QColor(color), opacity))
        self.version += 1
        return True

    def remove(self, a: int, b: int, kind: SelType = SelType.PERMANENT) -> None:
        lst = self.permanent if kind is SelType.PERMANENT else self.conditional
        lst[:] = [s for s in lst if not (s.a == a and s.b == b)]
        self.version += 1

    def visible(self, cursor: int) -> list[Sel]:
        """All selections to draw, bottom to top."""
        out = list(self.permanent)
        out += [s for s in self.conditional if s.a <= cursor < s.b]
        if self.anchor is not None:
            a, b = self._span(self.anchor, cursor)
            out.append(Sel(a, b, theme.SELECTION))
        elif self.normal:
            out.append(self.normal)
        return out
