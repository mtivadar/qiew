"""A document = data + detected format + highlight rules + selections."""
from __future__ import annotations

from typing import Callable

from .datamodel import DataModel
from .formats import choose_format
from .formats.base import FileFormat
from .highlight import Highlighter
from .selection import Selections


class Document:
    def __init__(self, dm: DataModel, fmt: FileFormat | None = None) -> None:
        self.dm = dm
        self.sel = Selections()
        self.hl = Highlighter()
        self.fmt = fmt or choose_format(dm)
        self.fmt.doc = self
        self.fmt.setup(self)
        self.hl.version += 1
        # wired by the UI
        self._goto: Callable[[int], None] | None = None
        self._cursor: Callable[[], int] | None = None
        self.open_buffer: Callable[[bytes, str], None] | None = None

    def goto(self, offset: int) -> None:
        if self._goto:
            self._goto(int(offset))

    def cursor(self) -> int:
        return self._cursor() if self._cursor else 0
