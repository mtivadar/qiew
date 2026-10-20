"""Byte highlighting rules ("text decorators").

Each rule colours a page of bytes using regexes + numpy slice assignments,
replacing the old per-byte ``penMap``/``brushMap`` dictionaries.  Rules are
evaluated over the page plus a small margin on both sides so strings that
cross a page boundary are coloured consistently while scrolling.

Priority (same as the original decorator chain):
    ascii strings  <  prefixes (MZ, PE, call [mem]) / wide strings  <  ranges  <  edited bytes
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np

from . import theme

MARGIN = 128


@dataclass
class PageColors:
    """Colours for one page of bytes (arrays have the page length)."""

    fg: np.ndarray
    bg: np.ndarray
    display: np.ndarray  # bytes to show in text columns (wide strings compacted)


class Rule:
    def apply(self, buf: bytes, base: int, fg, bg, fg_set, display) -> None:  # pragma: no cover
        raise NotImplementedError


@dataclass
class AsciiStrings(Rule):
    """Printable runs (>= min_len) get a colour unless already coloured."""

    color: int = theme.RED
    min_len: int = 4
    charset: bytes = rb"a-zA-Z0-9\-\\.%*:/? _<>"

    def __post_init__(self):
        self._re = re.compile(rb"[" + self.charset + rb"]{%d,}" % self.min_len)

    def apply(self, buf, base, fg, bg, fg_set, display):
        for m in self._re.finditer(buf):
            s, e = m.span()
            sl = slice(s, e)
            free = ~fg_set[sl]
            fg[sl][free] = self.color
            fg_set[sl] = True


@dataclass
class Prefix(Rule):
    """Every occurrence of ``pattern`` (+ extra bytes) gets fg/bg."""

    pattern: bytes
    fg: int = theme.YELLOW
    bg: int | None = theme.DARK_RED
    extra: int = 0

    def apply(self, buf, base, fg, bg, fg_set, display):
        n = len(self.pattern) + self.extra
        i = buf.find(self.pattern)
        while i != -1:
            fg[i:i + n] = self.fg
            fg_set[i:i + n] = True
            if self.bg is not None:
                bg[i:i + n] = self.bg
            i = buf.find(self.pattern, i + n)


@dataclass
class WideStrings(Rule):
    """UTF-16LE ascii strings: coloured and compacted for display."""

    color: int = theme.YELLOW
    min_len: int = 4
    _re: re.Pattern = field(default=re.compile(rb"(?:[a-zA-Z0-9\-\\.%*:/? ]\x00){4,}"), repr=False)

    def apply(self, buf, base, fg, bg, fg_set, display):
        for m in self._re.finditer(buf):
            s, e = m.span()
            fg[s:e] = self.color
            fg_set[s:e] = True
            n = (e - s) // 2
            display[s:s + n] = display[s:e:2].copy()
            display[s + n:e] = 0


@dataclass
class Range(Rule):
    """Absolute file range [a, b) coloured.

    ``override=True`` recolours everything; otherwise only bytes that still
    have the default colour (mirrors the old ``ignoreHighlights`` flag).
    """

    a: int
    b: int
    color: int
    override: bool = False

    def apply(self, buf, base, fg, bg, fg_set, display):
        s = max(self.a - base, 0)
        e = min(self.b - base, len(buf))
        if e <= s:
            return
        if self.override:
            fg[s:e] = self.color
        else:
            sl = slice(s, e)
            fg[sl][~fg_set[sl]] = self.color


class Highlighter:
    """Runs a list of rules over a page and returns colours + display bytes."""

    def __init__(self, rules: list[Rule] | None = None):
        self.rules: list[Rule] = list(rules or [])
        self.version = 0

    def add(self, rule: Rule) -> None:
        self.rules.append(rule)
        self.version += 1

    def colorize(self, dm, offset: int, length: int) -> PageColors:
        size = len(dm)
        a = max(0, offset - MARGIN)
        b = min(size, offset + length + MARGIN)
        buf = dm.read(a, b)
        n = len(buf)
        fg = np.full(n, theme.FG, dtype=np.uint8)
        bg = np.full(n, theme.BG, dtype=np.uint8)
        fg_set = np.zeros(n, dtype=bool)
        display = np.frombuffer(buf, dtype=np.uint8).copy()

        ranges = [r for r in self.rules if isinstance(r, Range)]
        for rule in self.rules:
            if not isinstance(rule, Range):
                rule.apply(buf, a, fg, bg, fg_set, display)
        for rule in ranges:
            rule.apply(buf, a, fg, bg, fg_set, display)

        # modified (unsaved) bytes always win
        for s, e in dm.modified.overlapping(a, b):
            fg[s - a:e - a] = theme.EDITED

        lo = offset - a
        hi = lo + min(length, size - offset) if offset < size else lo
        return PageColors(fg[lo:hi], bg[lo:hi], display[lo:hi])


def default_rules() -> list[Rule]:
    """The classic Qiew look for executables."""
    return [
        AsciiStrings(),
        Prefix(b"MZ"),
        Prefix(b"PE\x00\x00"),
        Prefix(b"\xff\x15", fg=theme.WHITE, bg=theme.GRAY, extra=4),   # call [imm32]
        WideStrings(),
    ]
