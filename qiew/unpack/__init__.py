"""Decrypt/encrypt ("unpack") plugins operating on the current selection."""
from __future__ import annotations

import importlib
import logging

from .base import DecryptPlugin

log = logging.getLogger(__name__)
BUILTIN = ["basic", "rc4", "aes", "base64_codec"]
_loaded = False


def all_plugins() -> list[type[DecryptPlugin]]:
    global _loaded
    if not _loaded:
        _loaded = True
        for m in BUILTIN:
            try:
                importlib.import_module(f"{__name__}.{m}")
            except ImportError as e:
                log.info("unpack plugin %s disabled: %s", m, e)
        # user plugins are imported by the format registry loader
        from .. import formats

        formats._load()
    out, todo = [], [DecryptPlugin]
    while todo:
        c = todo.pop()
        for s in c.__subclasses__():
            todo.append(s)
            if s.__dict__.get("name"):
                out.append(s)
    return sorted(out, key=lambda c: (c.priority, c.name))
