"""Format plugin registry.

Built-in formats live in this package; extra ones can be dropped as ``.py``
files into ``~/.qiew/plugins`` (or a directory given in ``QIEW_PLUGINS``).
Any ``FileFormat`` / ``DecryptPlugin`` subclass found there is registered.
Formats whose optional dependency is missing are skipped silently.
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import sys
from pathlib import Path

from .base import FileFormat

log = logging.getLogger(__name__)

BUILTIN = ["binary", "pe", "elf", "bootsector", "ntfs", "apk"]
_loaded = False
_user_modules: list = []


def plugin_dirs() -> list[Path]:
    dirs = [Path.home() / ".qiew" / "plugins"]
    extra = os.environ.get("QIEW_PLUGINS")
    if extra:
        dirs += [Path(p) for p in extra.split(os.pathsep) if p]
    return dirs


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    for mod in BUILTIN:
        try:
            importlib.import_module(f"{__name__}.{mod}")
        except ImportError as e:  # optional dependency missing
            log.info("format %s disabled: %s", mod, e)
    for d in plugin_dirs():
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            name = f"qiew_user_plugin_{f.stem}"
            try:
                spec = importlib.util.spec_from_file_location(name, f)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[name] = mod
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
                _user_modules.append(mod)
            except Exception as e:  # noqa: BLE001 - never let a plugin kill the app
                log.warning("failed to load plugin %s: %s", f, e)


def _subclasses(cls):
    out, todo = [], [cls]
    while todo:
        c = todo.pop()
        for s in c.__subclasses__():
            out.append(s)
            todo.append(s)
    return out


def all_formats() -> list[type[FileFormat]]:
    _load()
    fmts = [c for c in _subclasses(FileFormat) if c.__dict__.get("name")]
    # de-duplicate by name, keep most derived/last defined
    seen: dict[str, type[FileFormat]] = {}
    for c in fmts:
        seen[c.name] = c
    return sorted(seen.values(), key=lambda c: c.priority, reverse=True)


def choose_format(dm) -> FileFormat:
    from .binary import Binary

    for cls in all_formats():
        try:
            if cls.recognize(dm):
                log.info("format: %s", cls.name)
                return cls(dm)
        except Exception as e:  # noqa: BLE001
            log.debug("format %s failed recognition: %s", cls.name, e)
    return Binary(dm)
