"""Fallback format: any file."""
from __future__ import annotations

from .base import FileFormat


class Binary(FileFormat):
    name = "binary"
    priority = 0
    description = "Binary file, unknown format"

    @classmethod
    def recognize(cls, dm) -> bool:
        return True
