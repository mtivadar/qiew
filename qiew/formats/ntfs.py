"""NTFS volume image (self-contained, no fs_ntfs submodule needed)."""
from __future__ import annotations

from PySide6 import QtGui

from .. import disasm, highlight, theme
from ..selection import SelType
from .base import Action, FileFormat

SPECIAL_FILES = ["$MFT", "$MFTMirr", "$Boot", "$LogFile", "$BadClus", "$AttrDef", "$Bitmap", "$Extend",
                 "$Secure", "$Volume", "$UpCase", "$Reparse", "$Repair", "$Config", "$Deleted", "$Quota",
                 "$TxfLog", "$RmMetadata", "$I30", "$ObjId", "$Tops"]


class NTFS(FileFormat):
    name = "ntfs"
    priority = 6           # above bootsector, which also matches
    description = "NTFS volume"

    @classmethod
    def recognize(cls, dm) -> bool:
        return dm.u16(510) == 0xAA55 and dm.read(3, 7) == b"NTFS"

    def __init__(self, dm):
        super().__init__(dm)
        bps = dm.u16(0x0B) or 512
        spc = dm.byte(0x0D) or 1
        self.cluster = bps * spc
        self.mft_lcn = dm.u64(0x30) or 0
        cpr = dm.byte(0x40) or 0
        cpr = cpr - 256 if cpr >= 128 else cpr
        self.record_size = (1 << -cpr) if cpr < 0 else cpr * self.cluster

    def setup(self, doc):
        purple, olive = theme.PALETTE.index((128, 0, 128)), theme.PALETTE.index((128, 128, 0))
        rules = [highlight.AsciiStrings(), highlight.Prefix(b"MZ"), highlight.Prefix(b"PE\x00\x00"),
                 highlight.Prefix(b"\x55\xaa", theme.BRIGHT_GREEN, theme.DARK_RED)]
        rules += [highlight.Prefix(n.encode("utf-16-le"), theme.YELLOW, purple) for n in SPECIAL_FILES]
        rules += [highlight.Prefix(b"FILE", theme.YELLOW, theme.DARK_RED),
                  highlight.Prefix(b"INDX", theme.BRIGHT_GREEN, olive),
                  highlight.WideStrings(),
                  highlight.Range(0, 3, theme.YELLOW, override=True),        # jump
                  highlight.Range(3, 11, theme.BRIGHT_GREEN, override=True)]  # OEM id
        doc.hl.rules = rules
        doc.sel.add(0x0B, 0x50, QtGui.QColor(125, 175, 150), 0.4, SelType.PERMANENT)  # BPB

    def disasm_arch(self):
        return disasm.X86_16

    def record_offset(self, n: int) -> int:
        return self.mft_lcn * self.cluster + n * self.record_size

    def status_hint(self, off):
        mft = self.mft_lcn * self.cluster
        if off < 0x54:
            return "boot sector / BPB"
        if off >= mft and self.record_size:
            n = (off - mft) // self.record_size
            if n < 64:
                return f"MFT record {n}"
        return ""

    def _goto_record(self, n: int) -> None:
        off = self.record_offset(n)
        if 0 <= off < len(self.dm) and self.doc:
            self.doc.sel.add(off, off + self.record_size, QtGui.QColor(125, 175, 150), 0.4, SelType.CONDITIONAL)
            self.goto(off)

    def actions(self):
        return super().actions() + [
            Action("Go to $MFT record", "Alt+M", lambda: self._goto_record(0)),
            Action("Go to root directory record", "Alt+R", lambda: self._goto_record(5)),
        ]
