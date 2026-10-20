"""MBR / boot sector."""
from __future__ import annotations

from PySide6 import QtCore, QtGui, QtWidgets

from .. import disasm, highlight, theme
from ..selection import SelType
from .base import Action, FileFormat

LOAD = 0x7C00
PT = 0x1BE
PART_TYPES = {0x00: "empty", 0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended", 0x06: "FAT16", 0x07: "NTFS/exFAT",
              0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA", 0x0F: "Extended LBA", 0x17: "Hidden NTFS",
              0x27: "WinRE", 0x82: "Linux swap", 0x83: "Linux", 0x8E: "Linux LVM", 0xA5: "FreeBSD",
              0xAF: "HFS+", 0xDE: "Dell diagnostic", 0xEE: "GPT protective", 0xEF: "EFI system"}


class Bootsector(FileFormat):
    name = "bootsector"
    priority = 4
    description = "Boot sector / MBR"
    address_modes = ("MemAddr", "FileAddr")

    @classmethod
    def recognize(cls, dm) -> bool:
        return dm.u16(510) == 0xAA55

    def __init__(self, dm):
        super().__init__(dm)
        self._dialog = None

    def setup(self, doc):
        doc.hl.rules = [highlight.AsciiStrings(), highlight.Prefix(b"\x55\xaa", theme.YELLOW, theme.DARK_RED)]
        colors = [QtGui.QColor(125, 75, 150), QtGui.QColor(55, 125, 50)]
        for i in range(4):
            doc.sel.add(PT + i * 16, PT + (i + 1) * 16, colors[i % 2], 0.8, SelType.PERMANENT)

    def va(self, off):
        return LOAD + off

    def fa(self, va):
        off = va - LOAD
        return off if 0 <= off < len(self.dm) else None

    def disasm_arch(self):
        return disasm.X86_16

    def address_label(self, off):
        return f"{(LOAD + off) if self.address_mode == 'MemAddr' else off:08x}"

    def status_hint(self, off):
        if PT <= off < PT + 64:
            return f"partition #{(off - PT) // 16 + 1}"
        if off in (510, 511):
            return "boot signature"
        return ""

    def goto_spaces(self):
        return {"FileAddress": lambda x: x, "MemAddress": self.fa}

    def actions(self):
        return super().actions() + [
            Action("Partition table", "Alt+P", self.partition_table),
            Action("Previous partition entry", "[", self.prev_entry),
            Action("Next partition entry", "]", self.next_entry),
        ]

    def _entries(self):
        return [PT + i * 16 for i in range(4)]

    def next_entry(self):
        off = self.cursor
        nxt = [e for e in self._entries() if e > off]
        self.goto(nxt[0] if nxt else PT)

    def prev_entry(self):
        off = self.cursor
        prev = [e for e in self._entries() if e < off]
        self.goto(prev[-1] if prev else PT + 48)

    def partitions(self) -> list[dict]:
        out = []
        dm = self.dm
        for i in range(4):
            e = PT + i * 16
            ptype = dm.byte(e + 4) or 0
            out.append({
                "bootable": dm.byte(e) == 0x80,
                "type": PART_TYPES.get(ptype, f"{ptype:#04x}"),
                "chs_start": f"{(dm.u32(e) or 0) >> 8:06x}",
                "chs_end": f"{(dm.u32(e + 4) or 0) >> 8:06x}",
                "lba": dm.u32(e + 8) or 0,
                "sectors": dm.u32(e + 12) or 0,
            })
        return out

    def partition_table(self):
        if self._dialog is not None and self._dialog.isVisible():
            self._dialog.hide()
            return
        dlg = QtWidgets.QDialog(QtWidgets.QApplication.activeWindow())
        dlg.setWindowTitle("Partition table")
        dlg.setWindowFlag(QtCore.Qt.WindowType.Tool, True)
        rows = ["Bootable", "Type", "CHS Start", "CHS End", "LBA Start", "Sectors"]
        t = QtWidgets.QTableWidget(len(rows), 4, dlg)
        t.setVerticalHeaderLabels(rows)
        t.setHorizontalHeaderLabels(["#1", "#2", "#3", "#4"])
        for c, p in enumerate(self.partitions()):
            vals = ["yes" if p["bootable"] else "no", p["type"], p["chs_start"], p["chs_end"],
                    f"{p['lba']:#x}", f"{p['sectors']:#x}"]
            for r, v in enumerate(vals):
                it = QtWidgets.QTableWidgetItem(v)
                it.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter)
                if p["bootable"]:
                    it.setForeground(QtGui.QColor("green"))
                t.setItem(r, c, it)
        lay = QtWidgets.QVBoxLayout(dlg)
        lay.addWidget(t)
        dlg.resize(560, 260)
        self._dialog = dlg
        dlg.show()
