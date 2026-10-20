"""ELF format (pyelftools)."""
from __future__ import annotations

import bisect
import io

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .. import disasm, highlight
from .base import GREEN, PURPLE, Action, FileFormat, InfoDialog, NavTree, tree_item

ARCHS = {"x64": disasm.X86_64, "x86": disasm.X86_32, "ARM": disasm.THUMB, "AArch64": disasm.ARM64}


class DMStream(io.RawIOBase):
    """Read-only file-like view over a DataModel (no copy of the data)."""

    def __init__(self, dm):
        self.dm, self.pos = dm, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else len(self.dm) + off
        return self.pos

    def tell(self):
        return self.pos

    def read(self, n=-1):
        end = len(self.dm) if n is None or n < 0 else self.pos + n
        data = self.dm.read(self.pos, end)
        self.pos += len(data)
        return data


class ELF(FileFormat):
    name = "elf"
    priority = 5
    description = "ELF executable"
    address_modes = ("FA", "VA")
    left_width = 20

    @classmethod
    def recognize(cls, dm) -> bool:
        return dm.read(0, 4) == b"\x7fELF"

    def __init__(self, dm):
        super().__init__(dm)
        self._stream = DMStream(dm)
        self.elf = ELFFile(self._stream)
        self.sections = []
        for s in self.elf.iter_sections():
            h = s.header
            if h["sh_type"] != "SHT_NOBITS" and h["sh_size"]:
                self.sections.append((h["sh_offset"], h["sh_offset"] + h["sh_size"], s.name, h["sh_addr"]))
        self.sections.sort()
        self._sec_starts = [s[0] for s in self.sections]
        self.segments = [(p["p_offset"], p["p_filesz"], p["p_vaddr"]) for p in
                         (seg.header for seg in self.elf.iter_segments()) if p["p_type"] == "PT_LOAD"]
        self.symbols: dict[int, str] = {}
        for s in self.elf.iter_sections():
            if isinstance(s, SymbolTableSection):
                for sym in s.iter_symbols():
                    if sym.name and sym["st_value"] and sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT"):
                        self.symbols.setdefault(sym["st_value"], sym.name)
        self._dialog = None

    def setup(self, doc):
        doc.hl.rules = [highlight.AsciiStrings(), highlight.Prefix(b"\x7fELF"), highlight.Prefix(b"MZ"),
                        highlight.WideStrings()]

    # ---------------------------------------------------------------- addresses
    def va(self, off):
        for o, sz, v in self.segments:
            if o <= off < o + sz:
                return v + off - o
        return None

    def fa(self, va):
        for o, sz, v in self.segments:
            if v <= va < v + sz:
                return o + va - v
        return None

    def disasm_arch(self):
        return ARCHS.get(self.elf.get_machine_arch(), disasm.X86_64)

    def symbol(self, va):
        return self.symbols.get(va)

    def section_at(self, off):
        i = bisect.bisect_right(self._sec_starts, off) - 1
        if i >= 0 and self.sections[i][0] <= off < self.sections[i][1]:
            return self.sections[i]
        return None

    # ---------------------------------------------------------------- banners
    def address_label(self, off):
        sec = self.section_at(off)
        name = (sec[2] if sec else "--------")[:8].ljust(8)
        if self.address_mode == "VA":
            v = self.va(off)
            a = f"{v:08x}" if v is not None else "--------"
        else:
            a = f"{off:08x}"
        return f"{name} {a:>9}"

    def top_label(self):
        return f"Name      {self.address_mode:>5}"

    def status_hint(self, off):
        eh = self.elf.header
        if off < eh["e_ehsize"]:
            return "ELF header"
        if eh["e_phoff"] <= off < eh["e_phoff"] + eh["e_phnum"] * eh["e_phentsize"]:
            return "Program headers"
        if eh["e_shoff"] <= off < eh["e_shoff"] + eh["e_shnum"] * eh["e_shentsize"]:
            return "Section headers"
        sec = self.section_at(off)
        return sec[2] if sec else ""

    def goto_spaces(self):
        return {"FileAddress": lambda x: x, "VirtualAddress": self.fa}

    def goto_constants(self, space):
        ep = self.elf.header["e_entry"]
        if space == "VirtualAddress":
            return {"EP": ep, "END": len(self.dm)}
        return {"EP": self.fa(ep) or 0, "END": len(self.dm)}

    def actions(self):
        return super().actions() + [
            Action("Go to entry point", "F7", lambda: self.goto(self.fa(self.elf.header["e_entry"]))),
            Action("Previous section", "[", self.prev_section),
            Action("Next section", "]", self.next_section),
            Action("Sections / segments / symbols", "Alt+H", lambda: self.info(0)),
        ]

    def next_section(self):
        off = self.cursor
        nxt = [s for s in self.sections if s[0] > off]
        self.goto(nxt[0][0] if nxt else len(self.dm) - 1)

    def prev_section(self):
        off = self.cursor
        prev = [s for s in self.sections if s[0] < off]
        self.goto(prev[-1][0] if prev else 0)

    def info(self, tab):
        if self._dialog is None:
            from PySide6 import QtWidgets

            dlg = InfoDialog(QtWidgets.QApplication.activeWindow(), "ELF")
            t = NavTree(self.doc, ["Name", "Offset", "Size", "Address", "Type"])
            for s in self.elf.iter_sections():
                h = s.header
                t.addTopLevelItem(tree_item([s.name, f"{h['sh_offset']:X}", f"{h['sh_size']:X}", f"{h['sh_addr']:X}",
                                             h["sh_type"]], h["sh_offset"], h["sh_size"], {1: GREEN, 2: GREEN, 3: PURPLE}))
            t.setColumnWidth(0, 160)
            dlg.tabs.addTab(t, "&Sections")
            t = NavTree(self.doc, ["Type", "Offset", "FileSize", "VAddr", "MemSize", "Flags"])
            for seg in self.elf.iter_segments():
                p = seg.header
                t.addTopLevelItem(tree_item([p["p_type"], f"{p['p_offset']:X}", f"{p['p_filesz']:X}", f"{p['p_vaddr']:X}",
                                             f"{p['p_memsz']:X}", f"{p['p_flags']:x}"], p["p_offset"], p["p_filesz"],
                                            {1: GREEN, 2: GREEN, 3: PURPLE}))
            t.setColumnWidth(0, 140)
            dlg.tabs.addTab(t, "Se&gments")
            t = NavTree(self.doc, ["Symbol", "Address", "Offset"])
            for va, name in sorted(self.symbols.items()):
                fa = self.fa(va)
                t.addTopLevelItem(tree_item([name, f"{va:X}", f"{fa:X}" if fa is not None else "-"], fa))
            t.setColumnWidth(0, 300)
            dlg.tabs.addTab(t, "S&ymbols")
            self._dialog = dlg
        self._dialog.toggle(tab)
