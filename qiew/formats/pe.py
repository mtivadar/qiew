"""Portable Executable (MZ/PE) format."""
from __future__ import annotations

import bisect
import datetime

import pefile
from PySide6 import QtGui, QtWidgets

from .. import disasm, highlight, theme
from ..selection import SelType
from .base import GREEN, PURPLE, Action, FileFormat, InfoDialog, NavTree, tree_item

DIRECTORY_NAMES = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc", "Debug",
                   "Copyright", "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT",
                   "DelayedImports", "COM Descr.", "Reserved"]
_DIRS = [pefile.DIRECTORY_ENTRY[n] for n in (
    "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_DEBUG", "IMAGE_DIRECTORY_ENTRY_TLS", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT")]
MACHINES = {v: k.replace("IMAGE_FILE_MACHINE_", "") for k, v in pefile.MACHINE_TYPE.items() if isinstance(v, int)}
RES_TYPES = {v: k.replace("RT_", "") for k, v in pefile.RESOURCE_TYPE.items() if isinstance(v, int)}


def _s(b) -> str:
    if isinstance(b, (bytes, bytearray)):
        return b.decode("latin-1").rstrip("\x00")
    return str(b)


class PE(FileFormat):
    name = "pe"
    priority = 5
    description = "MZ-PE executable"
    address_modes = ("VA", "RVA", "FA")
    left_width = 20

    @classmethod
    def recognize(cls, dm) -> bool:
        if dm.read(0, 2) != b"MZ":
            return False
        lfanew = dm.u32(0x3C)
        return lfanew is not None and dm.read(lfanew, lfanew + 4) == b"PE\x00\x00"

    def __init__(self, dm):
        super().__init__(dm)
        self.pe = pefile.PE(data=dm.data, fast_load=True)
        try:
            self.pe.parse_data_directories(directories=_DIRS)
        except Exception:  # noqa: BLE001 - malformed directories should not block viewing
            pass
        oh = self.pe.OPTIONAL_HEADER
        self.image_base = oh.ImageBase
        self.overlay = self.pe.get_overlay_data_start_offset()
        secs = sorted((s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, _s(s.Name), s)
                      for s in self.pe.sections if s.SizeOfRawData)
        self._sec_starts = [s[0] for s in secs]
        self._secs = secs
        # O(1) symbol lookup for disassembly (old code scanned imports per call)
        self.imports: dict[int, str] = {}
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []) + getattr(self.pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            dll = _s(entry.dll)
            for imp in entry.imports:
                nm = _s(imp.name) if imp.name else f"ord{imp.ordinal}"
                self.imports[imp.address] = f"{dll}:{nm}"
        self.exports: dict[int, str] = {}
        exp = getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exp:
            for sym in exp.symbols:
                self.exports[self.image_base + sym.address] = _s(sym.name) if sym.name else f"ord{sym.ordinal}"
        self._dialog: InfoDialog | None = None

    # ---------------------------------------------------------------- setup
    def setup(self, doc):
        rules = highlight.default_rules()
        if self.overlay:
            rules.append(highlight.Range(self.overlay, len(self.dm), theme.GRAY))
        iat = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]]
        if iat.Size:
            s = self.rva_to_fa(iat.VirtualAddress)
            if s is not None:
                rules.append(highlight.Range(s, s + iat.Size, theme.GREEN))
        doc.hl.rules = rules
        ep = self.entry_point()
        if ep is not None:
            doc.sel.add(ep, ep + 30, theme.EP_MARK, 0.5, SelType.PERMANENT)

    # ---------------------------------------------------------------- addresses
    def rva_to_fa(self, rva: int) -> int | None:
        try:
            off = self.pe.get_offset_from_rva(rva)
        except Exception:  # noqa: BLE001
            return None
        return off if off is not None and 0 <= off < len(self.dm) else None

    def fa_to_rva(self, off: int) -> int | None:
        try:
            return self.pe.get_rva_from_offset(off)
        except Exception:  # noqa: BLE001
            return None

    def va(self, offset):
        rva = self.fa_to_rva(offset)
        return None if rva is None else rva + self.image_base

    def fa(self, va):
        return self.rva_to_fa(va - self.image_base)

    def entry_point(self) -> int | None:
        return self.rva_to_fa(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def disasm_arch(self):
        m = self.pe.FILE_HEADER.Machine
        if m == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return disasm.X86_64
        if m == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_ARM64"]:
            return disasm.ARM64
        if m in (pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_ARMNT"], pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_THUMB"]):
            return disasm.THUMB
        if m == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_ARM"]:
            return disasm.ARM
        return disasm.X86_32

    def symbol(self, va):
        return self.imports.get(va) or self.exports.get(va)

    def section_at(self, off: int):
        i = bisect.bisect_right(self._sec_starts, off) - 1
        if i >= 0 and self._secs[i][0] <= off < self._secs[i][1]:
            return self._secs[i]
        return None

    # ---------------------------------------------------------------- banners
    def address_label(self, off):
        sec = self.section_at(off)
        name = (sec[2] if sec else "--------")[:8].ljust(8)
        mode = self.address_mode
        if mode == "FA":
            a = f"{off:08x}"
        else:
            rva = self.fa_to_rva(off)
            if rva is None:
                a = " overlay"
            else:
                a = f"{rva:08x}" if mode == "RVA" else f"{rva + self.image_base:08x}"
        return f"{name} {a:>9}"

    def top_label(self):
        return f"Name      {self.address_mode:>5}"

    def status_hint(self, off):
        pe = self.pe
        if off < pe.DOS_HEADER.sizeof():
            return "DOS header"
        fh = pe.FILE_HEADER.get_file_offset()
        if fh <= off < fh + pe.FILE_HEADER.sizeof():
            return "File header"
        ohs = pe.OPTIONAL_HEADER.get_file_offset()
        ohe = ohs + pe.FILE_HEADER.SizeOfOptionalHeader
        if ohs <= off < ohe:
            return "Opt. header"
        if ohe <= off < ohe + len(pe.sections) * 0x28:
            return "Section header"
        for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if d.VirtualAddress and d.Size:
                s = self.rva_to_fa(d.VirtualAddress) if i != 4 else d.VirtualAddress  # security dir is a file offset
                if s is not None and s <= off < s + d.Size:
                    return DIRECTORY_NAMES[i] if i < len(DIRECTORY_NAMES) else f"dir{i}"
        if self.overlay is not None and off >= self.overlay:
            return "Overlay"
        sec = self.section_at(off)
        return sec[2] if sec else ""

    def status_extra(self):
        if not self.overlay:
            return []
        size = len(self.dm)
        n = size - self.overlay
        return [f"overlay: {n:,} bytes", f"         {n * 100 // max(1, size)}%"]

    # ---------------------------------------------------------------- goto
    def goto_spaces(self):
        return {"RVA": self.rva_to_fa, "FileAddress": lambda x: x, "VirtualAddress": self.fa}

    def goto_constants(self, space):
        ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        end = len(self.dm)
        end_rva = self.fa_to_rva(end - 1)
        if space == "RVA":
            return {"EP": ep_rva, "END": (end_rva or 0) + 1}
        if space == "VirtualAddress":
            return {"EP": ep_rva + self.image_base, "END": (end_rva or 0) + 1 + self.image_base}
        return {"EP": self.entry_point() or 0, "END": end}

    # ---------------------------------------------------------------- actions
    def actions(self):
        return super().actions() + [
            Action("Go to entry point", "F7", lambda: self.goto(self.entry_point())),
            Action("Go to overlay", "0", lambda: self.goto(self.overlay)),
            Action("Previous section", "[", self.prev_section),
            Action("Next section", "]", self.next_section),
            Action("Headers", "Alt+H", lambda: self.info(0)),
            Action("Sections", "Alt+S", lambda: self.info(1)),
            Action("Directories", "Alt+D", lambda: self.info(2)),
            Action("Imports", "Alt+I", lambda: self.info(3)),
            Action("Exports", "Alt+E", lambda: self.info(4)),
            Action("Version info", "Alt+V", lambda: self.info(5)),
            Action("Resources", "Alt+R", lambda: self.info(6)),
        ]

    def next_section(self):
        off = self.cursor
        sec = self.section_at(off)
        if sec:
            x = sec[1]
        else:
            nxt = [s for s in self._secs if s[0] > off]
            x = nxt[0][0] if nxt else len(self.dm) - 1
        self.goto(min(x, len(self.dm) - 1))

    def prev_section(self):
        off = self.cursor
        sec = self.section_at(off)
        if sec:
            prev = [s for s in self._secs if s[1] <= sec[0]]
            x = prev[-1][0] if prev else 0
        else:
            prev = [s for s in self._secs if s[0] < off]
            x = prev[-1][0] if prev else 0
        self.goto(x)

    # ---------------------------------------------------------------- info window
    def info(self, tab: int):
        if self._dialog is None:
            self._dialog = self._build_dialog()
        self._dialog.toggle(tab)

    def _build_dialog(self) -> InfoDialog:
        doc = self.doc
        parent = None
        app = QtWidgets.QApplication.instance()
        if app is not None:
            parent = app.activeWindow()
        dlg = InfoDialog(parent, "PE plugin")
        pe = self.pe

        # headers -----------------------------------------------------------
        t = NavTree(doc, ["Header", "Type", "Value", "Offset"])
        bk1, bk2 = QtGui.QBrush(QtGui.QColor(192, 165, 194)), QtGui.QBrush(QtGui.QColor(232, 194, 229))

        def struct(name, s, bk):
            top = tree_item([name], s.get_file_offset(), s.sizeof())
            top.setBackground(0, bk)
            keys = s.dump_dict()
            fields = [(k, v) for k, v in keys.items() if isinstance(v, dict) and "FileOffset" in v]
            for i, (k, v) in enumerate(fields):
                nxt = fields[i + 1][1]["FileOffset"] if i + 1 < len(fields) else s.get_file_offset() + s.sizeof()
                size = max(1, nxt - v["FileOffset"])
                val = v["Value"]
                sval = f"{val:X}" if isinstance(val, int) else _s(val) if isinstance(val, bytes) else str(val)
                typ = {1: "byte", 2: "word", 4: "dword", 8: "qword"}.get(size, f"[{size}]")
                top.addChild(tree_item([k, typ, sval, f"{v['FileOffset']:X}"], v["FileOffset"], size,
                                       {1: PURPLE, 2: GREEN}))
            return top

        t.addTopLevelItem(struct("IMAGE_DOS_HEADER", pe.DOS_HEADER, bk1))
        nt = tree_item(["IMAGE_NT_HEADERS"], pe.NT_HEADERS.get_file_offset(), pe.NT_HEADERS.sizeof())
        nt.setBackground(0, bk1)
        nt.addChild(struct("IMAGE_FILE_HEADER", pe.FILE_HEADER, bk2))
        opt = struct("IMAGE_OPTIONAL_HEADER", pe.OPTIONAL_HEADER, bk2)
        dd = tree_item([f"IMAGE_DATA_DIRECTORY [{len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)}]"])
        for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            dd.addChild(struct(f"[{i}] {d.name.replace('IMAGE_DIRECTORY_ENTRY_', '')}", d, bk2))
        opt.addChild(dd)
        nt.addChild(opt)
        t.addTopLevelItem(nt)
        sh = tree_item(["IMAGE_SECTION_HEADERS"])
        for i, s in enumerate(pe.sections):
            sh.addChild(struct(f"SECTION_HEADER [{i}] {_s(s.Name)}", s, bk1))
        t.addTopLevelItem(sh)
        t.setColumnWidth(0, 280)
        t.expandItem(nt)
        dlg.tabs.addTab(t, "&Header")

        # sections ----------------------------------------------------------
        t = NavTree(doc, ["Name", "FileOffset", "FileSize", "RVA", "MemSize", "Characteristics", "Entropy"])
        for s in pe.sections:
            flags = "".join(c if getattr(s, f) else "-" for c, f in (
                ("R", "IMAGE_SCN_MEM_READ"), ("W", "IMAGE_SCN_MEM_WRITE"), ("E", "IMAGE_SCN_MEM_EXECUTE"))) + " " + \
                "".join(c if getattr(s, f) else "-" for c, f in (
                    ("C", "IMAGE_SCN_CNT_CODE"), ("I", "IMAGE_SCN_CNT_INITIALIZED_DATA"),
                    ("U", "IMAGE_SCN_CNT_UNINITIALIZED_DATA")))
            it = tree_item([_s(s.Name), f"{s.PointerToRawData:X}", f"{s.SizeOfRawData:X}", f"{s.VirtualAddress:X}",
                            f"{s.Misc_VirtualSize:X}", f"{s.Characteristics:X} [{flags}]", f"{s.get_entropy():.2f}"],
                           s.PointerToRawData, s.SizeOfRawData, {1: GREEN, 2: GREEN, 3: PURPLE, 4: PURPLE})
            t.addTopLevelItem(it)
        t.setColumnWidth(0, 100)
        dlg.tabs.addTab(t, "&Sections")

        # directories -------------------------------------------------------
        t = NavTree(doc, ["Directory", "Section", "Address", "Size"])
        for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            name = d.name.replace("IMAGE_DIRECTORY_ENTRY_", "")
            if d.VirtualAddress and d.Size:
                off = d.VirtualAddress if i == 4 else self.rva_to_fa(d.VirtualAddress)
                sec = self.section_at(off) if off is not None else None
                it = tree_item([name, sec[2] if sec else "<outside>", f"{d.VirtualAddress:X}", f"{d.Size:X}"],
                               off, d.Size, {1: QtGui.QColor("red"), 2: GREEN, 3: GREEN})
            else:
                it = tree_item([name])
                it.setForeground(0, QtGui.QColor("gray"))
            t.addTopLevelItem(it)
        t.setColumnWidth(0, 150)
        dlg.tabs.addTab(t, "&Directories")

        # imports -----------------------------------------------------------
        t = NavTree(doc, ["Name", "RVA", "Hint"])
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) + getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            top = tree_item([_s(entry.dll)])
            for imp in entry.imports:
                rva = imp.address - self.image_base
                nm = _s(imp.name) if imp.name else f"ordinal:{imp.ordinal}"
                top.addChild(tree_item([nm, f"0x{rva:X}", str(imp.hint or "")], self.rva_to_fa(rva), 8 if
                                       self.disasm_arch() == disasm.X86_64 else 4))
            t.addTopLevelItem(top)
        t.setColumnWidth(0, 300)
        dlg.tabs.addTab(t, "&Imports")

        # exports -----------------------------------------------------------
        t = NavTree(doc, ["Name", "RVA", "Ordinal"])
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exp:
            top = tree_item([_s(pe.get_string_at_rva(exp.struct.Name)) or "<exports>"])
            for sym in exp.symbols:
                nm = _s(sym.name) if sym.name else f"ord{sym.ordinal}"
                if sym.forwarder:
                    nm += f" -> {_s(sym.forwarder)}"
                top.addChild(tree_item([nm, f"0x{sym.address:X}", str(sym.ordinal)], self.rva_to_fa(sym.address)))
            t.addTopLevelItem(top)
            t.expandItem(top)
        t.setColumnWidth(0, 300)
        dlg.tabs.addTab(t, "&Exports")

        # version info / summary -------------------------------------------
        t = QtWidgets.QTreeWidget()
        t.setHeaderLabels(["Field", "Value"])
        petype = "DLL" if pe.is_dll() else "Driver" if pe.is_driver() else "EXE" if pe.is_exe() else "n/a"
        rows = [("PE Type", petype), ("Size", f"{len(self.dm):,} bytes"),
                ("Overlay", f"{len(self.dm) - self.overlay:,} bytes at {self.overlay:#x}" if self.overlay else "-"),
                ("Machine", MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))),
                ("TimeDateStamp", _ts(pe.FILE_HEADER.TimeDateStamp)),
                ("Entry point", f"{pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}"),
                ("Imphash", _safe(pe.get_imphash))]
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            pdb = getattr(getattr(dbg, "entry", None), "PdbFileName", None)
            if pdb:
                rows.append(("PDB File", _s(pdb)))
        for k, v in _version_strings(pe):
            rows.append((k, v))
        for k, v in rows:
            t.addTopLevelItem(QtWidgets.QTreeWidgetItem([k, str(v)]))
        t.setColumnWidth(0, 200)
        dlg.tabs.addTab(t, "&VersionInfo")

        # resources ---------------------------------------------------------
        t = NavTree(doc, ["Resource", "Offset", "Size", "Lang"])
        res = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if res:
            for rtype in res.entries:
                tname = _s(rtype.name) if rtype.name else RES_TYPES.get(rtype.id, str(rtype.id))
                ti = tree_item([tname])
                for rname in getattr(getattr(rtype, "directory", None), "entries", []):
                    nname = _s(rname.name) if rname.name else str(rname.id)
                    for lang in getattr(getattr(rname, "directory", None), "entries", []):
                        data = getattr(lang, "data", None)
                        if data is None:
                            continue
                        off = self.rva_to_fa(data.struct.OffsetToData)
                        ti.addChild(tree_item([nname, f"{off:X}" if off is not None else "?",
                                               f"{data.struct.Size:X}", str(getattr(data, "lang", ""))],
                                              off, data.struct.Size, {1: GREEN, 2: GREEN}))
                t.addTopLevelItem(ti)
        t.setColumnWidth(0, 200)
        dlg.tabs.addTab(t, "&Resources")
        return dlg


def _ts(v: int) -> str:
    try:
        return f"{v:#x} ({datetime.datetime.fromtimestamp(v, datetime.timezone.utc):%Y-%m-%d %H:%M:%S} UTC)"
    except (OverflowError, OSError, ValueError):
        return f"{v:#x}"


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return "-"


def _version_strings(pe):
    out = []
    for fi in getattr(pe, "FileInfo", None) or []:
        entries = fi if isinstance(fi, list) else [fi]
        for e in entries:
            if getattr(e, "Key", b"") in (b"StringFileInfo", "StringFileInfo"):
                for st in e.StringTable:
                    for k, v in st.entries.items():
                        out.append((_s(k), _s(v)))
    return out
