"""Android APK (zip). Files can be opened in a new qiew window.

Manifest details (permissions, components) use androguard when installed.
"""
from __future__ import annotations

import bisect
import io
import zipfile

from PySide6 import QtGui, QtWidgets

from .. import highlight, theme
from .base import GREEN, Action, FileFormat, InfoDialog, NavTree, tree_item


class _ZipStream(io.RawIOBase):
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
        d = self.dm.read(self.pos, end)
        self.pos += len(d)
        return d

    def readinto(self, b):
        d = self.read(len(b))
        b[:len(d)] = d
        return len(d)


class APK(FileFormat):
    name = "apk"
    priority = 5
    description = "Android package"

    @classmethod
    def recognize(cls, dm) -> bool:
        if dm.read(0, 4) != b"PK\x03\x04":
            return False
        try:
            names = zipfile.ZipFile(_ZipStream(dm)).namelist()
        except zipfile.BadZipFile:
            return False
        return "AndroidManifest.xml" in names

    def __init__(self, dm):
        super().__init__(dm)
        self.zip = zipfile.ZipFile(_ZipStream(dm))
        self._infos = sorted(self.zip.infolist(), key=lambda z: z.header_offset)
        self._starts = [z.header_offset for z in self._infos]
        self._dialog = None

    def setup(self, doc):
        doc.hl.rules = [highlight.AsciiStrings(), highlight.Prefix(b"PK\x03\x04", theme.YELLOW, theme.DARK_RED),
                        highlight.Prefix(b"PK\x01\x02", theme.YELLOW, theme.DARK_RED), highlight.WideStrings()]

    def status_hint(self, off):
        i = bisect.bisect_right(self._starts, off) - 1
        if i >= 0:
            zi = self._infos[i]
            if off < zi.header_offset + 30 + len(zi.filename) + len(zi.extra) + zi.compress_size:
                return zi.filename[-40:]
        return ""

    def actions(self):
        return super().actions() + [
            Action("Files", "Alt+F", lambda: self.info(0)),
            Action("Manifest (permissions / components)", "Alt+P", lambda: self.info(1)),
        ]

    def open_member(self, name: str) -> None:
        if self.doc and self.doc.open_buffer:
            self.doc.open_buffer(self.zip.read(name), name)

    def _manifest(self):
        try:
            try:
                from androguard.core.apk import APK as AG  # androguard >= 4
            except ImportError:
                from androguard.core.bytecodes.apk import APK as AG  # androguard 3
        except ImportError:
            return None
        try:
            return AG(self.dm.read(0, len(self.dm)), raw=True)
        except Exception:  # noqa: BLE001
            return None

    def info(self, tab):
        if self._dialog is None:
            dlg = InfoDialog(QtWidgets.QApplication.activeWindow(), "APK")
            files = NavTree(self.doc, ["File", "Offset", "Size", "Compressed"])
            for zi in self.zip.infolist():
                files.addTopLevelItem(tree_item([zi.filename, f"{zi.header_offset:X}", str(zi.file_size),
                                                 str(zi.compress_size)], zi.header_offset, None, {1: GREEN}))
            files.setColumnWidth(0, 360)
            files.setToolTip("Enter: jump to local header.  Double click: open file in a new window.")
            files.itemDoubleClicked.disconnect()
            files.itemDoubleClicked.connect(lambda it, _c: self.open_member(it.text(0)))
            dlg.tabs.addTab(files, "&Files")

            man = QtWidgets.QTreeWidget()
            man.setHeaderLabels(["Manifest"])
            ag = self._manifest()
            if ag is None:
                man.addTopLevelItem(QtWidgets.QTreeWidgetItem(["install 'androguard' for manifest details"]))
            else:
                for title, items in [("Package", [ag.get_package()]), ("Permissions", ag.get_permissions()),
                                     ("Activities", ag.get_activities()), ("Services", ag.get_services()),
                                     ("Receivers", ag.get_receivers()), ("Providers", ag.get_providers())]:
                    top = QtWidgets.QTreeWidgetItem([title])
                    for x in items:
                        c = QtWidgets.QTreeWidgetItem([str(x).replace("android.permission.", "")])
                        c.setForeground(0, QtGui.QColor("purple"))
                        top.addChild(c)
                    man.addTopLevelItem(top)
                    top.setExpanded(True)
            dlg.tabs.addTab(man, "&Manifest")
            self._dialog = dlg
        self._dialog.toggle(tab)
