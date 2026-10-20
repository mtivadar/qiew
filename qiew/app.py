"""Main window and the canvas that paints banners + the active view."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

from . import __version__, disasm, theme
from .datamodel import BufferDataModel, DataModel, FileDataModel
from .dialogs import AnnotationsDialog, DropperDialog, GotoDialog, SearchDialog, UnpackDialog, parse_hex
from .document import Document
from .render import GlyphAtlas, GridRenderer
from .views.binview import BinView
from .views.byteview import is_plain_text
from .views.disasmview import DisasmView
from .views.hexview import HEX_KEYS, HexView

log = logging.getLogger("qiew")
SEP = 5  # gap between banners and the view (px)


class Canvas(QtWidgets.QWidget):
    """Paints top/left/bottom banners and the current view; routes input."""

    def __init__(self, doc: Document, font: QtGui.QFont, parent=None):
        super().__init__(parent)
        self.doc = doc
        self.font_ = font
        self.bold = QtGui.QFont(font)
        self.bold.setBold(True)
        self.views = [BinView(doc), HexView(doc), DisasmView(doc)]
        self.vi = 0
        self._atlas: GlyphAtlas | None = None
        self._renderer: GridRenderer | None = None
        doc._goto = self.goto
        doc._cursor = self.cursor
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self.setMinimumSize(200, 120)
        self._dragging = False
        self.search = SearchDialog(self)
        self.gotodlg = GotoDialog(self)
        self.dropper: DropperDialog | None = None
        self.unpack: UnpackDialog | None = None
        self.annotations: AnnotationsDialog | None = None
        self.on_change = lambda: None   # notifies the window (title, actions)

    # ------------------------------------------------------------------ basics
    @property
    def view(self):
        return self.views[self.vi]

    def cursor(self) -> int:
        return self.view.cursor_offset()

    def refresh(self) -> None:
        self.view.invalidate()
        self.update()
        self.on_change()

    def goto(self, off: int) -> None:
        self.view.goto(off)
        self.update()

    def set_font(self, font: QtGui.QFont) -> None:
        self.font_ = font
        self.bold = QtGui.QFont(font)
        self.bold.setBold(True)
        self._atlas = None
        self._layout()
        self.refresh()

    # ------------------------------------------------------------------ geometry
    def _ensure_renderer(self) -> GlyphAtlas:
        dpr = self.devicePixelRatioF()
        if self._atlas is None or abs(self._atlas.dpr - dpr) > 1e-3:
            self._atlas = GlyphAtlas(self.font_, dpr)
            self._renderer = GridRenderer(self._atlas)
            for v in self.views:
                v.invalidate()
        return self._atlas

    def _geometry(self):
        a = self._ensure_renderer()
        cw, ch = a.cw, a.ch
        top_h = ch + 6
        bottom_h = 2 * ch + 10
        left_w = self.doc.fmt.left_width * cw + 10
        x0, y0 = left_w + SEP, top_h + SEP
        w = max(0, self.width() - x0)
        h = max(0, self.height() - y0 - bottom_h - SEP)
        return cw, ch, top_h, bottom_h, left_w, x0, y0, w, h

    def _layout(self) -> None:
        cw, ch, *_rest, w, h = self._geometry()
        for v in self.views:
            if isinstance(v, DisasmView):
                v.cw, v.ch = cw, ch
            v.resize(max(1, h // ch), max(1, (w - v.x_margin) // cw))

    def resizeEvent(self, ev):
        self._layout()
        super().resizeEvent(ev)

    # ------------------------------------------------------------------ painting
    def paintEvent(self, ev):
        cw, ch, top_h, bottom_h, left_w, x0, y0, w, h = self._geometry()
        if self._atlas is None or self._renderer is None:
            return
        view = self.view
        bgc = QtGui.QColor(*theme.PALETTE.colors()[theme.BG])
        p = QtGui.QPainter(self)
        p.fillRect(self.rect(), QtGui.QColor(20, 20, 20))
        # banners background
        p.fillRect(0, 0, self.width(), top_h, bgc)
        p.fillRect(0, y0, left_w, h, bgc)
        p.fillRect(0, self.height() - bottom_h, self.width(), bottom_h, bgc)
        p.fillRect(x0, y0, w, h, bgc)

        img = view.image(self._renderer)
        p.setClipRect(x0, y0, w, h)
        p.drawImage(QtCore.QPointF(x0 + view.x_margin, y0), img)
        p.translate(x0, y0)
        view.paint_overlays(p, cw, ch)
        p.resetTransform()
        p.setClipping(False)

        self._paint_top(p, cw, ch, top_h, x0 + view.x_margin)
        self._paint_left(p, cw, ch, left_w, y0)
        self._paint_bottom(p, cw, ch, bottom_h)
        p.end()

    def _text(self, p, x, y, s, color, font=None):
        p.setFont(font or self.font_)
        p.setPen(color)
        p.drawText(QtCore.QPointF(x, y + self._atlas.ascent), s)

    def _paint_top(self, p, cw, ch, top_h, vx):
        y = 3
        self._text(p, 5, y, self.doc.fmt.top_label(), theme.BANNER_HILITE, self.bold)
        self._text(p, vx, y, self.view.header(), theme.BANNER_HILITE, self.bold)

    def _paint_left(self, p, cw, ch, left_w, y0):
        fmt = self.doc.fmt
        p.setClipRect(0, y0, left_w, self.view.rows * ch)
        for i, off in enumerate(self.view.row_offsets()[: self.view.rows]):
            if off >= len(self.doc.dm) and i:
                break
            self._text(p, 5, y0 + i * ch, fmt.address_label(off), theme.BANNER_TEXT, self.bold)
        p.setClipping(False)

    def _paint_bottom(self, p, cw, ch, bottom_h):
        dm, fmt, view = self.doc.dm, self.doc.fmt, self.view
        y = self.height() - bottom_h + 4
        pos = view.cursor_offset()
        yellow = theme.BANNER_HILITE

        def fmtv(v, w):
            return "-" * w if v is None else f"{v:0{w}X}"

        self._text(p, cw, y, f"POS: {pos:08x}", yellow)
        if view.edit:
            self._text(p, cw, y + ch, "[edit mode]", theme.CURSOR_EDIT)
        else:
            self._text(p, cw, y + ch, "[view mode]", QtGui.QColor(0, 153, 51))
        self._text(p, 17 * cw, y, f"DWORD: {fmtv(dm.u32(pos), 8)}", yellow)
        self._text(p, 17 * cw, y + ch, f" WORD: {fmtv(dm.u16(pos), 4)}", yellow)
        self._text(p, 35 * cw, y, f"QWORD: {fmtv(dm.u64(pos), 16)}", yellow)
        self._text(p, 62 * cw, y, f"BYTE: {fmtv(dm.byte(pos), 2)}", yellow)
        p.setPen(yellow)
        for c in (15, 33, 59, 71):
            x = c * cw + 5
            p.drawLine(x, self.height() - bottom_h, x, self.height())
        rng = self.doc.sel.current(pos)
        if rng:
            self._text(p, 73 * cw, y, f"Selection: {rng[0]:x}:{rng[1] - rng[0]}", QtGui.QColor(51, 153, 255))
        else:
            self._text(p, 73 * cw, y, "<no selection>", QtGui.QColor(128, 128, 128))
        hint = fmt.status_hint(pos)
        if hint:
            self._text(p, 73 * cw, y + ch, hint, QtGui.QColor(172, 129, 255))
        extra = fmt.status_extra()
        col = 73 + 26
        if extra:
            p.setPen(yellow)
            p.drawLine(col * cw - cw // 2, self.height() - bottom_h, col * cw - cw // 2, self.height())
            for i, s in enumerate(extra[:2]):
                self._text(p, col * cw, y + i * ch, s, QtGui.QColor(128, 128, 128))
        right = f"{view.name}  {len(dm):,} bytes" + ("  *modified*" if dm.dirty else "")
        fm = QtGui.QFontMetrics(self.font_)
        self._text(p, self.width() - fm.horizontalAdvance(right) - cw, y + ch, right, QtGui.QColor(128, 128, 128))

    # ------------------------------------------------------------------ input
    def event(self, ev):
        t = ev.type()
        if t == QtCore.QEvent.Type.KeyPress and ev.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
            self.switch_view()
            return True
        if t == QtCore.QEvent.Type.ShortcutOverride and self.view.edit and self._edit_wants(ev):
            ev.accept()   # typed characters go to the editor, not to shortcuts
            return True
        return super().event(ev)

    def _edit_wants(self, ev) -> bool:
        if isinstance(self.view, HexView):
            mods = ev.modifiers() & ~Qt.KeyboardModifier.KeypadModifier
            return ev.key() in HEX_KEYS and mods in (Qt.KeyboardModifier.NoModifier,
                                                     Qt.KeyboardModifier.AltModifier,
                                                     Qt.KeyboardModifier.ShiftModifier)
        return is_plain_text(ev)

    def keyPressEvent(self, ev):
        key = ev.key()
        if key == Qt.Key.Key_F2:
            self.toggle_edit()
            return
        if key == Qt.Key.Key_Escape and (self.doc.sel.normal or self.doc.sel.anchor is not None):
            self.doc.sel.clear()
            self.update()
            return
        if self.view.key_press(ev):
            self.update()
            self.on_change()
            return
        super().keyPressEvent(ev)

    def keyReleaseEvent(self, ev):
        if not ev.isAutoRepeat() and self.view.key_release(ev):
            self.update()
            return
        super().keyReleaseEvent(ev)

    def _cell_at(self, pos: QtCore.QPointF):
        cw, ch, _t, _b, _l, x0, y0, w, h = self._geometry()
        x = pos.x() - x0 - self.view.x_margin
        y = pos.y() - y0
        if x < 0 or y < 0 or y >= h:
            return None
        return x / cw, y / ch

    def mousePressEvent(self, ev):
        self.setFocus()
        if ev.button() != Qt.MouseButton.LeftButton:
            return
        cell = self._cell_at(ev.position())
        if cell is None:
            return
        sel = self.doc.sel
        if ev.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            sel.start(self.cursor())
            self.view.click(*cell)
            sel.stop(self.cursor())
        else:
            self.view.click(*cell)
            sel.clear()
            sel.start(self.cursor())
            self._dragging = True
        self.update()

    def mouseMoveEvent(self, ev):
        if self._dragging:
            cell = self._cell_at(ev.position())
            if cell is not None:
                self.view.click(*cell)
                self.update()

    def mouseReleaseEvent(self, ev):
        if self._dragging:
            self._dragging = False
            sel = self.doc.sel
            if sel.anchor == self.cursor():
                sel.anchor = None
            else:
                sel.stop(self.cursor())
            self.update()

    def wheelEvent(self, ev):
        steps = ev.angleDelta().y() / 120
        if steps:
            self.view.wheel(int(round(steps * 3)) or (1 if steps > 0 else -1))
            self.update()

    # ------------------------------------------------------------------ commands
    def switch_view(self, index: int | None = None) -> None:
        cur = self.cursor()
        self.view.set_edit(False)
        self.vi = (self.vi + 1) % len(self.views) if index is None else index
        self._layout()
        self.view.goto(cur)
        self.update()
        self.on_change()

    def toggle_edit(self) -> None:
        v = self.view
        if v.editable:
            v.set_edit(not v.edit)
            self.update()
            self.on_change()

    def find_next(self, from_start: bool = False, backward: bool = False) -> bool:
        s = self.search.searcher
        if not s.needles:
            self.search.popup()
            return False
        cur = self.cursor()
        start = cur if backward else (cur if from_start else cur + 1)
        idx, n = s.find(self.doc.dm, start, backward)
        if idx < 0:
            return False
        self.doc.sel.set(idx, idx + n, theme.SEARCH_HIT, 0.8)
        self.goto(idx)
        return True

    def copy_hex(self) -> None:
        rng = self.doc.sel.current(self.cursor())
        if rng:
            data = self.doc.dm.read(*rng)
            QtWidgets.QApplication.clipboard().setText(data.hex())

    def paste_hex(self) -> None:
        if not self.view.edit:
            return
        data = parse_hex(QtWidgets.QApplication.clipboard().text())
        if data:
            self.doc.dm.write(self.cursor(), data)
            self.refresh()

    def cycle_hex_columns(self) -> None:
        for v in self.views:
            if isinstance(v, HexView):
                v.cycle_columns()
        self.update()

    def cycle_address_mode(self) -> None:
        self.doc.fmt.cycle_address_mode()
        self.update()

    def set_arch(self, arch_mode) -> None:
        fmt = self.doc.fmt
        fmt.disasm_arch = lambda am=arch_mode: am  # instance override
        for v in self.views:
            if isinstance(v, DisasmView):
                v.reset_engine()
        self.update()

    def show_tool(self, name: str) -> None:
        cls = {"dropper": DropperDialog, "unpack": UnpackDialog, "annotations": AnnotationsDialog}[name]
        dlg = getattr(self, name)
        if dlg is None:
            dlg = cls(self)
            setattr(self, name, dlg)
        dlg.toggle()

    def annotate(self, child: bool) -> None:
        if self.annotations is None:
            self.annotations = AnnotationsDialog(self)
        self.annotations.add_from_selection(child)


class MainWindow(QtWidgets.QMainWindow):
    windows: list["MainWindow"] = []

    def __init__(self, dm: DataModel, font: QtGui.QFont, title: str | None = None):
        super().__init__()
        self.doc = Document(dm)
        self.doc.open_buffer = self.open_buffer
        self.canvas = Canvas(self.doc, font, self)
        self.setCentralWidget(self.canvas)
        self.canvas.on_change = self._update_title
        self._title = title or os.path.basename(dm.source) or "qiew"
        self._build_menus()
        self._update_title()
        MainWindow.windows.append(self)
        log.info("format: %s", self.doc.fmt.name)

    # ------------------------------------------------------------------ menus
    def _act(self, menu, text, slot, shortcut=None, letter_ok=True):
        a = QtGui.QAction(text, self)
        if shortcut:
            if isinstance(shortcut, (list, tuple)):
                a.setShortcuts([QtGui.QKeySequence(s) for s in shortcut])
            else:
                a.setShortcut(QtGui.QKeySequence(shortcut))
        a.triggered.connect(slot)
        menu.addAction(a)
        return a

    def _build_menus(self):
        c = self.canvas
        mb = self.menuBar()
        f = mb.addMenu("&File")
        self._act(f, "&Open…", self.open_dialog, QtGui.QKeySequence.StandardKey.Open)
        self._act(f, "&Save", self.save, QtGui.QKeySequence.StandardKey.Save)
        self._act(f, "Save &As…", self.save_as, QtGui.QKeySequence.StandardKey.SaveAs)
        f.addSeparator()
        self._act(f, "&Close", self.close, QtGui.QKeySequence.StandardKey.Close)
        self._act(f, "&Quit", QtWidgets.QApplication.closeAllWindows, QtGui.QKeySequence.StandardKey.Quit)

        e = mb.addMenu("&Edit")
        self._act(e, "Toggle edit mode\tF2", c.toggle_edit)
        self._act(e, "Copy selection as hex", c.copy_hex, ["Ctrl+Ins", "Ctrl+Shift+C"])
        self._act(e, "Paste hex (edit mode)", c.paste_hex, ["Shift+Ins", "Ctrl+Shift+V"])
        e.addSeparator()
        self._act(e, "&Find…", c.search.popup, ["/", QtGui.QKeySequence.StandardKey.Find])
        self._act(e, "Find &next", lambda: c.find_next() or self._nothing(), ["N", QtGui.QKeySequence.StandardKey.FindNext])
        self._act(e, "Find &previous", lambda: c.find_next(backward=True) or self._nothing(),
                  ["B", QtGui.QKeySequence.StandardKey.FindPrevious])
        self._act(e, "&Go to…", c.gotodlg.toggle, "Alt+G")

        v = mb.addMenu("&View")
        self._act(v, "Switch view mode\tTab", c.switch_view)
        for i, view in enumerate(c.views):
            self._act(v, f"{view.name} view", lambda _=False, i=i: c.switch_view(i), f"Ctrl+{i + 1}")
        v.addSeparator()
        self._act(v, "Cycle hex columns", c.cycle_hex_columns, "F6")
        self._act(v, "Cycle address mode", c.cycle_address_mode, "F3")
        arch = v.addMenu("Disassembler architecture")
        for name, am in [("Auto (from format)", None), ("x86 16-bit", disasm.X86_16), ("x86 32-bit", disasm.X86_32),
                         ("x86 64-bit", disasm.X86_64), ("ARM", disasm.ARM), ("ARM Thumb", disasm.THUMB),
                         ("ARM64", disasm.ARM64)]:
            self._act(arch, name, lambda _=False, am=am: self._set_arch(am))
        v.addSeparator()
        self._act(v, "Bigger font", lambda: self._font_step(1), QtGui.QKeySequence.StandardKey.ZoomIn)
        self._act(v, "Smaller font", lambda: self._font_step(-1), QtGui.QKeySequence.StandardKey.ZoomOut)

        t = mb.addMenu("&Tools")
        self._act(t, "Decrypt / Encrypt…", lambda: c.show_tool("unpack"), "Shift+F4")
        self._act(t, "Dropper…", lambda: c.show_tool("dropper"), "F10")
        t.addSeparator()
        self._act(t, "Annotations", lambda: c.show_tool("annotations"), "?")
        self._act(t, "Annotate selection (top level)", lambda: c.annotate(False), "Ctrl+A")
        self._act(t, "Annotate selection (child)", lambda: c.annotate(True), "Alt+A")

        fmt = self.doc.fmt
        acts = fmt.actions()
        if acts:
            m = mb.addMenu(fmt.name.upper() if len(fmt.name) <= 4 else fmt.name.capitalize())
            for a in acts:
                self._act(m, a.text, self._wrap(a.callback), a.shortcut)

        h = mb.addMenu("&Help")
        self._act(h, "Keys…", self.show_keys, "F1")
        self._act(h, "About Qiew", self.about)

    def _wrap(self, cb):
        def run():
            cb()
            self.canvas.refresh()
        return run

    def _nothing(self):
        self.statusBar().showMessage("Nothing found.", 2000)

    def _set_arch(self, am):
        if am is None:
            self.doc.fmt.__dict__.pop("disasm_arch", None)
            for v in self.canvas.views:
                if isinstance(v, DisasmView):
                    v.reset_engine()
            self.canvas.update()
        else:
            self.canvas.set_arch(am)

    def _font_step(self, d):
        f = QtGui.QFont(self.canvas.font_)
        f.setPointSize(max(6, f.pointSize() + d))
        self.canvas.set_font(f)

    def _update_title(self):
        self.setWindowTitle(f"qiew - {self._title} [{self.doc.fmt.name}][*]")
        self.setWindowModified(self.doc.dm.dirty)

    # ------------------------------------------------------------------ file ops
    def open_dialog(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open file")
        if path:
            open_file(path, self.canvas.font_)

    def open_buffer(self, data: bytes, name: str):
        w = MainWindow(BufferDataModel(data, name), self.canvas.font_, name)
        w.resize(1000, 700)
        w.show()

    def save(self) -> bool:
        dm = self.doc.dm
        if isinstance(dm, FileDataModel):
            ok = dm.save()
            if not ok:
                QtWidgets.QMessageBox.warning(self, "Qiew", "Could not write the file (permissions?).\nUse Save As.")
            self.canvas.refresh()
            return ok
        return self.save_as()

    def save_as(self) -> bool:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save as", self.doc.dm.source)
        if not path:
            return False
        try:
            self.doc.dm.save_as(path)
        except OSError as e:
            QtWidgets.QMessageBox.warning(self, "Qiew", str(e))
            return False
        return True

    def closeEvent(self, ev):
        if self.doc.dm.dirty:
            r = QtWidgets.QMessageBox.question(
                self, "Qiew", "Do you want to save the changes?",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
                | QtWidgets.QMessageBox.StandardButton.Cancel)
            if r == QtWidgets.QMessageBox.StandardButton.Cancel:
                ev.ignore()
                return
            if r == QtWidgets.QMessageBox.StandardButton.Yes and not self.save():
                ev.ignore()
                return
        self.doc.dm.close()
        if self in MainWindow.windows:
            MainWindow.windows.remove(self)
        ev.accept()

    def show_keys(self):
        QtWidgets.QMessageBox.information(self, "Qiew keys", KEYS_HELP)

    def about(self):
        QtWidgets.QMessageBox.about(
            self, "About Qiew",
            f"<b>Qiew {__version__}</b><br>Hex / binary / disassembly viewer for reverse engineering.<br>"
            "Marius TIVADAR, GPLv2.<br>Powered by Qt (PySide6), numpy, capstone, pefile, pyelftools.")


KEYS_HELP = """\
Tab            switch view (binary / hex / disasm)
F2             toggle edit mode
arrows, PgUp/PgDn, Home/End     move
Ctrl+arrows    scroll page (Ctrl+Left/Right shift by one byte)
Ctrl+Home/End  start / end of file
Shift+move     select    Esc  clear selection
/  n  b        search, next, previous
Alt+G          go to (expressions, EP / END constants)
F3             cycle address mode (VA / RVA / FA ...)
F6             cycle hex columns
F7             go to entry point (PE / ELF)
s / e          skip run of same byte / skip to zero block
[ ]            previous / next section (PE) or partition (MBR)
0              go to overlay (PE)
Alt+H/V/I/E/S/D  PE info windows
Enter / Backspace (disasm)  follow branch / go back
Ctrl+Ins       copy selection as hex
Shift+F4       decrypt / encrypt selection
F10            dropper
Ctrl+A / Alt+A annotate selection;  ?  annotations window
(on macOS, Ctrl = Cmd and Alt = Option)
"""


def open_file(path: str, font: QtGui.QFont) -> MainWindow | None:
    try:
        dm = FileDataModel(path)
    except OSError as e:
        QtWidgets.QMessageBox.critical(None, "Qiew", f"Cannot open {path}:\n{e}")
        return None
    w = MainWindow(dm, font)
    screen = QtGui.QGuiApplication.primaryScreen().availableGeometry()
    w.resize(int(screen.width() * 0.85), int(screen.height() * 0.85))
    w.show()
    return w


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qiew", description="Hex / binary / disassembly viewer")
    parser.add_argument("files", nargs="*", help="file(s) to open")
    parser.add_argument("--font", help="font family (default: Terminus if installed, else system monospace)")
    parser.add_argument("--font-size", type=int, default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="[%(name)s] %(message)s")

    QtWidgets.QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    app.setApplicationName("qiew")
    app.setApplicationVersion(__version__)
    font = theme.pick_font(args.font, args.font_size)

    files = args.files
    if not files:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Open file")
        if not path:
            return 0
        files = [path]
    opened = [w for w in (open_file(f, font) for f in files) if w]
    if not opened:
        return 1
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
