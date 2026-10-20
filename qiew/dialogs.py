"""Auxiliary windows: search, goto, dropper, decrypt/encrypt, annotations."""
from __future__ import annotations

import ast
import json
import operator as op
import os
import random
from typing import TYPE_CHECKING

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

from . import theme
from .selection import SelType

if TYPE_CHECKING:  # pragma: no cover
    from .app import Canvas


def _place_bottom_right(dlg: QtWidgets.QWidget, parent: QtWidgets.QWidget | None) -> None:
    if parent is None:
        return
    g = parent.window().geometry()
    dlg.adjustSize()
    dlg.move(g.right() - dlg.width() - 20, g.bottom() - dlg.height() - 40)


class ToolDialog(QtWidgets.QDialog):
    """Small non-modal tool window that toggles with its shortcut."""

    def __init__(self, canvas: "Canvas", title: str):
        super().__init__(canvas.window())
        self.canvas = canvas
        self.setWindowTitle(title)
        self.setWindowFlag(Qt.WindowType.Tool, True)

    def toggle(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.popup()

    def popup(self) -> None:
        _place_bottom_right(self, self.canvas)
        self.show()
        self.raise_()
        self.activateWindow()

    def done_and_refresh(self) -> None:
        self.canvas.refresh()


# ============================================================== search
def parse_hex(text: str) -> bytes | None:
    t = text.replace(" ", "").replace("0x", "").replace(",", "")
    if len(t) % 2:
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


class Searcher:
    """Find bytes; text searches also look for the UTF-16LE form."""

    def __init__(self) -> None:
        self.needles: list[bytes] = []
        self.last = -1

    def set(self, needle: bytes, wide: bool) -> None:
        self.needles = [needle]
        if wide:
            try:
                w = needle.decode("utf-8").encode("utf-16-le")
                if w != needle:
                    self.needles.append(w)
            except UnicodeDecodeError:
                pass

    def find(self, dm, start: int, backward: bool = False) -> tuple[int, int]:
        best, blen = -1, 0
        for n in self.needles:
            if not n:
                continue
            i = dm.rfind(n, 0, start) if backward else dm.find(n, start)
            if i != -1 and (best == -1 or (i > best if backward else i < best)):
                best, blen = i, len(n)
        self.last = best
        return best, blen


class SearchDialog(ToolDialog):
    def __init__(self, canvas):
        super().__init__(canvas, "Search")
        self.searcher = Searcher()
        self.edit = QtWidgets.QLineEdit()
        self.hex = QtWidgets.QCheckBox("hex")
        btn = QtWidgets.QPushButton("Search")
        btn.setDefault(True)
        lay = QtWidgets.QGridLayout(self)
        lay.addWidget(self.edit, 0, 0, 1, 2)
        lay.addWidget(self.hex, 1, 0)
        lay.addWidget(btn, 1, 1)
        btn.clicked.connect(self.search)
        self.edit.returnPressed.connect(self.search)
        self.setFixedWidth(360)

    def popup(self):
        g = self.canvas.window().geometry()
        self.adjustSize()
        self.move(g.center().x() - self.width() // 2, g.center().y() - self.height() // 2)
        self.show()
        self.raise_()
        self.activateWindow()
        self.edit.setFocus()
        self.edit.selectAll()

    def search(self) -> None:
        text = self.edit.text()
        if not text:
            return
        if self.hex.isChecked():
            needle = parse_hex(text)
            if needle is None:
                QtWidgets.QMessageBox.warning(self, "Qiew", "Hex string with errors.")
                return
            self.searcher.set(needle, wide=False)
        else:
            self.searcher.set(text.encode("utf-8"), wide=True)
        self.hide()
        if not self.canvas.find_next(from_start=True):
            QtWidgets.QMessageBox.information(self.canvas, "Qiew", "Nothing found.")


# ============================================================== goto
_OPS = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.floordiv,
        ast.FloorDiv: op.floordiv, ast.Mod: op.mod, ast.Pow: op.pow, ast.USub: op.neg,
        ast.UAdd: op.pos, ast.BitAnd: op.and_, ast.BitOr: op.or_, ast.BitXor: op.xor,
        ast.LShift: op.lshift, ast.RShift: op.rshift}


def eval_expr(expr: str, constants: dict[str, int]) -> int:
    """Safe integer expression: numbers (hex ok), + - * / % ** & | ^ << >>, constants."""
    expr = expr.strip()
    # bare hex without 0x (e.g. "401000") is common in RE work
    if expr and all(c in "0123456789abcdefABCDEF" for c in expr) and any(c.isalpha() for c in expr):
        expr = "0x" + expr

    def ev(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.operand))
        if isinstance(node, ast.Name):
            k = node.id.upper()
            if k in constants:
                return int(constants[k])
            # allow bare hex identifiers like "ff" or "dead"
            try:
                return int(node.id, 16)
            except ValueError:
                pass
        raise ValueError(f"bad expression: {ast.dump(node)}")

    return int(ev(ast.parse(expr, mode="eval").body))


class GotoDialog(ToolDialog):
    def __init__(self, canvas):
        super().__init__(canvas, "GoTo")
        self.combo = QtWidgets.QComboBox()
        self.edit = QtWidgets.QLineEdit()
        self.edit.setPlaceholderText("expression, e.g. EP+0x10, 401000, END-0x200")
        self.label = QtWidgets.QLabel(" ")
        lay = QtWidgets.QGridLayout(self)
        lay.addWidget(self.combo, 0, 0)
        lay.addWidget(self.edit, 0, 1)
        lay.addWidget(self.label, 1, 0, 1, 2)
        self.edit.returnPressed.connect(self.go)
        self.setMinimumWidth(420)

    def popup(self):
        fmt = self.canvas.doc.fmt
        cur = self.combo.currentText()
        self.combo.clear()
        self.combo.addItems(list(fmt.goto_spaces()))
        if cur:
            i = self.combo.findText(cur)
            if i >= 0:
                self.combo.setCurrentIndex(i)
        super().popup()
        self.edit.setFocus()
        self.edit.selectAll()

    def go(self):
        fmt = self.canvas.doc.fmt
        space = self.combo.currentText()
        try:
            value = eval_expr(self.edit.text(), fmt.goto_constants(space))
        except Exception:  # noqa: BLE001
            self.label.setText("error.")
            return
        self.label.setText(f"{value:#x} ({value})")
        off = fmt.goto_spaces()[space](value)
        if off is None:
            self.label.setText(f"{value:#x}: not mapped in file")
            return
        self.canvas.goto(off)


# ============================================================== dropper
class DropperDialog(ToolDialog):
    """Dump selection/whole file as binary, hex text, or carve embedded PEs."""

    def __init__(self, canvas):
        super().__init__(canvas, "Dropper")
        src = QtWidgets.QGroupBox("From")
        self.rsel = QtWidgets.QRadioButton("Selection")
        self.rwf = QtWidgets.QRadioButton("Whole file")
        self.rsel.setChecked(True)
        v = QtWidgets.QVBoxLayout(src)
        v.addWidget(self.rsel)
        v.addWidget(self.rwf)
        typ = QtWidgets.QGroupBox("Type")
        self.rbin = QtWidgets.QRadioButton("Binary")
        self.rhex = QtWidgets.QRadioButton("Hex")
        self.rpe = QtWidgets.QRadioButton("PE (carve MZ)")
        self.rbin.setChecked(True)
        v = QtWidgets.QVBoxLayout(typ)
        for w in (self.rbin, self.rhex, self.rpe):
            v.addWidget(w)
        ok = QtWidgets.QPushButton("Ok")
        ok.clicked.connect(self.drop)
        lay = QtWidgets.QGridLayout(self)
        lay.addWidget(src, 0, 0)
        lay.addWidget(typ, 0, 1)
        lay.addWidget(ok, 1, 1)

    def _base_name(self) -> str | None:
        src = self.canvas.doc.dm.source
        if src and os.path.isabs(src) and os.path.isdir(os.path.dirname(src)):
            return src
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Drop to", src or "dropped")
        return path or None

    def drop(self):
        dm = self.canvas.doc.dm
        if self.rwf.isChecked():
            a, b = 0, len(dm)
        else:
            rng = self.canvas.doc.sel.current()
            if not rng:
                QtWidgets.QMessageBox.information(self, "Qiew", "No selection.")
                return
            a, b = rng
        base = self._base_name()
        if not base:
            return
        written = []
        data = dm.read(a, b)
        try:
            if self.rbin.isChecked():
                p = base + ".drop"
                with open(p, "wb") as f:
                    f.write(data)
                written.append(p)
            elif self.rhex.isChecked():
                p = base + ".drop.hex"
                with open(p, "w", encoding="ascii") as f:
                    for i in range(0, len(data), 20):
                        f.write(" ".join(f"{x:02X}" for x in data[i:i + 20]) + "\n")
                written.append(p)
            else:
                written += carve_pe(data, base)
        except OSError as e:
            QtWidgets.QMessageBox.warning(self, "Qiew", f"Write failed: {e}")
            return
        self.hide()
        msg = "\n".join(written) if written else "nothing dropped"
        QtWidgets.QMessageBox.information(self.canvas, "Qiew", f"Done:\n{msg}")


def carve_pe(data: bytes, base: str) -> list[str]:
    """Extract every embedded MZ/PE (except at offset 0) into separate files."""
    import pefile

    out = []
    idx = data.find(b"MZ", 1)
    n = 0
    while idx != -1:
        try:
            pe = pefile.PE(data=data[idx:], fast_load=True)
            end = pe.OPTIONAL_HEADER.SizeOfHeaders
            for s in pe.sections:
                end = max(end, s.PointerToRawData + s.SizeOfRawData)
            if idx + end <= len(data):
                p = f"{base}.drop.{n}.mzpe"
                with open(p, "wb") as f:
                    f.write(data[idx:idx + end])
                out.append(p)
                n += 1
        except pefile.PEFormatError:
            pass
        idx = data.find(b"MZ", idx + 2)
    return out


# ============================================================== unpack
class UnpackDialog(ToolDialog):
    def __init__(self, canvas):
        super().__init__(canvas, "Decrypt/Encrypt")
        from .unpack import all_plugins

        self.plugins = [cls() for cls in all_plugins()]
        self.list = QtWidgets.QListWidget()
        self.stack = QtWidgets.QStackedWidget()
        for p in self.plugins:
            self.list.addItem(p.name)
            self.stack.addWidget(p.build_ui(self))
        self.list.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.list.setFixedWidth(120)
        proceed = QtWidgets.QPushButton("Proceed")
        proceed.clicked.connect(self.proceed)
        self.status = QtWidgets.QLabel("operates on the current selection")
        self.status.setStyleSheet("color: gray")
        lay = QtWidgets.QGridLayout(self)
        lay.addWidget(self.list, 0, 0, 2, 1)
        lay.addWidget(self.stack, 0, 1)
        bottom = QtWidgets.QHBoxLayout()
        bottom.addWidget(self.status, 1)
        bottom.addWidget(proceed)
        lay.addLayout(bottom, 1, 1)
        if self.plugins:
            self.list.setCurrentRow(0)

    def proceed(self):
        i = self.list.currentRow()
        if i < 0:
            return
        doc = self.canvas.doc
        rng = doc.sel.current()
        p = self.plugins[i]
        if p.needs_selection and not rng:
            self.status.setText("select something first")
            return
        try:
            msg = p.proceed(doc, rng, self)
        except Exception as e:  # noqa: BLE001
            msg = f"error: {e}"
        self.status.setText(msg or "done")
        self.canvas.refresh()


# ============================================================== annotations
class ColorButton(QtWidgets.QPushButton):
    colorChanged = QtCore.Signal(QtGui.QColor)

    def __init__(self, color: QtGui.QColor):
        super().__init__()
        self.setMaximumWidth(32)
        self.set_color(color)
        self.clicked.connect(self._pick)

    def set_color(self, c: QtGui.QColor) -> None:
        self._color = QtGui.QColor(c)
        self.setStyleSheet(f"background-color: {self._color.name()};")

    def color(self) -> QtGui.QColor:
        return self._color

    def _pick(self):
        c = QtWidgets.QColorDialog.getColor(self._color, self)
        if c.isValid():
            self.set_color(c)
            self.colorChanged.emit(c)


class AnnotationsDialog(ToolDialog):
    """Name byte ranges, colour them, describe them; save/load as JSON."""

    COLS = ["Name", "Offset", "Size", "Value", "Description", "Color"]
    A_ROLE = Qt.ItemDataRole.UserRole

    def __init__(self, canvas):
        super().__init__(canvas, "Annotations")
        self._n = 0
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setDragDropMode(QtWidgets.QAbstractItemView.DragDropMode.InternalMove)
        self.tree.itemChanged.connect(self._changed)
        self.tree.currentItemChanged.connect(self._selected)
        self.tree.installEventFilter(self)
        load = QtWidgets.QPushButton("Load")
        save = QtWidgets.QPushButton("Save")
        load.clicked.connect(self.load)
        save.clicked.connect(self.save)
        lay = QtWidgets.QVBoxLayout(self)
        lay.addWidget(self.tree)
        h = QtWidgets.QHBoxLayout()
        h.addStretch(1)
        h.addWidget(load)
        h.addWidget(save)
        lay.addLayout(h)
        self.resize(640, 320)

    # ------------------------------------------------------------ editing
    def add_from_selection(self, child: bool) -> None:
        rng = self.canvas.doc.sel.current(self.canvas.cursor())
        if not rng:
            return
        color = QtGui.QColor(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        self.add(rng[0], rng[1], color, f"field_{self._n}", "", child, 0.4 if child else 0.25)
        self._n += 1
        if not self.isVisible():
            self.popup()

    def add(self, a, b, color, name, desc, child, opacity=0.4, parent_item=None):
        doc = self.canvas.doc
        dm = doc.dm
        size = b - a
        value = {1: dm.byte, 2: dm.u16, 4: dm.u32, 8: dm.u64}.get(size)
        value = f"{value(a):X}" if value else repr(dm.read(a, min(b, a + 32)))
        doc.sel.add(a, b, color, opacity, SelType.PERMANENT)
        it = QtWidgets.QTreeWidgetItem([name, hex(a), hex(size), value, desc, ""])
        it.setFlags(it.flags() | Qt.ItemFlag.ItemIsEditable)
        it.setData(0, self.A_ROLE, (a, b, opacity))
        self.tree.blockSignals(True)
        target = parent_item
        if target is None and child:
            target = self.tree.currentItem() or self.tree.topLevelItem(0)
        if target is not None:
            target.addChild(it)
            target.setExpanded(True)
        else:
            self.tree.addTopLevelItem(it)
        self.tree.blockSignals(False)
        btn = ColorButton(color)
        btn.colorChanged.connect(lambda c, item=it: self._recolor(item, c))
        self.tree.setItemWidget(it, 5, btn)
        self.canvas.refresh()
        return it

    def _recolor(self, it, color):
        a, b, opacity = it.data(0, self.A_ROLE)
        sel = self.canvas.doc.sel
        sel.remove(a, b)
        sel.add(a, b, color, opacity)
        self.canvas.refresh()

    def _changed(self, it, col):
        # only Name / Description are meaningful edits; restore the others
        if col in (1, 2, 3):
            a, b, _ = it.data(0, self.A_ROLE)
            self.tree.blockSignals(True)
            it.setText(1, hex(a))
            it.setText(2, hex(b - a))
            self.tree.blockSignals(False)

    def _selected(self, cur, _prev):
        if cur is None:
            return
        a, b, _ = cur.data(0, self.A_ROLE)
        self.canvas.doc.sel.set(a, b, theme.SELECTION, 0.2)
        self.canvas.goto(a)

    def eventFilter(self, obj, ev):
        if obj is self.tree and ev.type() == QtCore.QEvent.Type.KeyPress and ev.key() == Qt.Key.Key_Delete:
            it = self.tree.currentItem()
            if it is not None:
                self._remove(it)
            return True
        return super().eventFilter(obj, ev)

    def _remove(self, it):
        for i in range(it.childCount()):
            self._remove(it.child(i))
        a, b, _ = it.data(0, self.A_ROLE)
        self.canvas.doc.sel.remove(a, b)
        parent = it.parent()
        if parent is not None:
            parent.removeChild(it)
        else:
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(it))
        self.canvas.refresh()

    # ------------------------------------------------------------ persistence
    def _dump(self, it) -> dict:
        a, b, opacity = it.data(0, self.A_ROLE)
        btn = self.tree.itemWidget(it, 5)
        return {"name": it.text(0), "offset": a, "size": b - a, "description": it.text(4),
                "color": btn.color().name() if btn else "#00ff00", "opacity": opacity,
                "children": [self._dump(it.child(i)) for i in range(it.childCount())]}

    def save(self):
        src = self.canvas.doc.dm.source or "annotations"
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save annotations", src + ".qiew.json",
                                                        "Qiew annotations (*.json)")
        if not path:
            return
        data = [self._dump(self.tree.topLevelItem(i)) for i in range(self.tree.topLevelItemCount())]
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "annotations": data}, f, indent=2)

    def load(self):
        src = self.canvas.doc.dm.source or ""
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load annotations", os.path.dirname(src),
                                                        "Qiew annotations (*.json)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> None:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        def walk(nodes, parent):
            for n in nodes:
                a = int(n["offset"])
                it = self.add(a, a + int(n["size"]), QtGui.QColor(n.get("color", "#00ff00")),
                              n.get("name", ""), n.get("description", ""), parent is not None,
                              float(n.get("opacity", 0.4)), parent)
                walk(n.get("children", []), it)

        walk(data.get("annotations", []), None)
        self._n = max(self._n, sum(1 for _ in self.tree.findItems("", Qt.MatchFlag.MatchContains | Qt.MatchFlag.MatchRecursive)))
