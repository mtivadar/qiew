"""Offscreen GUI smoke tests (QT_QPA_PLATFORM=offscreen)."""
from PySide6 import QtCore
from PySide6.QtTest import QTest

K = QtCore.Qt.Key


def _open(qapp, path):
    from qiew import app, theme

    w = app.MainWindow(app.FileDataModel(path), theme.pick_font())
    w.resize(1200, 700)
    w.show()
    qapp.processEvents()
    return w


def test_pe_document(qapp, pe_file):
    w = _open(qapp, pe_file)
    c = w.canvas
    fmt = c.doc.fmt
    assert fmt.name == "pe"
    assert fmt.entry_point() == 0x200
    assert fmt.va(0x200) == 0x401000 and fmt.fa(0x401010) == 0x210
    assert fmt.overlay == 0x400
    assert fmt.status_hint(0x400) == "Overlay"
    assert fmt.string_at_va(0x401010) == "Hello qiew world"

    QTest.keyClick(c, K.Key_F7)
    assert c.cursor() == 0x200
    for _ in range(3):                         # bin -> hex -> disasm -> bin
        QTest.keyClick(c, K.Key_Tab)
        c.grab()
        assert c.cursor() == 0x200
        if c.vi == 2:
            lines = c.view.lines
            assert lines[0].mnemonic == "push" and lines[0].refstr == "Hello qiew world"
    w.close()


def test_navigation_and_selection(qapp, pe_file):
    w = _open(qapp, pe_file)
    c = w.canvas
    c.switch_view(1)                           # hex, 16 columns
    QTest.keyClick(c, K.Key_Down)
    QTest.keyClick(c, K.Key_Right, QtCore.Qt.KeyboardModifier.ShiftModifier)
    assert c.cursor() == 17
    assert c.doc.sel.current() == (16, 18)
    QTest.keyClick(c, K.Key_End, QtCore.Qt.KeyboardModifier.ControlModifier)
    assert c.cursor() == len(c.doc.dm) - 1
    QTest.keyClick(c, K.Key_Home, QtCore.Qt.KeyboardModifier.ControlModifier)
    assert c.cursor() == 0 and c.view.offset == 0
    QTest.keyClick(c, K.Key_PageDown)
    assert c.view.offset == c.view.page_len or c.view.offset == c.view.max_offset()
    w.close()


def test_hex_edit(qapp, pe_file):
    w = _open(qapp, pe_file)
    c = w.canvas
    c.switch_view(1)
    c.goto(0x10)
    QTest.keyClick(c, K.Key_F2)
    assert c.view.edit
    QTest.keyClicks(c, "ab")
    assert c.doc.dm.byte(0x10) == 0xAB and c.cursor() == 0x11
    assert c.doc.dm.dirty
    QTest.keyClick(c, K.Key_F2)
    c.doc.dm.modified.clear()   # avoid the "save changes?" prompt
    w.close()


def test_bootsector(qapp, mbr_file):
    w = _open(qapp, mbr_file)
    fmt = w.canvas.doc.fmt
    assert fmt.name == "bootsector"
    p = fmt.partitions()[0]
    assert p["bootable"] and p["type"] == "NTFS/exFAT"
    assert fmt.va(0) == 0x7C00
    w.close()


def test_disasm_scroll_back(qapp, pe_file):
    w = _open(qapp, pe_file)
    c = w.canvas
    c.goto(0x200)
    c.switch_view(2)
    QTest.keyClick(c, K.Key_Down)
    QTest.keyClick(c, K.Key_Down, QtCore.Qt.KeyboardModifier.ControlModifier)
    off = c.view.offset
    QTest.keyClick(c, K.Key_Up, QtCore.Qt.KeyboardModifier.ControlModifier)
    assert c.view.offset == 0x200 and off == 0x205
    w.close()


def test_disasm_backtrack_without_history(qapp, pe_file):
    w = _open(qapp, pe_file)
    c = w.canvas
    c.switch_view(2)
    c.goto(0x205)                 # jump straight to the 'ret'
    c.view._trail.clear()
    QTest.keyClick(c, K.Key_Up, QtCore.Qt.KeyboardModifier.ControlModifier)
    assert c.view.offset in (0x200, 0x202)   # both are valid x86 decodings
    w.close()
