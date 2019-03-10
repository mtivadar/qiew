from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt5 import QtGui, QtCore, QtWidgets
import PyQt5
from cemu import *

import sys, os
import DisasmViewMode

import fs_ntfs.fs_ntfs
from fs_ntfs.fs_ntfs import ntfs

class FsNtfs(FileFormat):
    name = 'fs_ntfs'
    priority = 5

    lock = 0
    def recognize(self, dataModel):
        self.dataModel = dataModel
        if self.dataModel.getWORD(510) != 0xAA55:
            # check if valid boot record
            return False

        if self.dataModel.getDWORD(3) != 0x5346544e:
            # check if NTFS magic
            return False

        # this will actually hit the same as mbr plugin, but this one has bigger priority

        return True

    def _encodeutf16(self, s):
        return '\x00'.join(s)

    def init(self, viewMode, parent):
        self._viewMode = viewMode

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.INDXbrush = QtGui.QBrush(QtGui.QColor(128, 128, 0))
        self.SpecialFilebrush = QtGui.QBrush(QtGui.QColor(128, 0, 128))
        self.yellowPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(0, 255, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))        


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'MZ', brush=self.MZbrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'PE\x00\x00', brush=self.MZbrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\x55\xAA', brush=self.MZbrush, pen=self.greenPen)


        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$MFT'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$MFTMirr'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Boot'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$LogFile'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$BadClus'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$AttrDef'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Bitmap'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Extend'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Secure'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Volume'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$UpCase'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Reparse'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Repair'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Config'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Deleted'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Repair'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Quota'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$TxfLog'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$TxfLog.blf'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$RmMetadata'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$I30'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$ObjId'), brush=self.SpecialFilebrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, self._encodeutf16('$Tops'), brush=self.SpecialFilebrush, pen=self.yellowPen)



        self.textDecorator = HighlightPrefix(self.textDecorator, 'FILE', brush=self.MZbrush, pen=self.yellowPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'INDX', brush=self.INDXbrush, pen=self.greenPen)


        # first jump
        self.textDecorator = RangePen(self.textDecorator, 0, 2, pen=self.yellowPen, ignoreHighlights=True)

        # ntfs
        self.textDecorator = RangePen(self.textDecorator, 3, 8, pen=self.greenPen, ignoreHighlights=True)


        self.textDecorator = HighlightWideChar(self.textDecorator)

        self._viewMode.setTransformationEngine(self.textDecorator)

        # $BOOT
        self._viewMode.selector.addSelection((0x0B, 0x48 + 8, QtGui.QBrush(QtGui.QColor(125, 175, 150)), 0.4), type=TextSelection.SelectionType.PERMANENT)

        
        self.ntfs = fs_ntfs.fs_ntfs.ntfs.NTFS(self.dataModel)

    def hintDisasm(self):
        return DisasmViewMode.Disasm_x86_16bit

    def hintDisasmVA(self, offset):
        return offset

    def disasmVAtoFA(self, va):
        return va
        
    def getBanners(self):
        return [Banners.FileAddrBanner(self.dataModel, self._viewMode), Banners.TopBanner(self.dataModel, self._viewMode), Banners.BottomBanner(self.dataModel, self._viewMode)]

    def registerShortcuts(self, parent):
        self._parent = parent
        self.w = DialogGoto(parent, self)
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._showit, self._showit)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("s"), parent, self.skip_chars, self.skip_chars)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("e"), parent, self.skip_block, self.skip_block)]

        # goto $MFT
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+M"), parent, self._goto_mft, self._goto_mft)]

        # goto root (.)
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+R"), parent, self._goto_root, self._goto_root)]


    def _goto_root(self):
        fobj = self.ntfs.mft.get_file_record(5)

        if fobj:
            self._viewMode.selector.addSelection((fobj.offset, fobj.offset + fobj.size, QtGui.QBrush(QtGui.QColor(125, 175, 150)), 0.4), type=TextSelection.SelectionType.IF_CURSOR_IN_RANGE)
            self._viewMode.goTo(fobj.offset)

    def _goto_mft(self):
        fobj = self.ntfs.mft.get_file_record(0)

        if fobj:
            self._viewMode.selector.addSelection((fobj.offset, fobj.offset + fobj.size, QtGui.QBrush(QtGui.QColor(125, 175, 150)), 0.4), type=TextSelection.SelectionType.IF_CURSOR_IN_RANGE)
            self._viewMode.goTo(fobj.offset)




    def _showit(self):
        if not self.w.isVisible():
            self.w.show()
        else:
            self.w.hide()

    def skip_block(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        x = self.dataModel.getData().find(b'\x00'*8, off)
        if x == -1:
            x = off


        if x == off:
            if x < sizeOfData - 1:
                x += 1

        self._viewMode.goTo(x)

        return

    def skip_chars(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off + 1

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        # skip bytes of current value
#        import time

        BYTES = 512
#        k = time.time()
        b = self.dataModel.getStream(off, off + 1)
        z = b * BYTES

        # compare stream of bytes
        z = self.dataModel.getStream(off, off+BYTES)
        while x < sizeOfData - BYTES and self.dataModel.getStream(x, x + BYTES) == z:
            x += BYTES

        while x < sizeOfData - 1 and self.dataModel.getBYTE(x) == ord(b):
            x += 1

#        print time.time() - k

        self._viewMode.goTo(x)
