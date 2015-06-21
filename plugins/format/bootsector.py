import sys, os

from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt4 import QtGui, QtCore
import PyQt4

from cemu import *

import distorm3

class Bootsector(FileFormat):
    name = 'bootsector'
    priority = 4

    def recognize(self, dataModel):
        self.dataModel = dataModel
        if self.dataModel.getWORD(510) == 0xAA55:
            return True

        return False

    def init(self, viewMode):
        self.viewMode = viewMode

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\x55\xAA', brush=self.MZbrush, pen=self.greenPen)

        self.viewMode.setTransformationEngine(self.textDecorator)
        self.viewMode.selector.addSelection((446,      446+1*16, QtGui.QBrush(QtGui.QColor(125, 75, 150)), 0.8), type=TextSelection.SelectionType.PERMANENT)
        self.viewMode.selector.addSelection((446+16,   446+2*16, QtGui.QBrush(QtGui.QColor(55, 125, 50)), 0.8), type=TextSelection.SelectionType.PERMANENT)
        self.viewMode.selector.addSelection((446+2*16, 446+3*16, QtGui.QBrush(QtGui.QColor(125, 75, 150)), 0.8), type=TextSelection.SelectionType.PERMANENT)
        self.viewMode.selector.addSelection((446+3*16, 446+4*16, QtGui.QBrush(QtGui.QColor(55, 125, 50)), 0.8), type=TextSelection.SelectionType.PERMANENT)

        return True

    def hintDisasm(self):
        return distorm3.Decode16Bits

    def hintDisasmVA(self, offset):
        return 0x7c00 + offset

    def disasmVAtoFA(self, va):
        return va - 0x7c00

    def getBanners(self):
        return [BootBanner, Banners.TopBanner]

    def _showit(self):
        if not self.w.isVisible():
            self.w.show()
        else:
            self.w.hide()

    def _g_showit(self):
        if not self.g.isVisible():
            self.g.show()
        else:
            self.g.hide()


    def _writeData(self, w):
        Types = {0x07 : 'NTFS',
                 0x06 : 'FAT16',
                 0x0B : 'FAT32',
                 0x0F : 'Extended',
                 0x17 : 'Hidden NTFS',
                 0x82 : 'Linux Swap',
                 0x83 : 'Linux',
                 0xDE : 'Dell diagnostic'}

        # bootable
        active = None

        for i in range(4):
            b = '0x{0}'.format(self.dataModel.getBYTE(446 + i*16, asString=True))
            if b == '0x80':
                active = i

            item = QtGui.QTableWidgetItem(b)
            item.setTextAlignment(QtCore.Qt.AlignRight)
            if active and i == active:
                item.setTextColor(QtGui.QColor('green'))

            w.ui.tableWidget.setItem(0, i, item)

        # type
        for i in range(4):
            b = '0x{0}'.format(self.dataModel.getBYTE(446 + i*16 + 4, asString=True))
            if int(b, 16) in Types:
                b = Types[int(b,16)]

            item = QtGui.QTableWidgetItem(b)
            item.setTextAlignment(QtCore.Qt.AlignRight)
            if active and i == active:
                item.setTextColor(QtGui.QColor('green'))

            w.ui.tableWidget.setItem(1, i, item)

        # CHS Start
        for i in range(4):
            b = '0x{0}'.format(self.dataModel.getDWORD(446 + i*16 + 1) & 0x00FFFFFF)

            item = QtGui.QTableWidgetItem(b)
            item.setTextAlignment(QtCore.Qt.AlignRight)
            if active and i == active:
                item.setTextColor(QtGui.QColor('green'))

            w.ui.tableWidget.setItem(2, i, item)

        # CHS End
        for i in range(4):
            b = '0x{0}'.format(self.dataModel.getDWORD(446 + i*16 + 5) & 0x00FFFFFF)

            item = QtGui.QTableWidgetItem(b)
            item.setTextAlignment(QtCore.Qt.AlignRight)
            if active and i == active:
                item.setTextColor(QtGui.QColor('green'))

            w.ui.tableWidget.setItem(3, i, item)

        # LBA Start
        for i in range(4):
            b = '0x{0}'.format(self.dataModel.getDWORD(446 + i*16 + 8))

            item = QtGui.QTableWidgetItem(b)
            item.setTextAlignment(QtCore.Qt.AlignRight)
            if active and i == active:
                item.setTextColor(QtGui.QColor('green'))

            w.ui.tableWidget.setItem(4, i, item)

        # LBA End
        for i in range(4):
            b = '0x{0}'.format(self.dataModel.getDWORD(446 + i*16 + 0xC))

            item = QtGui.QTableWidgetItem(b)
            item.setTextAlignment(QtCore.Qt.AlignRight)
            if active and i == active:
                item.setTextColor(QtGui.QColor('green'))

            w.ui.tableWidget.setItem(5, i, item)

    def registerShortcuts(self, parent):
        self._parent = parent
        self.w = WHeaders(parent, self)
        self._writeData(self.w)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+P"), parent, self._showit, self._showit)

        self.g = MyDialogGoto(parent, self)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._g_showit, self._g_showit)


class MyDialogGoto(DialogGoto):
    def fa(self, offset):
        return offset - 0x7c00


class WHeaders(QtGui.QDialog):
    
    def __init__(self, parent, plugin):
        super(WHeaders, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(WHeaders, self).show

        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt4.uic.loadUi(os.path.join(root, 'plugins', 'format', 'bootsector.ui'), baseinstance=self)

        self.initUI()

    def show(self):

        # TODO: remember position? resize plugin windows when parent resize?
        pwidth = self.parent.parent.size().width()
        pheight = self.parent.parent.size().height()

        width = self.ui.tableWidget.size().width()+15
        height = self.ui.tableWidget.size().height()+15

        self.setGeometry(pwidth - width - 15, pheight - height, width, height)
        self.setFixedSize(width, height)

        self.oshow()

    def initUI(self):      

        self.setSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)

        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+P"), self, self.close, self.close)


class BootBanner(Banners.FileAddrBanner):
    def draw(self):
        qp = QtGui.QPainter()

        offset = 0x7c00 + self.viewMode.getPageOffset()
        columns, rows = self.viewMode.getGeometry()

        qp.begin(self.qpix)
        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)

        for i in range(rows):
            s = '{0:08x}'.format(offset)
            qp.drawText(0+5, (i+1) * self.fontHeight, s)
            columns = self.viewMode.getColumnsbyRow(i)
            offset += columns


        qp.end()
