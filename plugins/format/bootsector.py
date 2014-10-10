from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt4 import QtGui, QtCore
from cemu import *
import sys

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
        self._viewMode = viewMode

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\x55\xAA', brush=self.MZbrush, pen=self.greenPen)

        self._viewMode.setTransformationEngine(self.textDecorator)
        self._viewMode.selector.addSelection((446,      446+1*16, QtGui.QBrush(QtGui.QColor(125, 75, 150)), 0.8), type=TextSelection.SelectionType.PERMANENT)
        self._viewMode.selector.addSelection((446+16,   446+2*16, QtGui.QBrush(QtGui.QColor(55, 125, 50)), 0.8), type=TextSelection.SelectionType.PERMANENT)
        self._viewMode.selector.addSelection((446+2*16, 446+3*16, QtGui.QBrush(QtGui.QColor(125, 75, 150)), 0.8), type=TextSelection.SelectionType.PERMANENT)
        self._viewMode.selector.addSelection((446+3*16, 446+4*16, QtGui.QBrush(QtGui.QColor(55, 125, 50)), 0.8), type=TextSelection.SelectionType.PERMANENT)

        return True

    def hintDisasm(self):
        return distorm3.Decode16Bits

    def hintDisasmVA(self, offset):
        return 0x7c00 + offset

    def getBanners(self):
        return [BootBanner]

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
