from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt4 import QtGui, QtCore
import PyQt4
from cemu import *

import sys, os

class Binary(FileFormat):
    name = 'binary'
    priority = 0

    def recognize(self, dataModel):
        self.dataModel = dataModel
        return True

    def init(self, viewMode):
        self.viewMode = viewMode

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))        


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'MZ', brush=self.MZbrush, pen=self.greenPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'PE\x00\x00', brush=self.MZbrush, pen=self.greenPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\xFF\x15', additionalLength=4, brush=self.grayBrush, pen=self.whitePen)
        self.textDecorator = HighlightWideChar(self.textDecorator)

        self.viewMode.setTransformationEngine(self.textDecorator)
        return True

    def hintDisasm(self):
        return distorm3.Decode16Bits

    def hintDisasmVA(self, offset):
        return offset

    def disasmVAtoFA(self, va):
        return va
        
    def getBanners(self):
        return [Banners.FileAddrBanner(self.dataModel, self.viewMode), Banners.TopBanner(self.dataModel, self.viewMode)]

    def registerShortcuts(self, parent):
        self._parent = parent
        self.w = DialogGoto(parent, self)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._showit, self._showit)

    def _showit(self):
        if not self.w.isVisible():
            self.w.show()
        else:
            self.w.hide()


