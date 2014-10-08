from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt4 import QtGui, QtCore
from cemu import *
import sys

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

        return False

    def getBanners(self):
        return [Banners.FileAddrBanner]
