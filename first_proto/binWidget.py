#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
author: Marius TIVADAR
date: 02/2013
"""

import sys
from io import *
from PyQt5 import QtGui, QtCore, QtWidgets
import string
import mmap
import re
import binascii


class ConsoleEmulator():
    def __init__(self, qp, rows, cols):
        self.qp = qp
        self._x = 0
        self._y = 0
        self._rows = rows
        self._cols = cols

        fm = QtGui.QFontMetrics(self.qp.font())
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

    def incrementPosition(self):
        if self._x < self._cols - 1:
            self._x += 1
        else:
            self._x = 0
            self._y += 1


    def _validatePosition(self, x, y):
        if x >= self._cols:
            raise Exception("x > cols")

        if y >= self._rows:
            raise Exception("y > rows")

        return True

    def write(self, s):
        for c in s:
            if self._validatePosition(self._x, self._y):
                self.qp.drawText(self._x * self.fontWidth, self.fontHeight + self._y * self.fontHeight, c)
                self.incrementPosition()        

    def getXY(self):
        return (self._x, self._y)

    def writeAt(self, x, y, s):
        self.gotoXY(x, y)
        self.write(s)

    def writeLn(self):
        if True:#self._validatePosition(self._x, self._y):
            self._y += 1
            self._x = 0

    def gotoXY(self, x, y):
        if self._validatePosition(x, y):
            self._x = x
            self._y = y


class Observer:
    def update_geometry(self):
        NotImplementedError('method not implemented.')

class DataModel(Observer):
    def __init__(self, data):
        self.dataOffset = 0
        self.rows = self.cols = 0
        self.data = data

    def inLimits(self, x):
        if x >= 0 and x < len(self.data):
            return True

        return False

    def slide(self, off):
        if self.inLimits(self.dataOffset + off):
            self.dataOffset += off

    def update_geometry(self, rows, cols):
        self.rows = rows
        self.cols = cols

    def slideLine(self, factor):
        self.slide(factor*self.cols)

    def slidePage(self, factor):
        self.slide(factor*self.cols*self.rows)

    def slideToLastPage(self):
        self.dataOffset = len(self.data) - self.cols*self.rows

    def slideToFirstPage(self):
        self.dataOffset = 0

    def getDisplayablePage(self):
        return bytearray(self.data[self.dataOffset:self.dataOffset + self.rows*self.cols])

    def getQWORD(self, offset, asString=False):
        if offset + 8 > len(self.data):
            return None

        b = bytearray(self.data[offset:offset+8])

        d = ((b[7] << 56) | (b[6] << 48) | (b[5] << 40) | (b[4] << 32) | (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | (b[0])) & 0xFFFFFFFFFFFFFFFF

        if not asString:        
            return d

        s = '{0:016X}'.format(d)
        
        return s

    def getDWORD(self, offset, asString=False):
        if offset + 4 > len(self.data):
            return None

        b = bytearray(self.data[offset:offset+4])

        d = ((b[3] << 24) | (b[2] << 16) | (b[1] << 8) | (b[0])) & 0xFFFFFFFF

        if not asString:        
            return d

        s = '{0:08X}'.format(d)
        
        return s

    def getWORD(self, offset, asString=False):
        if offset + 2 > len(self.data):
            return None

        b = bytearray(self.data[offset:offset+2])

        d = ((b[1] << 8) | (b[0])) & 0xFFFF

        if not asString:        
            return d

        s = '{0:04X}'.format(d)
        
        return s

    def getBYTE(self, offset, asString=False):
        if offset + 1 > len(self.data):
            return None

        b = bytearray(self.data[offset:offset+1])

        d = (b[0]) & 0xFF

        if not asString:        
            return d

        s = '{0:02X}'.format(d)
        
        return s

    def getStrean(self, start, end):
        return bytearray(self.data[start:end])

    def getOffset(self):
        return self.dataOffset

class Cursor(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y
        
    def move(self, dx, dy):
        self.x += dx
        self.y += dy

    def moveAbsolute(self, x, y):
        self.x = x
        self.y = y

    def getPosition(self):
        return self.x, self.y

class Observable(object):
    def __init__(self):
        self.Callbacks = []

    def addHandler(self, h):
        if h not in self.Callbacks:
            self.Callbacks.append(h)

    def notify(self, rows, cols):
        for cbk in self.Callbacks:
            cbk.update_geometry(rows, cols)

class ViewMode(Observable):

    def __init__(self):
        super().__init__()

    """
    Convert IBM437 character codes 0x00 - 0xFF into Unicode.
    http://svn.openmoko.org/trunk/src/host/qemu-neo1973/phonesim/lib/serial/qatutils.cpp
    """
    cp437ToUnicode = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
        0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
        0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
        0x0018, 0x0019, 0x001c, 0x001b, 0x007f, 0x001d, 0x001e, 0x001f,
        0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
        0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
        0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
        0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
        0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
        0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
        0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
        0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
        0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
        0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
        0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
        0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x001a,
        0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7,
        0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,
        0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
        0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192,
        0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
        0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
        0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
        0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
        0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
        0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
        0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,
        0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
        0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x03bc, 0x03c4,
        0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
        0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
        0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0]

    def cp437(self, c):
        return chr(self.cp437ToUnicode[c])

    def getPageOffset(self):
        NotImplementedError('method not implemented.')

    def getGeometry(self):
        NotImplementedError('method not implemented.')

class BinViewMode(ViewMode):
    def __init__(self, width, height, data, cursor):
        super(ViewMode, self).__init__()

        self.dataModel = data
        self.addHandler(self.dataModel)

        self.width = width
        self.height = height
        #self.cursorX = 0
        #self.cursorY = 0

        self.cursor = cursor

        self.refresh = True

        self._selectionStart = False
        self._selectionOffset = 0

        # background brush
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        # text font
        self.font = QtGui.QFont('Terminus', 11, QtGui.QFont.Light)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 0, QtCore.Qt.SolidLine)
        self.resize(width, height)

        self.Paints = {}

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

    def setTransformationEngine(self, engine):
        self.transformationEngine = engine

    def computeTextArea(self):
        self.COLUMNS = self.width//self.fontWidth
        self.ROWS    = self.height//self.fontHeight
        self.notify(self.ROWS, self.COLUMNS)

    def drawAdditionals(self):
        self.newPix = self._getNewPixmap(self.width, self.height)
        qp = QtGui.QPainter()
        qp.begin(self.newPix)
        qp.drawPixmap(0, 0, self.qpix)
        self.transformationEngine.decorateText(qp, self.COLUMNS, self.ROWS)
        #self._makeSelection(qp, 1200, 1895, cols, rows, brush=QtGui.QBrush(QtGui.QColor(125, 255, 0)))
        if self._selectionStart:
            self.transformationEngine.makeSelection(qp, self._selectionOffset, self.getCursorAbsolutePosition(), self.COLUMNS, self.ROWS, brush=QtGui.QBrush(QtGui.QColor(125, 255, 0)))
            #po = self.dataModel.getPageOffset()

            string = self.dataModel.getStrean(self._selectionOffset, self.getCursorAbsolutePosition())
            self.transformationEngine.highliteText(qp, string, self.COLUMNS, self.ROWS, Exclude=[self._selectionOffset])

        self.drawCursor(qp)
        qp.end()

    def getPageOffset(self):
        return self.dataModel.getOffset()

    def getGeometry(self):
        return self.COLUMNS, self.ROWS

    def doSelection(self):
        self._selectionStart = not self._selectionStart

        if self._selectionStart:
            self._selectionOffset = self.getCursorAbsolutePosition()

    def draw(self, refresh=False):
#        print self.dataModel.getOffset()
        if self.dataModel.getOffset() in self.Paints:
            self.refresh = False
            self.qpix = QtGui.QPixmap(self.Paints[self.dataModel.getOffset()])
#            print 'hit'
            self.drawAdditionals()
            return

        if self.refresh or refresh:
            qp = QtGui.QPainter()
            qp.begin(self.qpix)
            self.drawTextMode(qp)
            self.refresh = False
            qp.end()

        self.Paints[self.dataModel.getOffset()] = QtGui.QPixmap(self.qpix)
        self.drawAdditionals()

    def drawCursor(self, qp):
        cursorX, cursorY = self.cursor.getPosition()
        qp.setBrush(QtGui.QColor(255, 255, 0))

        qp.drawRect(cursorX*self.fontWidth, cursorY*self.fontHeight, self.fontWidth, self.fontHeight)


    def scroll_h(self, dx):
        self.qpix.scroll(dx*self.fontWidth, 0, self.qpix.rect())

        qp = QtGui.QPainter()
        
        qp.begin(self.qpix)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dx)
        if dx < 0:
            qp.fillRect((self.COLUMNS - 1*factor)*self.fontWidth, 0, factor * self.fontWidth, self.ROWS*self.fontHeight, self.backgroundBrush)
        if dx > 0:
            qp.fillRect(0, 0, factor * self.fontWidth, self.ROWS*self.fontHeight, self.backgroundBrush)

        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        page = self.transformationEngine.transformText()
        # scriem pe fiecare coloana in parte
        for column in range(factor):
            # fiecare caracter de pe coloana
            for i in range(self.ROWS):

                if dx < 0:
                    # cu (column) selectam coloana
                    idx = (i+1)*(self.COLUMNS) - (column + 1)
                if dx > 0:
                    idx = (i)*(self.COLUMNS) + (column)

                #c = self.dataModel.getDisplayablePage()[idx]
                c = self.transformationEngine.getChar(idx)
                qp.setPen(self.transformationEngine.choosePen(idx))

                if self.transformationEngine.chooseBrush(idx) != None:
                    qp.setBackgroundMode(1)
                    qp.setBackground(self.transformationEngine.chooseBrush(idx))


#                self.transformText(qp, (idx, c), self.dataModel.getDisplayablePage())
                if dx < 0:
                    cemu.writeAt(self.COLUMNS - (column + 1), i, self.cp437(c))

                if dx > 0:
                    cemu.writeAt(column, i, self.cp437(c))

                qp.setBackgroundMode(0)
        qp.end()


    def scroll_v(self, dy):
        self.qpix.scroll(0, dy*self.fontHeight, self.qpix.rect())

        qp = QtGui.QPainter()
        
        qp.begin(self.qpix)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dy)
        if dy < 0:
            qp.fillRect(0, (self.ROWS-factor)*self.fontHeight, self.fontWidth*self.COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        if dy > 0:
            qp.fillRect(0, 0, self.fontWidth*self.COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        #data = self.dataModel.getDisplayablePage()
        page = self.transformationEngine.transformText()

        # cate linii desenam
        for row in range(factor):
            # desenam caracterele
            for i in range(self.COLUMNS):

                if dy < 0:
                    idx = (self.ROWS - (row + 1))*self.COLUMNS + i

                if dy > 0:
                    idx = i + (self.COLUMNS*row)

                #c = data[idx]
                #c = page[idx]
                c = self.transformationEngine.getChar(idx)
                qp.setPen(self.transformationEngine.choosePen(idx))

                if self.transformationEngine.chooseBrush(idx) != None:
                    qp.setBackgroundMode(1)
                    qp.setBackground(self.transformationEngine.chooseBrush(idx))


                #self.transformText(qp, (idx, c), data)

                if dy < 0:
                    cemu.writeAt(i, self.ROWS - 1 - row, self.cp437(c))

                if dy > 0:
                    cemu.writeAt(i, row, self.cp437(c))

                qp.setBackgroundMode(0)

        qp.end()


    def scroll(self, dx, dy):
        if self.dataModel.getOffset() in self.Paints:
            self.draw()
            return

        if dx != 0:
            if self.dataModel.inLimits((self.dataModel.getOffset() - dx)):
                self.scroll_h(dx)

        if dy != 0:
            if self.dataModel.inLimits((self.dataModel.getOffset() - dy*self.COLUMNS)):
                self.scroll_v(dy)
            else:
                if dy <= 0:
                    self.dataModel.slideToLastPage()
                else:
                    self.dataModel.slideToFirstPage()
                self.draw(refresh=True)

        self.draw()


    def scrollPages(self, number):
        self.scroll(0, -number*self.ROWS)

    def getPixmap(self):
        #return self.qpix
        return self.newPix

    def resize(self, width, height):
        self.width = width - width%self.fontWidth
        self.height = height - height%self.fontHeight
        self.computeTextArea()
        self.qpix = self._getNewPixmap(self.width, self.height)
        self.refresh = True

    # TODO: isText/transformText trebuie generalizate
    def isText(self, c):
        Special = string.ascii_letters + string.digits + ' .;\':;=\"?-!()/\\_'
        
        return str(c) in Special

    def _wchar(self, bytes, i):
        return bytes[i+1] == 0 and chr(bytes[i]) in string.ascii_letters

    def transformText(self, qp, v, text):
        i, c = v

        # aici ar veni procesatoarele de content
        if i + 4 < len(text):
            if self.isText(chr(text[i + 0])) and \
               self.isText(chr(text[i + 1])) and \
               self.isText(chr(text[i + 2])) and \
               self.isText(chr(text[i + 3])):
               qp.setPen(QtGui.QColor(255, 0, 0))

        if not self.isText(chr(text[i])):
            qp.setPen(self.textPen)

    def drawTextMode(self, qp):
        # draw background
        qp.fillRect(0, 0, self.COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight, self.backgroundBrush)

        # set text pen&font
        qp.setFont(self.font)
        qp.setPen(self.textPen)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        page = self.transformationEngine.transformText()
        for i, c in enumerate(page):
            #self.transformText(qp, (i, c),  self.dataModel.getDisplayablePage())
            c = self.transformationEngine.getChar(i)
            qp.setPen(self.transformationEngine.choosePen(i))

            if self.transformationEngine.chooseBrush(i) != None:
                qp.setBackgroundMode(1)
                qp.setBackground(self.transformationEngine.chooseBrush(i))

            cemu.write(self.cp437(c))
            qp.setBackgroundMode(0)                        
    
    def getCursorAbsolutePosition(self):
        x, y = self.cursor.getPosition()
        return self.dataModel.getOffset() + y*self.COLUMNS + x

    def moveCursor(self, direction):
        cursorX, cursorY = self.cursor.getPosition()

        if direction == Directions.Left:
            if cursorX == 0:
                if cursorY == 0:
                    self.dataModel.slide(-1)
                    self.scroll(1, 0)
                else:
                    self.cursor.moveAbsolute(self.COLUMNS-1, cursorY - 1)
                    #cursorX = self.COLUMNS-1                    
                    #cursorY -= 1
            else:
                self.cursor.move(-1, 0)
                #cursorX -= 1

        if direction == Directions.Right:
            if cursorX == self.COLUMNS-1:
                if cursorY == self.ROWS-1:
                    self.dataModel.slide(1)
                    self.scroll(-1, 0)
                else:
                    self.cursor.moveAbsolute(0, cursorY + 1)
                    #self.cursorX = 0
                    #self.cursorY += 1
            else:
                self.cursor.move(1, 0)
                #self.cursorX += 1

        if direction == Directions.Down:
            if cursorY == self.ROWS-1:
                self.dataModel.slideLine(1)
                self.scroll(0, -1)
            else:
                self.cursor.move(0, 1)
                #self.cursorY += 1

        if direction == Directions.Up:
            if cursorY == 0:
                self.dataModel.slideLine(-1)
                self.scroll(0, 1)
            else:
                self.cursor.move(0, -1)
                #self.cursorY -= 1

        if direction == Directions.End:
            self.cursor.moveAbsolute(self.COLUMNS-1, self.ROWS-1)
            #self.cursorX = self.COLUMNS-1
            #self.cursorY = self.ROWS-1

        if direction == Directions.Home:
            self.cursor.moveAbsolute(0, 0)
            #self.cursorX = 0
            #self.cursorY = 0

        if direction == Directions.CtrlHome:
            self.dataModel.slideToFirstPage()
            self.draw(refresh=True)
            self.cursor.moveAbsolute(0, 0)
            #self.cursorX = 0
            #self.cursorY = 0

        if direction == Directions.CtrlEnd:
            self.dataModel.slideToLastPage()
            self.draw(refresh=True)
            self.cursor.moveAbsolute(self.COLUMNS-1, self.ROWS-1)
            #self.cursorX = self.COLUMNS-1
            #self.cursorY = self.ROWS-1

def enum(**enums):
    return type('Enum', (), enums)

Directions = enum(Left=1, Right=2, Up=3, Down=4, End=5, Home=6, CtrlEnd=7, CtrlHome=8)

class HexViewMode(ViewMode):
    def __init__(self, width, height, data):
        super(ViewMode, self).__init__()

        self.dataModel = data
        self.width = width
        self.height = height
        self.cursorX = 0
        self.cursorY = 0

        self.refresh = True


        self.addHandler(self.dataModel)

        # background brush
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        # text font
        self.font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

        self.Special = string.ascii_letters + string.digits + ' .;\':;=\"?-!()/\\_'

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine)

        self.resize(width, height)

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

    def getPixmap(self):
        #return self.qpix
        return self.newPix        

    def computeTextArea(self):
        self.COLUMNS = 32
        self.CON_COLUMNS = self.width//self.fontWidth
        self.ROWS = self.height//self.fontHeight
        self.notify(self.ROWS, self.COLUMNS)

    def resize(self, width, height):
        self.width = width - width%self.fontWidth
        self.height = height - height%self.fontHeight
        self.computeTextArea()
        self.qpix = self._getNewPixmap(self.width, self.height)
        self.refresh = True

    def scroll(self, dx, dy):
        if dx != 0:
            self.scroll_h(dx)

        if dy != 0:
            self.scroll_v(dy)

        self.draw()

    def scrollPages(self, number):
        self.scroll(0, number*self.ROWS)

    def drawAdditionals(self):
        self.newPix = self._getNewPixmap(self.width, self.height)
        qp = QtGui.QPainter()
        qp.begin(self.newPix)
        qp.drawPixmap(0, 0, self.qpix)
        self.drawCursor(qp)
        # draw lines
        
        for i in range(self.COLUMNS/4)[1:]:
            xw = i*4*3*self.fontWidth - 4
            qp.setPen(QtGui.QColor(0, 255, 0))
            qp.drawLine(xw, 0, xw, self.ROWS*self.fontHeight)

        qp.end()


    def scroll_h(self, dx):

        gap = 5

        # hex part
        self.qpix.scroll(dx*3*self.fontWidth, 0, QtCore.QRect(0, 0, self.COLUMNS*3*self.fontWidth, self.ROWS*self.fontHeight))
        # text part
        self.qpix.scroll(dx*self.fontWidth, 0, QtCore.QRect((self.COLUMNS*3 + gap)*self.fontWidth , 0, self.COLUMNS*self.fontWidth, self.ROWS*self.fontHeight))        

        qp = QtGui.QPainter()
        
        qp.begin(self.qpix)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dx)

        textBegining = self.COLUMNS*3 + gap
        if dx < 0:
            # hex
            qp.fillRect((self.COLUMNS - 1*factor)*3*self.fontWidth, 0, factor * self.fontWidth * 3, self.ROWS*self.fontHeight, self.backgroundBrush)
            # text
            qp.fillRect((textBegining + self.COLUMNS - 1*factor)*self.fontWidth, 0, factor * self.fontWidth, self.ROWS*self.fontHeight, self.backgroundBrush)
        if dx > 0:
            # hex
            qp.fillRect(0, 0, factor * 3 * self.fontWidth, self.ROWS*self.fontHeight, self.backgroundBrush)
            # text
            qp.fillRect(textBegining*self.fontWidth, 0, factor * self.fontWidth, self.ROWS*self.fontHeight, self.backgroundBrush)            

        cemu = ConsoleEmulator(qp, self.ROWS, self.CON_COLUMNS)

        # scriem pe fiecare coloana in parte
        for column in range(factor):
            # fiecare caracter de pe coloana
            for i in range(self.ROWS):

                self.transformText(qp, (idx, self.dataModel.getDisplayablePage()[idx]), self.dataModel.getDisplayablePage())

                if dx < 0:
                    # cu (column) selectam coloana
                    idx = (i+1)*(self.COLUMNS) - (column + 1)
                if dx > 0:
                    idx = (i)*(self.COLUMNS) + (column)

                
                c = self.dataModel.getDisplayablePage()[idx]
                hex_s = str(hex(c)[2:]).zfill(2) + ' '
                if dx < 0:
                    cemu.writeAt((self.COLUMNS - (column + 1))*3, i, hex_s)
                    cemu.writeAt(textBegining + self.COLUMNS - (column + 1), i, self.cp437(c))

                if dx > 0:
                    cemu.writeAt((column)*3, i, hex_s)
                    cemu.writeAt(textBegining + column, i, self.cp437(c))

        qp.end()

    def scroll_v(self, dy):
        self.qpix.scroll(0, dy*self.fontHeight, self.qpix.rect())

        qp = QtGui.QPainter()
        
        qp.begin(self.qpix)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dy)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.CON_COLUMNS)

        if dy < 0:
            cemu.gotoXY(0, self.ROWS - factor)            
            qp.fillRect(0, (self.ROWS-factor)*self.fontHeight, self.fontWidth*self.CON_COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        if dy > 0:
            cemu.gotoXY(0, 0)            
            qp.fillRect(0, 0, self.fontWidth*self.CON_COLUMNS, factor * self.fontHeight, self.backgroundBrush)


        # cate linii desenam
        for row in range(factor):
            # desenam caracterele
            for i in range(self.COLUMNS):

                if dy < 0:
                    idx = (self.ROWS - (row + 1))*self.COLUMNS + i

                if dy > 0:
                    idx = i + (self.COLUMNS*row)

                self.transformText(qp, (idx, self.dataModel.getDisplayablePage()[idx]), self.dataModel.getDisplayablePage())
                if dy < 0:
                    c = self.dataModel.getDisplayablePage()[idx]
                    hex_s = str(hex(c)[2:]).zfill(2) + ' '

                    # write hex representation
                    cemu.write(hex_s)
                    # save hex position
                    x, y = cemu.getXY()
                    # write text
                    cemu.writeAt(self.COLUMNS*3 + 5 + (i%self.COLUMNS), y, self.cp437(c))
                    # go back to hex chars
                    cemu.gotoXY(x, y)


                if dy > 0:
                    c = self.dataModel.getDisplayablePage()[idx]
                    hex_s = str(hex(c)[2:]).zfill(2) + ' '

                    # write hex representation
                    cemu.write(hex_s)
                    # save hex position
                    x, y = cemu.getXY()
                    # write text
                    cemu.writeAt(self.COLUMNS*3 + 5 + (i%self.COLUMNS), y, self.cp437(c))
                    # go back to hex chars
                    cemu.gotoXY(x, y)


            cemu.writeLn()
        qp.end()

    def draw(self):
        if self.refresh:
            qp = QtGui.QPainter()
            qp.begin(self.qpix)
            self.drawTextMode(qp)
            self.refresh = False
            qp.end()

        self.drawAdditionals()

    # TODO: isText/transformText trebuie generalizate
    def isText(self, c):
        
        return str(c) in self.Special

    def transformText(self, qp, v, text):
        i, c = v

        # aici ar veni procesatoarele de content
        if i + 4 < len(text):
            if self.isText(chr(text[i + 0])) and \
               self.isText(chr(text[i + 1])) and \
               self.isText(chr(text[i + 2])) and \
               self.isText(chr(text[i + 3])):
               qp.setPen(QtGui.QColor(255, 0, 0))

        if not self.isText(chr(text[i])):
            qp.setPen(self.textPen)


    def drawTextMode(self, qp):
       
        # draw background
        qp.fillRect(0, 0, self.CON_COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight, self.backgroundBrush)

        # set text pen&font
        qp.setFont(self.font)
        qp.setPen(self.textPen)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.CON_COLUMNS)

        for i, c in enumerate(self.dataModel.getDisplayablePage()):
            self.transformText(qp, (i, c), self.dataModel.getDisplayablePage())
            hex_s = str(hex(c)[2:]).zfill(2) + ' '

            # write hex representation
            cemu.write(hex_s)
            # save hex position
            x, y = cemu.getXY()
            # write text
            cemu.writeAt(self.COLUMNS*3 + 5 + (i%self.COLUMNS), y, self.cp437(c))
            # go back to hex chars
            cemu.gotoXY(x, y)
            if (i+1)%self.COLUMNS == 0:
                cemu.writeLn()

    def moveCursor(self, direction):
        if direction == Directions.Left:
            if self.cursorX == 0:
                if self.cursorY == 0:
                    self.dataModel.slide(-1)
                    self.scroll(1, 0)
                else:
                    self.cursorX = self.COLUMNS-1
                    self.cursorY -= 1
            else:
                self.cursorX -= 1

        if direction == Directions.Right:
            if self.cursorX == self.COLUMNS-1:
                if self.cursorY == self.ROWS-1:
                    self.dataModel.slide(1)
                    self.scroll(-1, 0)
                else:
                    self.cursorX = 0
                    self.cursorY += 1
            else:
                self.cursorX += 1

        if direction == Directions.Down:
            if self.cursorY == self.ROWS-1:
                self.dataModel.slideLine(1)
                self.scroll(0, -1)
            else:
                self.cursorY += 1

        if direction == Directions.Up:
            if self.cursorY == 0:
                self.dataModel.slideLine(-1)
                self.scroll(0, 1)
            else:
                self.cursorY -= 1    

    def drawCursor(self, qp):
        qp.setBrush(QtGui.QColor(255, 255, 0))
        # cursor on text
        qp.drawRect((self.COLUMNS*3 + 5 + self.cursorX)*self.fontWidth, self.cursorY*self.fontHeight, self.fontWidth, self.fontHeight)

        # cursor on hex
        qp.drawRect(self.cursorX*3*self.fontWidth, self.cursorY*self.fontHeight, 2*self.fontWidth, self.fontHeight)


class TextTransformation:
    def __init__(self, dataModel):
        self.operations = []
        self.dataModel = dataModel
        self.penMap = {}
        self.brushMap = {}
        self.Special =  string.ascii_letters + string.digits + ' .;\':;=\"?-!()/\\_'
        self.Intervals = []


    def addOperation(self, op):
        self.operations.append(op)

    def isText(self, c):
        
        return str(c) in self.Special

    def getChar(self, idx):
        if idx < len(self.page):
            return self.page[idx]

        return 0

    def _makeSelection(self, qp, start, end, cols, rows, brush=QtGui.QBrush(QtGui.QColor(128, 0, 0))):
        off = self.dataModel.getOffset()
        page = self.dataModel.getDisplayablePage()

        # return if out of view
        if end < off:
            return

        if start > off + len(page):
            return

        if start < off:
            d0 = 0
        else:
            d0 = start - off

        if end > off + len(page):
            d1 = len(page)
        else:
            d1 = end - off
        
        mark = True
        height = 14

        qp.setOpacity(0.4)
        while mark:
            if d0/cols == d1/cols:
                qp.fillRect((d0%cols)*8, (d0/cols)*height, (d1-d0)*8, 1*height, brush)
                d0 += (d1 - d0)
            else:    
                qp.fillRect((d0%cols)*8, (d0/cols)*height, (cols - d0%cols)*8, 1*height, brush)
                d0 += (cols - d0%cols)

            if (d1 - d0 <= 0):
                mark = False
        qp.setOpacity(1)

    def decorateText(self, qp, cols, rows):
        self._makeSelection(qp, 18, 1595, cols, rows)
        self._makeSelection(qp, 1200, 1895, cols, rows, brush=QtGui.QBrush(QtGui.QColor(125, 255, 0)))
        self._makeSelection(qp, 10000, 11000, cols, rows)
        self._makeSelection(qp, 45000, 51000, cols, rows)        

    def makeSelection(self, qp, start, end, cols, rows, brush):
        self._makeSelection(qp, start, end, cols, rows, brush)
        """        
        off = self.dataModel.getOffset()
        for it in re.finditer('note', self.dataModel.getDisplayablePage()):
            self._makeSelection(qp, off + it.start(), off + it.end(), cols, rows, brush=QtGui.QBrush(QtGui.QColor(255, 255, 0)))

        """
        
    def highliteText(self, qp, text, cols, rows, Exclude=[]):
        page = self.dataModel.getDisplayablePage()

        
        # todo: nu am gasit o metoda mai eleganta pentru a selecta toate aparitiile ale lui text
        # regexp nu merg, "bad re expression"
        lenText = len(text)
        M = []
        idx = 0
        if lenText > 0:
            while idx < len(page):
                idx = page.find(text, idx, len(page))
                #print idx, len(text)

                if idx == -1:
                    break
                M.append((idx, lenText))
                idx += lenText

        
        #Match = [(m.start(), m.end()) for m in re.finditer(bytes(text), bytes(page))]
        
        for start, end in M:
            #print start, end
            #self._makeSelection(qp, start, end, cols, rows)
            off = self.dataModel.getOffset()
            if off+start not in Exclude:
                self._makeSelection(qp, off + start, off + start + end, cols, rows, brush=QtGui.QBrush(QtGui.QColor(125, 255, 0)))

        #idx = page.find(text)
        #print idx

        #x = self.dataModel.getOffset() + idx
        #self._makeSelection(qp, x, x + len(text), cols, rows)

    def _changeText(self, page, page_start, I):
        page_end = page_start + len(page)
        for obj in I:
            if obj['s'] >= page_start and obj['e'] <= page_end:
                page[obj['s']-page_start:obj['e']-page_start] = obj['text']


    def _expand(self, page, off, start, end):
        I = []
        start = start - off
        end = end - off
        i = start
        while i < end:

            if i+1 < end:
                if page[i+1] == 0 and self.isText(chr(page[i])):
                    k = 0
                    for j in range(i, end, 2):
                        if j < end:
                            if self.isText(chr(page[j])) and page[j+1] == 0:
                                k += 1
                            else:
                                break
                    if k > 4:
                        if i+k*2 <= end:
                        
                            obj = {}
                            obj['s'] = off + i + 1
                            obj['e'] = off + i + k * 2

                            for idx, j in enumerate(range(i+1, i + k*2)):
                                if j > i + k:
                                    page[j] = 0
                                elif j+idx+1 < end:
                                    page[j] = page[j + idx + 1]
                                    self.penMap[off + j] = self.greenPen
                                    
                            obj['text'] = page[i+1:i+k*2]
                            I.append(obj)
                            self.penMap[off + i] = self.greenPen
                            i += k*2

            i = i + 1

        return I
        pass
    """
    def transformText(self):
        page = self.dataModel.getDisplayablePage()
        self.page = page

        self.redPen = QtGui.QPen(QtGui.QColor(255, 0, 0))
        #self.redPen.setBrush(QtGui.QBrush(QtGui.QColor(112, 30, 50)))

        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))

        self.normalPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine)        

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))

        #self.penMap = [self.normalPen for x in range(len(page))]

        is_text = False
        off = self.dataModel.getOffset()

        # highlite text
        for i in range(len(page)):
            if (off + i) not in self.penMap:
                if not is_text:
                    if i + 4 < len(page):
                        if self.isText(page[i + 0]) and \
                           self.isText(page[i + 1]) and \
                           self.isText(page[i + 2]) and \
                           self.isText(page[i + 3]):
                           is_text = True
                        else:
                            self.penMap[off + i] = self.normalPen

                if not self.isText(page[i]):
                    is_text = False
                    self.penMap[off + i] = self.normalPen

                if is_text:
                    self.penMap[off + i] = self.redPen
                else:
                    self.penMap[off + i] = self.normalPen

        # highlite MZ/PE
        for i in range(len(page)):
            if i+1 < len(page):
                if (page[i] == 'M' and page[i+1] == 'Z') or (page[i] == 'P' and page[i+1] == 'E'):
                    self.brushMap[off+i] = self.MZbrush;
                    self.brushMap[off+i+1] = self.MZbrush;

                    self.penMap[off + i] = self.greenPen
                    self.penMap[off + i+1] = self.greenPen

            if i + 6 < len(page):
                if (ord(page[i]) == 0xFF and ord(page[i+1]) == 0x15):
                    for j in range(6):
                        self.brushMap[off + i + j] = self.grayBrush
                        self.penMap[off + i + j] = self.whitePen
                        if page[i+j] == chr(0):
                            page[i+j] = ' '

        # highlite widechar
        #return page
        
        page_end = off  + len(page)
        touched = False
        #print '-------'
        for idx, iv in enumerate(self.Intervals):
            #print 'acum aici'
            # in interval
            s, e, I = iv

            #print s ,e
            #print page_end
            page_start = off
            if off >= s:
                touched = True
                if page_end <= e:
                    self._changeText(page, off, I)
                else:
                    if off <= e:
                        I2 = self._expand(page, off, e, page_end)
                        for obj in I2:
                            I.append(obj)
                        e = page_end
                        self.Intervals[idx] = (s, e, I)
                    else:
                        # suntem cu mai multe pagini mai jos
                        touched = False

            else:
                if page_end <= e and page_end >= s:
                    # scrolled up
                    I2 = self._expand(page, off, page_start, s)
                    for obj in I2:
                        I.append(obj)
                    s = page_start
                    self.Intervals[idx] = (s, e, I)
                    touched = True
                else:
                    # out of this interval
                    touched = False


        if not touched:
            #print 'aici'
            self.Intervals.append((off, page_end, self._expand(page, off, off, page_end)))
        

        #return page


        return page
#        for i, a in enumerate(self.penMap):
 #           if a == None:
  #              print i
        #print self.penMap

        pass
    """
    
    def transformText(self):
        page = self.dataModel.getDisplayablePage()
        self.page = page

        self.redPen = QtGui.QPen(QtGui.QColor(255, 0, 0))
        #self.redPen.setBrush(QtGui.QBrush(QtGui.QColor(112, 30, 50)))

        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))

        self.normalPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine)        

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))

        #self.penMap = [self.normalPen for x in range(len(page))]

        is_text = False
        off = self.dataModel.getOffset()

        # highlite text
        for i in range(len(page)):
            if (off + i) not in self.penMap:
                if not is_text:
                    if i + 4 < len(page):
                        if self.isText(chr(page[i + 0])) and \
                           self.isText(chr(page[i + 1])) and \
                           self.isText(chr(page[i + 2])) and \
                           self.isText(chr(page[i + 3])):
                           is_text = True
                        else:
                            self.penMap[off + i] = self.normalPen

                if not self.isText(chr(page[i])):
                    is_text = False
                    self.penMap[off + i] = self.normalPen

                if is_text:
                    self.penMap[off + i] = self.redPen
                else:
                    self.penMap[off + i] = self.normalPen

        # highlite MZ/PE
        for i in range(len(page)):
            if i+1 < len(page):
                if (page[i] == ord('M') and page[i+1] == ord('Z')) or (page[i] == ord('P') and page[i+1] == ord('E')):
                    self.brushMap[off+i] = self.MZbrush;
                    self.brushMap[off+i+1] = self.MZbrush;

                    self.penMap[off + i] = self.greenPen
                    self.penMap[off + i+1] = self.greenPen

            if i + 6 < len(page):
                if (page[i] == 0xFF and page[i+1] == 0x15):
                    for j in range(6):
                        self.brushMap[off + i + j] = self.grayBrush
                        self.penMap[off + i + j] = self.whitePen
                        if page[i+j] == 0:
                            page[i+j] = ord(' ')

        # highlite widechar
        #return page
        
        page_end = off  + len(page)
        touched = False
        #print '-------'
        for idx, iv in enumerate(self.Intervals):
            #print 'acum aici'
            # in interval
            s, e, I = iv

            #print s ,e
            #print page_end
            page_start = off
            if off >= s:
                touched = True
                if page_end <= e:
                    self._changeText(page, off, I)
                else:
                    if off <= e:
                        I2 = self._expand(page, off, e, page_end)
                        for obj in I2:
                            I.append(obj)
                        e = page_end
                        self.Intervals[idx] = (s, e, I)
                    else:
                        # suntem cu mai multe pagini mai jos
                        touched = False

            else:
                if page_end <= e and page_end >= s:
                    # scrolled up
                    I2 = self._expand(page, off, page_start, s)
                    for obj in I2:
                        I.append(obj)
                    s = page_start
                    self.Intervals[idx] = (s, e, I)
                    touched = True
                else:
                    # out of this interval
                    touched = False


        if not touched:
            #print 'aici'
            self.Intervals.append((off, page_end, self._expand(page, off, off, page_end)))
        

        #return page
        return page
#        for i, a in enumerate(self.penMap):
 #           if a == None:
  #              print i
        #print self.penMap

        pass
    

    def choosePen(self, idx):
        key = self.dataModel.getOffset() + idx
        if key in self.penMap:
            return self.penMap[key]

        return QtGui.QPen(QtGui.QColor(255, 255, 255))

    def chooseBrush(self, idx):
        off = self.dataModel.getOffset() + idx
        if off in self.brushMap:
            return self.brushMap[off]

        return None

class FileAddrBanner():
    def __init__(self, width, height, dataModel, viewMode):
        self.width = width
        self.height = height
        self.dataModel = dataModel
        self.viewMode = viewMode
        self.qpix = self._getNewPixmap(width, height)
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))        
        

        # text font
        self.font = QtGui.QFont('Terminus', 11, QtGui.QFont.Light)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 0, QtCore.Qt.SolidLine)

    def setViewMode(self, viewMode):
        self.viewMode = viewMode

    def getPixmap(self):
        return self.qpix

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

    def draw(self):
        qp = QtGui.QPainter()

        offset = self.viewMode.getPageOffset()
        columns, rows = self.viewMode.getGeometry()

        qp.begin(self.qpix)
        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)
        
        for i in range(rows):
            s = '{0:08x}'.format(offset)
            qp.drawText(0+5, (i+1) * self.fontHeight, s)
            offset += columns
        

        qp.end()

    def resize(self, width, height):
        self.width = width
        self.height = height

        self.qpix = self._getNewPixmap(self.width, self.height)
        


class BottomBanner():
    def __init__(self, width, height, dataModel, viewMode):
        self.width = width
        self.height = height
        self.dataModel = dataModel
        self.viewMode = viewMode

        self.qpix = self._getNewPixmap(width, height)
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))        
        

        # text font
        self.font = QtGui.QFont('Consolas', 11, QtGui.QFont.Light)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

        self.textPen = QtGui.QPen(QtGui.QColor(255, 255, 0), 0, QtCore.Qt.SolidLine)


    def setViewMode(self, viewMode):
        self.viewMode = viewMode

    def draw(self):
        qp = QtGui.QPainter()
        qp.begin(self.qpix)

        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)

        cemu = ConsoleEmulator(qp, self.height//self.fontHeight, self.width//self.fontWidth)

        dword = self.dataModel.getDWORD(self.viewMode.getCursorAbsolutePosition(), asString=True)
        sd = 'DWORD: {0}'.format(dword)

        pos = 'POS: {0:08x}'.format(self.viewMode.getCursorAbsolutePosition())

        qword = self.dataModel.getQWORD(self.viewMode.getCursorAbsolutePosition(), asString=True)
        sq = 'QWORD: {0}'.format(qword)

        byte = self.dataModel.getBYTE(self.viewMode.getCursorAbsolutePosition(), asString=True)
        sb = 'BYTE: {0}'.format(byte)

        cemu.writeAt(1,  0, pos)
        cemu.writeAt(17, 0, sd)
        cemu.writeAt(35, 0, sq)
        cemu.writeAt(62, 0, sb)

        qp.drawLine(120, 0, 120, 50)
        qp.drawLine(270, 0, 270, 50)
        qp.drawLine(480, 0, 480, 50)
        qp.drawLine(570, 0, 570, 50)
        """
        # position
        qp.drawText(0 + 5, self.fontHeight, pos)
        # separator
        qp.drawLine(120, 0, 120, 50)

        # dword
        qp.drawText(130 + 5, self.fontHeight, sd)
        # separator
        qp.drawLine(270, 0, 270, 50)

        # qword
        qp.drawText(280 + 5, self.fontHeight, sq)
        # separator
        qp.drawLine(480, 0, 480, 50)

        # byte
        qp.drawText(490 + 5, self.fontHeight, sb)
        # separator
        qp.drawLine(570, 0, 570, 50)
        """
        
        qp.end()

        pass
    def getPixmap(self):
        return self.qpix

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

    def resize(self, width, height):
        self.width = width
        self.height = height

        self.qpix = self._getNewPixmap(self.width, self.height)


class binWidget(QtGui.QWidget):
  
    def __init__(self, mapped):      
        super(binWidget, self).__init__()
        
        # offset for text window
        self.offsetWindow_h = 100
        self.offsetWindow_v = 0
        self.data = mapped
        self.dataOffset = 0
        
        self.dataModel = DataModel(mapped)
        self.cursor = Cursor(0, 0)

        self.textTransformation = TextTransformation(self.dataModel)
        self.textTransformation.addOperation('color-every-string')
        
        self.multipleViewModes = [BinViewMode(self.size().width(), self.size().height(), self.dataModel, self.cursor),
                                  HexViewMode(self.size().width(), self.size().height(), self.dataModel)]
        self.viewMode = self.multipleViewModes[0]
        self.viewMode.setTransformationEngine(self.textTransformation)

        self.banner = BottomBanner(self.size().width(), 100, self.dataModel, self.viewMode)
        self.filebanner = FileAddrBanner(100, self.size().height(), self.dataModel, self.viewMode)        

        self.initUI()
        
        self.getDisplayedData()

    def initUI(self):
        
        self.setMinimumSize(1, 30)
        self.activateWindow()
        self.grabKeyboard()

        self.painted = False
        self.scroll = False
        self.scroll_right = False
        self.scroll_left = False
        self.scroll_down = False
        self.scroll_up = False        
        self.scroll_pdown = False
        self.scroll_pup = False        

        self.installEventFilter(self)
    """        
            # build thumbnail

            dwidth = 100
            dheight = 1200
                    
            factor = dheight/dwidth
            import math
            x = int(math.sqrt(len(self.data)/factor))
            cols = x
            pixThumb = QtGui.QPixmap(x*self.viewMode.fontWidth, factor*x*self.viewMode.fontHeight)
            
            qp = QtGui.QPainter()
            
            qp.begin(pixThumb)
            qp.setFont(self.viewMode.font)
            qp.setPen(self.viewMode.textPen)
            

            for i,c  in enumerate(self.data):
                self.viewMode.transformText(qp, (i, c), self.data)
                qp.drawText((i%cols)*self.viewMode.fontWidth, self.viewMode.fontHeight + (i/cols)*self.viewMode.fontHeight, c)


            qp.end()
            self.newqpix = pixThumb.scaled(dwidth, dheight, aspectRatioMode = QtCore.Qt.IgnoreAspectRatio, transformMode = QtCore.Qt.FastTransformation)
    """
    """
    def getDisplayedData(self):
        if self.dataOffset < 0:
            self.dataOffset = 0
            return False

        chrlist = [unichr(cp437ToUnicode[ord(c)]) for c in self.data[self.dataOffset : self.dataOffset + self.viewMode.COLUMNS*self.viewMode.ROWS]]
        self.text = "".join(chrlist)
        return True
    """

    def switchViewMode(self):
        self.multipleViewModes = self.multipleViewModes[::-1]
        self.viewMode = self.multipleViewModes[0]
        self.banner.setViewMode(self.viewMode)
        self.filebanner.setViewMode(self.viewMode)        

    def getDisplayedData(self):
        return True

    # event handlers
    def resizeEvent(self, e):
        self.viewMode.resize(self.size().width() - self.offsetWindow_h, self.size().height() - self.offsetWindow_v - 50)
        self.banner.resize(self.size().width(), 100)
        self.filebanner.resize(75, self.size().height() - 55)
        #self.viewMode.resize(100, 1000)

    def paintEvent(self, e):
        if self.scroll == False:
            self.viewMode.draw()
        else:
            scroll_f = 1
            if self.scroll_right:
                self.viewMode.scroll(-scroll_f, 0)
                self.scroll_right = False

            if self.scroll_left:
                self.viewMode.scroll(scroll_f, 0)
                self.scroll_left = False

            if self.scroll_down:
                self.viewMode.scroll(0, -scroll_f)
                self.scroll_down = False

            if self.scroll_up:
                self.viewMode.scroll(0, scroll_f)
                self.scroll_up = False

            if self.scroll_pdown:
                self.viewMode.scrollPages(1)
                self.scroll_pdown = False

            if self.scroll_pup:
                self.viewMode.scrollPages(-1)
                self.scroll_pup = False

            self.scroll = False
            pass

        self.banner.draw()
        self.filebanner.draw()
        qp = QtGui.QPainter()
        qp.begin(self)
        qp.setOpacity(1)
        qp.drawPixmap(self.offsetWindow_h, self.offsetWindow_v, self.viewMode.getPixmap())

        qp.drawPixmap(self.offsetWindow_h, self.size().height() - 50, self.banner.getPixmap())

        qp.drawPixmap(20, 0, self.filebanner.getPixmap())
        qp.end()


    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            key = event.key()
            modifiers = event.modifiers()
            
            scroll_f = 1
            if modifiers == QtCore.Qt.ControlModifier:
                if key == QtCore.Qt.Key_Right:
                    self.dataModel.slide(scroll_f)

                    #self.dataOffset += scroll_f
                    if self.getDisplayedData():
                        self.scroll_right = True
                        self.scroll = True
                        self.update()

                if key == QtCore.Qt.Key_Left:
                    self.dataModel.slide(-scroll_f)
                    #self.dataOffset -= scroll_f
                    if self.getDisplayedData():
                        self.scroll_left = True
                        self.scroll = True
                        self.update()

                if key == QtCore.Qt.Key_End:
                    self.viewMode.moveCursor(Directions.CtrlEnd)
                    self.update()

                if key == QtCore.Qt.Key_Home:
                    self.viewMode.moveCursor(Directions.CtrlHome)
                    self.update()


            else:

                if key == QtCore.Qt.Key_Left:
                    self.viewMode.moveCursor(Directions.Left)
                    self.update()

                if key == QtCore.Qt.Key_Right:
                    self.viewMode.moveCursor(Directions.Right)
                    self.update()

                if key == QtCore.Qt.Key_Down:
                    self.viewMode.moveCursor(Directions.Down)
                    self.update()

                if key == QtCore.Qt.Key_End:
                    self.viewMode.moveCursor(Directions.End)
                    self.update()

                if key == QtCore.Qt.Key_Home:
                    self.viewMode.moveCursor(Directions.Home)
                    self.update()

                if key == QtCore.Qt.Key_Up:
                    self.viewMode.moveCursor(Directions.Up)
                    self.update()

                if key == QtCore.Qt.Key_Tab:
                        self.switchViewMode()
                        self.viewMode.resize(self.size().width() - self.offsetWindow_h, self.size().height() - self.offsetWindow_v)
                        self.update()

                if key == QtCore.Qt.Key_PageDown:
                        self.dataModel.slidePage(1)
                        self.scroll = True
                        self.scroll_pdown = True
                        self.update()

                if key == QtCore.Qt.Key_PageUp:
                        self.dataModel.slidePage(-1)
                        self.scroll = True
                        self.scroll_pup = True
                        self.update()

            if modifiers == QtCore.Qt.ShiftModifier:
                self.viewMode.doSelection()

        return False

    def setTextViewport(self, qp):
        qp.setViewport(self.offsetWindow_h, self.offsetWindow_v, self.size().width(), self.size().height())
        qp.setWindow(0, 0, self.size().width(), self.size().height())





class Example(QtGui.QWidget):
    
    def __init__(self):
        super(Example, self).__init__()
        
        self.initUI()
        
    def initUI(self):      

        if len(sys.argv) > 1:
            f = open(sys.argv[1], "r+b")
        else:
            f = open("notepad.exe", "r+b")

        # memory-map the file, size 0 means whole file
        mapped = mmap.mmap(f.fileno(), 0)
        #mapped.close()

        self.wid = binWidget(mapped)
        
        hbox = QtWidgets.QHBoxLayout()
        hbox.addWidget(self.wid)
        self.setLayout(hbox)

        screen = QtWidgets.QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width()-100, screen.height()-100)
        #self.setGeometry(100, 300, 1424, 310)
        self.setWindowTitle('binhex widget')
        #self.showFullScreen()
        
        self.showMaximized()
        self.wid.activateWindow()

        
def main():
    
    app = QtGui.QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
