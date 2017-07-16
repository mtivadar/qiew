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

    def slide(self, off):
        self.dataOffset += off

    def update_geometry(self, rows, cols):
        self.rows = rows
        self.cols = cols

    def slideLine(self, factor):
        self.slide(factor*self.cols)

    def slidePage(self, factor):
        self.slide(factor*self.cols*self.rows)

    def getDisplayablePage(self):
        return bytearray(self.data[self.dataOffset:self.dataOffset + self.rows*self.cols])

    def getOffset(self):
        return self.dataOffset

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

class BinViewMode(ViewMode):
    def __init__(self, width, height, data):
        super(ViewMode, self).__init__()

        self.dataModel = data
        self.addHandler(self.dataModel)

        self.width = width
        self.height = height
        self.cursorX = 0
        self.cursorY = 0

        self.refresh = True

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
        self.drawCursor(qp)
        qp.end()

    def draw(self):
        if self.refresh:
            qp = QtGui.QPainter()
            qp.begin(self.qpix)
            self.drawTextMode(qp)
            self.refresh = False
            qp.end()


        self.drawAdditionals()

    def drawCursor(self, qp):
        qp.setBrush(QtGui.QColor(255, 255, 0))
        qp.drawRect(self.cursorX*self.fontWidth, self.cursorY*self.fontHeight, self.fontWidth, self.fontHeight)


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

        # scriem pe fiecare coloana in parte
        for column in range(factor):
            # fiecare caracter de pe coloana
            for i in range(self.ROWS):

                if dx < 0:
                    # cu (column) selectam coloana
                    idx = (i+1)*(self.COLUMNS) - (column + 1)
                if dx > 0:
                    idx = (i)*(self.COLUMNS) + (column)

                c = self.dataModel.getDisplayablePage()[idx]

                self.transformText(qp, (idx, c), self.dataModel.getDisplayablePage())
                if dx < 0:
                    cemu.writeAt(self.COLUMNS - (column + 1), i, self.cp437(c))

                if dx > 0:
                    cemu.writeAt(column, i, self.cp437(c))

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
        if dx != 0:
            self.scroll_h(dx)

        if dy != 0:
            self.scroll_v(dy)

        self.draw()


    def scrollPages(self, number):
        self.scroll(0, number*self.ROWS)

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


def enum(**enums):
    return type('Enum', (), enums)

Directions = enum(Left=1, Right=2, Up=3, Down=4)

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

                if dx < 0:
                    # cu (column) selectam coloana
                    idx = (i+1)*(self.COLUMNS) - (column + 1)
                if dx > 0:
                    idx = (i)*(self.COLUMNS) + (column)

                self.transformText(qp, (idx, self.dataModel.getDisplayablePage()[idx]), self.dataModel.getDisplayablePage())
                
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


    def addOperation(self, op):
        self.operations.append(op)

    def isText(self, c):
        
        return str(c) in self.Special

    def getChar(self, idx):
        return self.page[idx]

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

        #return page
        is_text = False
        off = self.dataModel.getOffset()

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

        #return page
        i = 0        
        while i < len(page):
            if i+1 < len(page):
                if page[i+1] == 0 and self.isText(chr(page[i])):
                    k = 0
                    for j in range(i, len(page), 2):
                        if j < len(page):
                            if self.isText(chr(page[j])) and page[j+1] == 0:
                                k += 1
                            else:
                                break
                    if k > 4:
                        if i+k*2 <= len(page):
                        
                            for idx, j in enumerate(range(i+1, i + k*2)):
                                if j > i + k:
                                    page[j] = 0
                                elif j+idx+1 < len(page):
                                    page[j] = page[j + idx + 1]
                                    self.penMap[off + j] = self.greenPen
                                    
                            self.penMap[off + i] = self.greenPen
                            i += k*2

            i = i + 1



        return page
#        for i, a in enumerate(self.penMap):
 #           if a == None:
  #              print i
        #print self.penMap

        pass

    def choosePen(self, idx):
        return self.penMap[self.dataModel.getOffset() + idx]

    def chooseBrush(self, idx):
        off = self.dataModel.getOffset() + idx
        if off in self.brushMap:
            return self.brushMap[off]

        return None

class binWidget(QtGui.QWidget):
  
    def __init__(self, mapped):      
        super(binWidget, self).__init__()
        
        # offset for text window
        self.offsetWindow_h = 100
        self.offsetWindow_v = 20
        self.data = mapped
        self.dataOffset = 0
        
        self.dataModel = DataModel(mapped)

        self.textTransformation = TextTransformation(self.dataModel)
        self.textTransformation.addOperation('color-every-string')
        
        self.multipleViewModes = [BinViewMode(self.size().width(), self.size().height(), self.dataModel),
                                  HexViewMode(self.size().width(), self.size().height(), self.dataModel)]
        self.viewMode = self.multipleViewModes[0]
        self.viewMode.setTransformationEngine(self.textTransformation)

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

    def getDisplayedData(self):
        return True

    # event handlers
    def resizeEvent(self, e):
        self.viewMode.resize(self.size().width() - self.offsetWindow_h, self.size().height() - self.offsetWindow_v)

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

        qp = QtGui.QPainter()
        qp.begin(self)
        qp.setOpacity(1)
        qp.drawPixmap(self.offsetWindow_h, self.offsetWindow_v, self.viewMode.getPixmap())
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

                    """
                        self.dataModel.slideLine(scroll_f)
                        #self.dataOffset += scroll_f*self.viewMode.COLUMNS
                        if self.getDisplayedData():
                            self.scroll = True
                            self.scroll_down = True
                            self.update()
                    """
            
                if key == QtCore.Qt.Key_Up:
                    self.viewMode.moveCursor(Directions.Up)
                    self.update()

                    """
                        self.dataModel.slideLine(-scroll_f)
                        #self.dataOffset -= scroll_f*self.viewMode.COLUMNS
                        if self.getDisplayedData():
                            self.scroll = True
                            self.scroll_up = True
                            self.update()
                    """

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

        return False

    def setTextViewport(self, qp):
        qp.setViewport(self.offsetWindow_h, self.offsetWindow_v, self.size().width(), self.size().height())
        qp.setWindow(0, 0, self.size().width(), self.size().height())





class Example(QtGui.QWidget):
    
    def __init__(self):
        super(Example, self).__init__()
        
        self.initUI()
        
    def initUI(self):      

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
