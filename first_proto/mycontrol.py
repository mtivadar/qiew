#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
ZetCode PyQt5 tutorial

In this example, we create a custom widget.

author: Jan Bodnar
website: zetcode.com 
last edited: October 2011
"""

import sys
from io import *
from PyQt5 import QtGui, QtCore, QtWidgets
import string

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


class Communicate(QtCore.QObject):
    
    updateBW = QtCore.pyqtSignal(int)



class BurningWidget(QtGui.QWidget):
  
    def __init__(self):      
        super(BurningWidget, self).__init__()
        
        self.kataka=False
        self.painted = False
        self.scroll = False
        self.scroll_right = False

        self.from_where = 1
        self.drawMode = 1
        self.selection = 0
             
        self.to_where = self.MAX_DISPLAYED_CHARS
        self.initUI()
    
    def getStream(self, data):
        self.stream = ''
        for a in data[self.read_pos:self.read_pos + self.MAX_DISPLAYED_CHARS]:
            self.stream += chr(cp437ToUnicode[ord(a)])

    def isText(self, c):
        Special = string.ascii_letters + string.digits + ' .';
        
        return c in Special

    @property
    def drawMode(self):
        return self._drawMode

    @drawMode.setter
    def drawMode(self, value):
        if value == 1:
            self.NUMBER_COLS = 170
            self.MAX_DISPLAYED_CHARS = self.NUMBER_COLS*50
            

        if value == 2:
            self.NUMBER_COLS = 32
            self.MAX_DISPLAYED_CHARS = self.NUMBER_COLS*50

        self._drawMode = value

    def initUI(self):
        
        self.setMinimumSize(1, 30)
        self.data = open('notepad.exe', 'rb+').read()
#        self.data = open('bb', 'rb+').read()
        self.read_pos = 0
        self.getStream(self.data)
#        self.stream = bytearray(self.stream, 'UTF')
        self.activateWindow()
#        self.setFocus()
        self.grabKeyboard()
#        print self.stream
#        self.stream = data[:256]
        self.installEventFilter(self)
        self.position = 1
        self.position_y = 1

#        self.stream = [chr(c) for c in range(255)]
#        self.stream += [u'\u0218', u'\u0219']
#        self.show()

    def eventFilter(self, watched, event):
 #       print event
        if event.type() == QtCore.QEvent.KeyPress:
            key = event.key()
            modifiers = event.modifiers()

            
            if modifiers == QtCore.Qt.ControlModifier:
                if key == QtCore.Qt.Key_Right:
                    self.read_pos += 1
                    self.getStream(self.data)
                    self.scroll_right = True
                    self.scroll = True
#                    self.painted = False

                if key == QtCore.Qt.Key_Left:
                    self.read_pos -= 1
                    self.getStream(self.data)
                    self.painted = False

                self.update()
                return False

            if modifiers == QtCore.Qt.ShiftModifier:
                if key == QtCore.Qt.Key_Right:
                    self.selection += 1

                if key == QtCore.Qt.Key_Left:
                    self.selection -= 1

                if key == QtCore.Qt.Key_Down:
                    self.selection += self.NUMBER_COLS

                if key == QtCore.Qt.Key_Up:
                    self.selection -= self.NUMBER_COLS

                self.update()
                return False

            self.selection = 0
            if key == QtCore.Qt.Key_Right:
                if self.position < self.NUMBER_COLS:
                    self.position += 1
                else:
                    self.position = 1
                    self.position_y += 1

            if key == QtCore.Qt.Key_Left:
                if self.position > 1:
                    self.position -= 1
                else:
                    if self.position_y > 1:
                        self.position = self.NUMBER_COLS
                        self.position_y -= 1
                        self.painted = False
                
            if key == QtCore.Qt.Key_Up:
                if self.position_y > 1:
                    self.position_y -= 1

            if key == QtCore.Qt.Key_Down:
                if self.position_y < 50:
                    self.position_y += 1


                if self.position_y >= 50:
                    self.read_pos += self.NUMBER_COLS
                    self.getStream(self.data)
                    self.scroll = True
#                    self.painted = False

            if key == QtCore.Qt.Key_PageDown:
                self.read_pos += self.NUMBER_COLS*20;
                self.getStream(self.data)
                self.painted = False
#                self.kataka=True

            if key == QtCore.Qt.Key_PageUp:
                self.read_pos -= self.NUMBER_COLS*20;
                self.getStream(self.data)
                self.painted = False

            if key == QtCore.Qt.Key_Tab:
                if self.drawMode == 1:
                    self.drawMode = 2
                else:
                    self.drawMode = 1
                self.painted = False
            #print self.position


            self.from_where = (self.position_y - 1)*170
            self.to_where   = (self.position_y + 1)*170
#            self.update(0, (self.position_y - 1)*16, 1624, 2*16)

            self.update()
#            self.stream[1] += 1
            #print 'etc'
        return False
                                             
#    def keyPressEvent(self, e):
#        print e
#        e.accept()

#    def mousePressEvent(self, event):
#        print 'a'
#        event.accept()

#    def event(self, event):
#        print event
#        if event.type() == QtCore.QEvent.KeyPress:
#            print 'da'
#        return QtGui.QWidget.event(self, event)

    def paintEvent(self, e):

        if self.painted == False:      
            self.qpix = QtGui.QPixmap(self.size().width(), self.size().height())
            qp2 = QtGui.QPainter()

            qp2.begin(self.qpix)
            if self.drawMode == 2:
                self.drawWidget(qp2)
            else:
                self.drawTextMode(qp2)

            qp2.end()
            self.painted = True

        qp = QtGui.QPainter()
        qp.begin(self)
        if self.scroll == False:
            qp.drawPixmap(0, 0, self.qpix)
        else:
            if self.scroll_right == True:
                self.qpix.scroll(-8, 0, 100, 20, (self.NUMBER_COLS+1)*8, 16*52)                

                # fac noua fila
                qpix2 = QtGui.QPixmap(self.size().width(), self.size().height())
            
                qp3 = QtGui.QPainter()
                qp3.begin(qpix2)
                qp3.drawPixmap(0, 0, self.qpix)
                self.drawTextMode3(qp3)
                qp3.end()
                self.qpix.swap(qpix2)

                qp.drawPixmap(0, 0, self.qpix)
                self.scroll_right = False

            else:
                self.qpix.scroll(0, -16, 100, 20, (self.NUMBER_COLS+1)*8, 16*52)

                # fac noua fila
                qpix2 = QtGui.QPixmap(self.size().width(), self.size().height())
            
                qp3 = QtGui.QPainter()
                qp3.begin(qpix2)
                qp3.drawPixmap(0, 0, self.qpix)
                self.drawTextMode2(qp3)
                qp3.end()
                self.qpix.swap(qpix2)

                qp.drawPixmap(0, 0, self.qpix)

            self.scroll = False

      

        if self.drawMode == 1:
            self.drawCursorsForTextMode(qp)
        else:
            self.drawCursorsForHexMode(qp)


        qp.end()



      
    def drawCursorsForTextMode(self, qp):
        # draw cursor on text
        font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)
        qp.setFont(font)
        metrics = qp.fontMetrics()
        fw = metrics.width('a')
        #rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(255, 255, 0))

        qp.drawRect(100 + self.position*fw , \
                    self.position_y * metrics.height() + 5, \
                    fw , \
                    metrics.height())

#        qp.setPen(QtGui.QColor(255, 255, 0))
        qp.setPen(QtGui.QColor("transparent"))

        qp.setBrush(QtGui.QColor(85, 155, 30))

        dy = 0
        dx = 0
        pos_x = self.position
        if self.selection != 0:
            qp.setOpacity(0.4)
            for i in range(self.selection):
                dx += 1
                if (pos_x + dx) % self.NUMBER_COLS == 0:
                    dy += 1
                    pos_x = 1
                    dx = 0
                qp.drawRect(100 + (pos_x + dx)*(fw), \
                            (self.position_y + dy) * metrics.height() + 5, \
                            fw, \
                            metrics.height())
        

    def drawCursorsForHexMode(self, qp):
        font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)
        qp.setFont(font)
        metrics = qp.fontMetrics()
        fw = metrics.width('a')
        #rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(255, 255, 0))

        # draw cursor on hex
        qp.drawRect(fw*3*self.position, \
                    self.position_y * metrics.height() + 5, \
                    3*fw, \
                    metrics.height() + 2)

        # draw cursor on text
        qp.drawRect(self.NUMBER_COLS*fw*3 + 100 + self.position*fw , \
                    self.position_y * metrics.height() + 5, \
                    fw + 4, \
                    metrics.height() + 2)
                                          

    def drawTextMode(self, qp):
        font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)
        font.setFixedPitch(True)
#       font = QtGui.QFont('Consolas', 11, QtGui.QFont.Light)
        qp.setFont(font)
        metrics = qp.fontMetrics()


        size = self.size()
        w = size.width()
        h = size.height()


        till = int(((w / 750.0) * 700))
        full = int(((w / 750.0) * 700))

        pen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, 
            QtCore.Qt.SolidLine)
        

        #the big rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(0, 0, 128))
        qp.drawRect(0, 0, w-2, h-2)

        #rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(255, 255, 0))
        fw = metrics.width('a')
#        print 'fw ' + str(fw)
#        print metrics.height()

        # draw cursor on text
#        qp.drawRect(100 + self.position*fw , \
#                    self.position_y * metrics.height() + 5, \
#                    fw + 4, \
#                    metrics.height() + 2)
                                          

        # textul (draw borders)   
        qp.setPen(pen)
        qp.setBrush(QtCore.Qt.NoBrush)
        qp.drawRect(0, 0, w-1, h-1)



#        height = (self.from_where/170)*20
        height = 20
       
        j = 1
#        for i, e in enumerate(self.stream[self.from_where:self.to_where]):
        for i, e in enumerate(self.stream):

            if i % 170 == 0:
                height += metrics.height()
                j = 1


            # draw ascii

            if i + 3 < self.MAX_DISPLAYED_CHARS:
                if self.isText(self.stream[i + 0]) and \
                   self.isText(self.stream[i + 1]) and \
                   self.isText(self.stream[i + 2]) and \
                   self.isText(self.stream[i + 3]):
                    qp.setPen(QtGui.QColor(255, 0, 0))

            if self.isText(self.stream[i]) == False:
                qp.setPen(pen)                

#            qp.drawText(self.NUMBER_COLS*fw*3 + 100  + j*10-fw/2, height, e)

            qp.drawText(100  + j*fw, height, e)

            j += 1
      


    def drawTextMode2(self, qp):
        font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)
        qp.setFont(font)
        metrics = qp.fontMetrics()


        size = self.size()
        w = size.width()
        h = size.height()




        till = int(((w / 750.0) * 700))
        full = int(((w / 750.0) * 700))

        pen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, 
            QtCore.Qt.SolidLine)
        

        #rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(255, 255, 0))
        fw = metrics.width('a')
#        print 'fw ' + str(fw)
#        print metrics.height()

        # draw cursor on text
#        qp.drawRect(100 + self.position*fw , \
#                    self.position_y * metrics.height() + 5, \
#                    fw + 4, \
#                    metrics.height() + 2)
                                          

        # textul (draw borders)   
        qp.setPen(pen)
        qp.setBrush(QtCore.Qt.NoBrush)
        qp.drawRect(0, 0, w-1, h-1)



#        height = (self.from_where/170)*20
        height = 20
       
        j = 1
#        for i, e in enumerate(self.stream[self.from_where:self.to_where]):
        offset = len(self.stream)/self.NUMBER_COLS
        height = (offset+1)*metrics.height()
                         

        for i, e in enumerate(self.stream[(offset-1)*self.NUMBER_COLS:(offset-1)*self.NUMBER_COLS + self.NUMBER_COLS]):
#            if i % 170 == 0:
#                height += metrics.height()
#                j = 1


            # draw ascii

            if i + 3 < self.MAX_DISPLAYED_CHARS:
                if self.isText(self.stream[i + 0]) and \
                   self.isText(self.stream[i + 1]) and \
                   self.isText(self.stream[i + 2]) and \
                   self.isText(self.stream[i + 3]):
                    qp.setPen(QtGui.QColor(255, 0, 0))

            if self.isText(self.stream[i]) == False:
                qp.setPen(pen)                

#            qp.drawText(self.NUMBER_COLS*fw*3 + 100  + j*10-fw/2, height, e)

#            if len(self.stream) - i > 170:
#                continue

            qp.drawText(100  + j*fw, height, e)

            j += 1

    def drawTextMode3(self, qp):
        font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)
        qp.setFont(font)
        metrics = qp.fontMetrics()


        size = self.size()
        w = size.width()
        h = size.height()




        till = int(((w / 750.0) * 700))
        full = int(((w / 750.0) * 700))

        pen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, 
            QtCore.Qt.SolidLine)
        

        #rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(255, 255, 0))
        fw = metrics.width('a')
                                          

        # textul (draw borders)   
        qp.setPen(pen)
        qp.setBrush(QtCore.Qt.NoBrush)
        qp.drawRect(0, 0, w-1, h-1)



#        height = (self.from_where/170)*20
        height = 20
       
        j = 1
        ROW = []
        for k in range(self.MAX_DISPLAYED_CHARS/self.NUMBER_COLS - 1):
            ROW += [self.stream[(k+1)*self.NUMBER_COLS]]


        
#        for i, e in enumerate(self.stream[self.from_where:self.to_where]):
#        offset = len(self.stream)/self.NUMBER_COLS
        height = 20 + 16
        
#        qp.setBackgroundMode(1)
#        qp.setBackground(QtGui.QBrush(QtGui.QColor(0, 0, 128)))
        qp.fillRect(100, 20, fw, 16*50, QtGui.QBrush(QtGui.QColor(0, 0, 128)))

        qp.fillRect(100 + self.NUMBER_COLS*fw, 20, 2*fw, 16*50, QtGui.QBrush(QtGui.QColor(0, 0, 128)))
#        qp.setWindow(200, 20, self.NUMBER_COLS*fw, 16*50)
#        qp.setClipping(True)
#        qp.drawText(0, 20, 'Marius')
        for i, e in enumerate(ROW):
            if i + 3 < 50:
                if self.isText(self.stream[(i+1)*self.NUMBER_COLS + 0]) and \
                   self.isText(self.stream[(i+1)*self.NUMBER_COLS + 1]) and \
                   self.isText(self.stream[(i+1)*self.NUMBER_COLS + 2]) and \
                   self.isText(self.stream[(i+1)*self.NUMBER_COLS + 3]):
                   qp.setPen(QtGui.QColor(255, 0, 0))

            if self.isText(e) == False:
                qp.setPen(pen)                

            qp.drawText(100 + self.NUMBER_COLS*fw, height, e)
            height += metrics.height()

#        for i, e in enumerate(self.stream[(offset-1)*self.NUMBER_COLS:(offset-1)*self.NUMBER_COLS + self.NUMBER_COLS]):
#            if i % 170 == 0:
#                height += metrics.height()
#                j = 1


            # draw ascii

#            if i + 3 < self.MAX_DISPLAYED_CHARS:
#                if self.isText(self.stream[i + 0]) and \
#                   self.isText(self.stream[i + 1]) and \
#                   self.isText(self.stream[i + 2]) and \
#                   self.isText(self.stream[i + 3]):
#                    qp.setPen(QtGui.QColor(255, 0, 0))

#            if self.isText(self.stream[i]) == False:
#                qp.setPen(pen)                

#            qp.drawText(self.NUMBER_COLS*fw*3 + 100  + j*10-fw/2, height, e)

#            if len(self.stream) - i > 170:
#                continue

#            qp.drawText(100  + j*fw, height, e)

#            j += 1

    def drawWidget(self, qp):
#        font = QtGui.QFont('Serif', 12, QtGui.QFont.Light)
#        font = QtGui.QFont('ISO-8859-1', 12, QtGui.QFont.Light)
#        font = QtGui.QFont('Courier New', 12, QtGui.QFont.Light)
#        qp.setViewport(0, 0, 400, 400)
#        qp.setOpacity(0.8)
        font = QtGui.QFont('Terminus', 12, QtGui.QFont.Light)
        qp.setFont(font)
        metrics = qp.fontMetrics()



        size = self.size()
        w = size.width()
        h = size.height()

        j = 1


        till = int(((w / 750.0) * 700))
        full = int(((w / 750.0) * 700))

        pen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, 
            QtCore.Qt.SolidLine)
        

        #the big rectangle
#        qp.setBackground(QtGui.QBrush(QtGui.QColor(0, 0, 128)))
#        qp.setBackgroundMode(0)
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(0, 0, 128))
        qp.drawRect(0, 0, w-2, h-2)

        #rectangle
        qp.setPen(QtGui.QColor(255, 255, 255))
        qp.setBrush(QtGui.QColor(255, 255, 0))
        fw = metrics.width('a')
#        print 'fw ' + str(fw)
#        print metrics.height()

        qp.setOpacity(0.5)
        for i in range(self.NUMBER_COLS/4)[:-1]:
            qp.drawLine(fw*3 + fw*3*4*(i+1) - 4, 20, fw*3 + fw*3*4*(i+1) - 4, 800);

        qp.setOpacity(1)

        # textul (draw borders)   
        qp.setPen(pen)
        qp.setBrush(QtCore.Qt.NoBrush)
        qp.drawRect(0, 0, w-1, h-1)

        height = 20

        for i, e in enumerate(self.stream):

            if i % self.NUMBER_COLS == 0:
                height += metrics.height()
                j = 1

            # draw hex
#            print str(hex(ord(self.data[i]))[2:]),
            qp.drawText(j*(3*fw), height, str(hex(ord(self.data[self.read_pos+i]))[2:]).zfill(2) + ' ')

            # draw ascii
            
            if i + 3 < self.MAX_DISPLAYED_CHARS:
                if self.isText(self.stream[i + 0]) and \
                   self.isText(self.stream[i + 1]) and \
                   self.isText(self.stream[i + 2]) and \
                   self.isText(self.stream[i + 3]):
                    qp.setPen(QtGui.QColor(255, 0, 0))

            if self.isText(self.stream[i]) == False:
                qp.setPen(pen)                
#            qp.drawText(self.NUMBER_COLS*fw*3 + 100  + j*10-fw/2, height, e)
            qp.drawText(self.NUMBER_COLS*fw*3 + 100  + j*fw, height, e)

            j += 1
"""
        step = int(round(w / 10.0))


        till = int(((w / 750.0) * self.value))
        full = int(((w / 750.0) * 700))

        if self.value >= 700:
            qp.setPen(QtGui.QColor(255, 255, 255))
            qp.setBrush(QtGui.QColor(255, 255, 184))
            qp.drawRect(0, 0, full, h)
            qp.setPen(QtGui.QColor(255, 175, 175))
            qp.setBrush(QtGui.QColor(255, 175, 175))
            qp.drawRect(full, 0, till-full, h)
        else:
            qp.setPen(QtGui.QColor(255, 255, 255))
            qp.setBrush(QtGui.QColor(55, 255, 184))
            qp.drawRect(0, 0, till, h)


        pen = QtGui.QPen(QtGui.QColor(20, 20, 20), 1, 
            QtCore.Qt.SolidLine)
            
        qp.setPen(pen)
        qp.setBrush(QtCore.Qt.NoBrush)
        qp.drawRect(0, 0, w-1, h-1)

        j = 0

        for i in range(step, 10*step, step):
          
            qp.drawLine(i, 0, i, 5)
            metrics = qp.fontMetrics()
            fw = metrics.width(str(self.num[j]))
            qp.drawText(i-fw/2, h/2, str(self.num[j]))
            j = j + 1
"""            

class Example(QtGui.QWidget):
    
    def __init__(self):
        super(Example, self).__init__()
        
        self.initUI()
        
    def initUI(self):      

#        sld = QtGui.QSlider(QtCore.Qt.Horizontal, self)
        
#        sld.setRange(1, 750)
#        sld.setValue(75)
#        sld.setGeometry(30, 40, 150, 30)

#        self.c = Communicate()        
        self.wid = BurningWidget()
#        self.wid.setFocusPolicy(QtCore.Qt.WindowStaysOnTopHint)
#        self.c.updateBW[int].connect(self.wid.setValue)

#        sld.valueChanged[int].connect(self.changeValue)
        hbox = QtGui.QHBoxLayout()
        hbox.addWidget(self.wid)
#        vbox = QtGui.QVBoxLayout()
#        vbox.addStretch(1)
#        vbox.addLayout(hbox)
        self.setLayout(hbox)

        screen = QtGui.QDesktopWidget().screenGeometry()        
        self.setGeometry(0, 0, screen.width(), screen.height())
#        self.setGeometry(100, 300, 1424, 310)
        self.setWindowTitle('Burning widget')
#        self.setCentralWidget(self.wid)

#        self.setFocusPolicy(QtCore.Qt.NoFocus)
#        self.showFullScreen()
        self.show()
#        self.raise_()
        self.wid.activateWindow()


        
    def changeValue(self, value):
             
#        self.c.updateBW.emit(value)        
        self.wid.repaint()
        
def main():
    
    app = QtGui.QApplication(sys.argv)
    ex = Example()
#    scrollArea = QtGui.QScrollArea();
#    scrollArea.setBackgroundRole(QtGui.QPalette.Dark);
#    scrollArea.setWidget(ex);
#    ex = BurningWidget()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
