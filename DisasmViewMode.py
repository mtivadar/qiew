from ViewMode import *
from cemu import *
import TextSelection

from PyQt4 import QtGui, QtCore
from time import time 
import sys
import threading
import re
import binascii

import distorm3



class ASMLine:
    def __init__(self, d, plugin):
        self._hexstr = self.hexlify(d.instructionBytes)
        self._instruction = str(d)
        self._size = d.size
        self._addr = d.address
        self._mnemonic = d.mnemonic
        self._d = d
        self.refString = ''

        if 'FLAG_RIP_RELATIVE' in d.flags:
            if len(d.operands) > 1:
                o = d.operands[1]
                if o.dispSize != 0:
                    x =  d.address + d.size + o.disp
                    self.refString = plugin.stringFromVA(x)

        elif d.mnemonic == 'PUSH':

            o = d.operands[0]
            if o.type == 'Immediate':
                self.refString = plugin.stringFromVA(o.value)

        else:
            pass




    def hexlify(self, sb):
        hexstr = binascii.hexlify(sb)
        hexstr = ' '.join([hexstr[i:i+2] for i in range(0, len(hexstr), 2)])
        return hexstr

    @property
    def size(self):
        return self._size

    @property
    def offset(self):
        return self._addr

    @property
    def hex(self):
        return self._hexstr    

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def instruction(self):
        return self._instruction
      
    @property
    def restOfInstr(self):
        #TODO: should test if flag is CANNOT_DECODE instead. We check for 'DB 0xYY'
        if ' ' not in self.mnemonic:
            return ' '.join(self.instruction.split(' ')[1:])
        else:
            return ''

    @property
    def refString(self):
        return self.refString

    @property
    def obj(self):
        return self._d
    
class DisasmViewMode(ViewMode):
    def __init__(self, width, height, data, cursor, widget=None, plugin=None):
        super(ViewMode, self).__init__()

        self.plugin = plugin

        self.dataModel = data
        self.addHandler(self.dataModel)


        self.width = width
        self.height = height
        #self.cursorX = 0
        #self.cursorY = 0

        self.cursor = cursor
        self.widget = widget

        self.refresh = True

        self.selector = TextSelection.DefaultSelection(self)

        # background brush
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        # text font
        self.font = QtGui.QFont('Terminus', 11, QtGui.QFont.Light)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self._fontWidth  = fm.width('a')
        self._fontHeight = fm.height()

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 0, QtCore.Qt.SolidLine)
        self.resize(width, height)

        self.Paints = {}

        self.Ops = []
        self.newPix = None

        self.OPCODES = []
        self.ASMSeparators = ' ,.[]+-:'
        self.ASM_RE = delim = '|'.join(map(re.escape, self.ASMSeparators))

        self.DRAW_AREA = 0
        self.selector = TextSelection.DisasmSelection(self)

    @property
    def fontWidth(self):
        return self._fontWidth

    @property
    def fontHeight(self):
        return self._fontHeight

    def setTransformationEngine(self, engine):
        self.transformationEngine = engine

    def resize(self, width, height):
        self.width = width - width%self.fontWidth
        self.height = height - height%self.fontHeight
        self.computeTextArea()
        self.qpix = self._getNewPixmap(self.width, self.height)
        self.refresh = True

    def computeTextArea(self):
        self.COLUMNS = self.width/self.fontWidth
        self.ROWS    = self.height/self.fontHeight
        self.notify(self.ROWS, self.COLUMNS)

    def getPixmap(self):
        for t in self.Ops:
            if len(t) == 1:
                t[0]()

            else:
                t[0](*t[1:])

        self.Ops = []
        
        if not self.newPix:
            self.draw()

        return self.newPix


    def getPageOffset(self):
        return self.dataModel.getOffset()

    def getGeometry(self):
        return self.COLUMNS, self.ROWS

    def getDataModel(self):
        return self.dataModel

    def startSelection(self):
        self.selector.startSelection()

    def stopSelection(self):
        self.selector.stopSelection()

    def getCursorAbsolutePosition(self):
        x, y = self.cursor.getPosition()
        preY = sum([asm.size for asm in self.OPCODES[:y]])

        asm = self.OPCODES[y]

        if x < len(asm.hex):
            postY = x/3
        else:
            postY = asm.size

        return self.dataModel.getOffset() + preY + postY

    def drawCursor(self, qp):
        cursorX, cursorY = self.cursor.getPosition()

        asm = self.OPCODES[cursorY]
        line = self.DRAW_AREA*' ' + asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

        x = cursorX
        """
        while x-1 > self.DRAW_AREA:
            if x-1 < len(line):
                if line[x-1] not in self.ASMSeparators:
                    x -= 1
                else:
                    break
        """
        xstart = x

        x = cursorX
        while x < len(line):
            if x < len(line):
                if line[x] not in self.ASMSeparators:
                    x += 1
                else:
                    break

        xend = x
        

        qp.setBrush(QtGui.QColor(255, 255, 0))

        qp.setOpacity(0.5)
        qp.drawRect(xstart*self.fontWidth, cursorY*self.fontHeight, (xend - xstart)*self.fontWidth, self.fontHeight + 2)
        qp.setOpacity(1)



    def drawSelected(self, qp):
        qp.setFont(self.font)
        cursorX, cursorY = self.cursor.getPosition()

        qasm = self.OPCODES[cursorY]
        line = self.DRAW_AREA*' ' + qasm.hex + (30 - len(qasm.hex))*' ' + qasm.mnemonic + (10 - len(qasm.mnemonic))*' ' + qasm.restOfInstr

        xstart = cursorX

        x = cursorX
        while x < len(line):
            if x < len(line):
                if line[x] not in self.ASMSeparators:
                    x += 1
                else:
                    break

        xend = x

        text = line[xstart:xend]

        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        for i, asm in enumerate(self.OPCODES):
            line = asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

            for g in [line]:
                if text in g:

                    for xstart in [m.start() for m in re.finditer(text, g)]:
                        qp.setBrush(QtGui.QColor(255, 255, 0))
                        qp.setPen(QtGui.QColor(255, 255, 0))
                        xend = len(text)

                        #print text

                        if i == cursorY and xstart == cursorX:
                            continue

                        
                        if xstart + xend + 1 < len(line):
                            if line[xstart + xend] not in self.ASMSeparators:
                                continue

                        if xstart - 1 > 0:
                            if line[xstart - 1] not in self.ASMSeparators:
                                continue

                        qp.setOpacity(0.4)
                        #qp.drawRect(xstart*self.fontWidth, i*self.fontHeight, (xend - xstart)*self.fontWidth, self.fontHeight + 2)
                        brush=QtGui.QBrush(QtGui.QColor(0, 255, 0))
                        qp.fillRect(xstart*self.fontWidth, i*self.fontHeight + 2 , (len(text))*self.fontWidth, self.fontHeight, brush)
                        qp.setOpacity(1)

                        #print asm.hex
                        #qp.setPen(QtGui.QPen(QtGui.QColor(255, 0, 0)))
                        #cemu.writeAt(g.index(text), i, text)


#        qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))


    def drawBranch(self, qp):

        qp.fillRect(-50, 0, 50,  self.ROWS * self.fontHeight, self.backgroundBrush)

        cursorX, cursorY = self.cursor.getPosition()

        asm = self.OPCODES[cursorY]
        line = self.DRAW_AREA*' ' + asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

        if asm.mnemonic in ['JZ', 'JB', 'JP', 'CALL', 'JMP', 'JNZ']:
            #print dir(asm.obj)
            #print asm.obj.flowControl
            #print asm.obj.dt

            tsize = sum([o.size for o in self.OPCODES])
            msize = sum([o.size for o in self.OPCODES[:cursorY]])

            half = self.fontHeight/2
            for o in asm.obj.operands:

                #print 'operand ' + str(o)
                #print 'msize ' +  str(msize)

                target = o.value
                #print 'target ' + str(hex(target))

                screenVA = self._getVA(self.dataModel.getOffset())
                if target >  screenVA and target < self._getVA(self.dataModel.getOffset()) + tsize - self.OPCODES[-1].size:
                    # branch target is in screen

                    sz = 0
                    for i, t in enumerate(self.OPCODES):
                        sz += t.size
                        if sz+self._getVA(self.dataModel.getOffset()) >= target:
                            break

                    #print self.OPCODES[i+1].instruction
                    qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.SolidLine))

                    
                    #qp.drawLine((len(line) + 1)*self.fontWidth, cursorY*self.fontHeight + self.fontHeight/2, len(line)*self.fontWidth + 200, cursorY*self.fontHeight + half)
                    qp.drawLine(-5, cursorY*self.fontHeight + self.fontHeight/2, -30, cursorY*self.fontHeight + half)

                    tasm = self.OPCODES[i+1]
                    tline = self.DRAW_AREA*' ' + tasm.hex + (30 - len(tasm.hex))*' ' + tasm.mnemonic + (10 - len(tasm.mnemonic))*' ' + tasm.restOfInstr

                    qp.drawLine(-30, cursorY*self.fontHeight + self.fontHeight/2, -30, (i + 1)*self.fontHeight + half)
                    #print tline
                    qp.drawLine(-30, (i + 1)*self.fontHeight + half, -15, (i + 1)*self.fontHeight + half)

                    points = [QtCore.QPoint(-15, (i + 1)*self.fontHeight + half - 5), 
                              QtCore.QPoint(-15, (i + 1)*self.fontHeight + half + 5), 
                              QtCore.QPoint(-5, (i + 1)*self.fontHeight + half), ]
                    needle = QtGui.QPolygon(points)
                    qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 128, 0)))
                    qp.drawPolygon(needle)



                elif target > screenVA:
                    # branch is at greater address, out of screen
                    qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.SolidLine))

                    qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.DotLine))

                    qp.drawLine(-5, cursorY*self.fontHeight + self.fontHeight/2, -30, cursorY*self.fontHeight + half)
                    qp.drawLine(-30, cursorY*self.fontHeight + self.fontHeight/2, -30, (self.ROWS - 2)*self.fontHeight + half)

                    points = [QtCore.QPoint(-25, (self.ROWS - 2)*self.fontHeight + half), 
                              QtCore.QPoint(-35, (self.ROWS - 2)*self.fontHeight + half), 
                              QtCore.QPoint(-30, (self.ROWS - 2)*self.fontHeight + 2*half), ]
                    needle = QtGui.QPolygon(points)
                    qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 128, 0)))
                    qp.drawPolygon(needle)

                else:
                    # upper arrow
                    # branch is at lower address, out of screen

                    qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.SolidLine))

                    qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.DotLine))

                    qp.drawLine(-5, cursorY*self.fontHeight + self.fontHeight/2, -30, cursorY*self.fontHeight + half)
                    qp.drawLine(-30, cursorY*self.fontHeight + self.fontHeight/2, -30, (1)*self.fontHeight + half)

                    points = [QtCore.QPoint(-25, (1)*self.fontHeight + half), 
                              QtCore.QPoint(-35, (1)*self.fontHeight + half), 
                              QtCore.QPoint(-30, (1)*self.fontHeight), ]
                    needle = QtGui.QPolygon(points)
                    qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 128, 0)))
                    qp.drawPolygon(needle)
                    #qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.DashedLine))



    def draw(self, refresh=False):
        if self.dataModel.getOffset() in self.Paints:
            self.refresh = False
            self.qpix = QtGui.QPixmap(self.Paints[self.dataModel.getOffset()])
            #print 'hit'
            self.drawAdditionals()
            return

        if self.refresh or refresh:
            qp = QtGui.QPainter()
            qp.begin(self.qpix)
            # viewport
            #qp.fillRect(0, 0, self.COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight, self.backgroundBrush)

            #start = time()
            self.drawTextMode(qp)
            #end = time() - start
            #print 'Time ' + str(end)
            self.refresh = False
            qp.end()

#        self.Paints[self.dataModel.getOffset()] = QtGui.QPixmap(self.qpix)
        self.drawAdditionals()

    def drawAdditionals(self):
        self.newPix = self._getNewPixmap(self.width, self.height)
        qp = QtGui.QPainter()
        qp.begin(self.newPix)
        qp.setWindow(-50, 0, self.COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight)

        qp.drawPixmap(0, 0, self.qpix)

        #self.transformationEngine.decorateText()

        # highlight selected text
        self.selector.highlightText()

        # draw other selections
        self.selector.drawSelections(qp)

        # draw our cursor
        self.drawCursor(qp)

        #qp.setViewport(0, 0, 50,  self.ROWS * self.fontHeight)
        """
        self.newPix = self._getNewPixmap(50, self.height)
        qp = QtGui.QPainter()
        qp.begin(self.newPix)

        qp.setViewport(0, 0, 50,  self.ROWS * self.fontHeight)
        """
        self.drawBranch(qp)
        self.drawSelected(qp)
        qp.end()

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

    def getColumnsbyRow(self, row):
        if row < len(self.OPCODES):
            obj = self.OPCODES[row]
            return obj.size
        else:
            return 0
        

    def _buildOpstr(self, hexdump, instruction):
        s = ''
        for i in range(10):
            if len(hexdump) > i*2 + 2 - 1:
                s += hexdump[i*2:i*2 + 2] + ' '


        s += ' '*(30 - len(s))

        s += instruction

        return s

    def _getVA(self, offset):
        if self.plugin:
            return self.plugin.hintDisasmVA(offset)

        return 0

    def _getOpcodes(self, ofs, code, dt):
        
        self.OPCODES = []        

        DEC = distorm3.DecomposeGenerator(self._getVA(ofs), code, dt)
        g = 0
        for d in DEC:
            newline = ASMLine(d, self.plugin)
            if 'FLAG_RIP_RELATIVE' in newline.obj.flags:
                #print dir(newline.obj)
#                if newline.obj.dispSize:
 #                   print str(newline.obj) + ' ' + str(newline.obj.flags)

  #                  print newline.obj.address + newline.obj.size + newline.obj.disp

                if len(newline.obj.operands) > 1:
                    o = newline.obj.operands[1]
                    if o.dispSize != 0:
                        print newline.obj
                        print hex(o.disp)
                        x =  newline.obj.address + newline.obj.size + o.disp
                        print self.plugin.stringFromVA(x)


            self.OPCODES.append(newline)
            g += 1
            if g == self.ROWS:
                break


    def _drawRow(self, qp, cemu, row, asm):
        qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))

        # write hexdump
        cemu.writeAt(0, row, asm.hex)

        # fill with spaces
        cemu.write((30 - len(asm.hex))*' ')


        # let's color some branch instr
        if asm.mnemonic in ['JZ', 'JB', 'JP', 'CALL', 'JMP', 'JNZ']:
            qp.setPen(QtGui.QPen(QtGui.QColor(255, 0, 0)))
        else:
            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))
        
        cemu.write(asm.mnemonic)
        cemu.write((10-len(asm.mnemonic))*' ')

        cemu.write(asm.restOfInstr)

        if len(asm.refString) > 4:
            cemu.write((30-len(asm.restOfInstr))*' ')

            qp.setPen(QtGui.QPen(QtGui.QColor(82, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write('; ' + asm.refString)


    def drawTextMode(self, qp):
        # draw background
        qp.fillRect(0, 0, self.COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight, self.backgroundBrush)

        # set text pen&font
        qp.setFont(self.font)
        qp.setPen(self.textPen)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        if len(self.OPCODES) == 0:

            self._getOpcodes(self.dataModel.getOffset(), str(self.getDisplayablePage()), self.plugin.hintDisasm())



        for i in range(self.ROWS):
            if i < len(self.OPCODES):
                asm = self.OPCODES[i]
                self._drawRow(qp, cemu, i, asm)


    def goTo(self, offset):
        tsize = sum([asm.size for asm in self.OPCODES])

        if offset < self.dataModel.getOffset() + tsize and offset > self.dataModel.getOffset():
            # if in current page, move cursore
            x, y = self.dataModel.getXYInPage(offset)
            self.cursor.moveAbsolute(y + self.DRAW_AREA, x)
        else:
            # else, move page
            self.dataModel.goTo(offset)
            self.cursor.moveAbsolute(self.DRAW_AREA, 0)
            #self.draw(refresh=True)

        #TODO: getDisplayablePage() won't contain what we want to disasm. we will use dataModel
        #      in this view, getDisplayablePage will contain disasm text, because that is what is displayed
        self._getOpcodes(offset, str(self.getDisplayablePage()), self.plugin.hintDisasm())

        self.draw(refresh=True)
        if self.widget:
            self.widget.update()


    def scrollPages(self, number, cachePix=None, pageOffset=None):
        self.scroll(0, -number*self.ROWS, cachePix=cachePix, pageOffset=pageOffset)

    def scroll_v(self, dy, cachePix=None, pageOffset=None):
        start = time()        

        if not cachePix:
            self.qpix.scroll(0, dy*self.fontHeight, self.qpix.rect())

        qp = QtGui.QPainter()

        if cachePix:
            qp.begin(cachePix)
        else:
            qp.begin(self.qpix)

        #self.font.setStyleHint(QtGui.QFont.AnyStyle, QtGui.QFont.PreferAntialias)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dy)
        if dy < 0:
            qp.fillRect(0, (self.ROWS-factor)*self.fontHeight, self.fontWidth*self.COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        if dy > 0:
            qp.fillRect(0, 0, self.fontWidth*self.COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        lastPen = None
        lastBrush = None

        
        # repeat as many rows we have scrolled
        
        for row in range(factor):

            if dy < 0:
                tsize = sum([asm.size for asm in self.OPCODES])

                #self.dataModel.slide(self.OPCODES[0].size)
                start = self.dataModel.getOffset() + tsize

                # let's say we decode maximum 50 bytes
                end = start + 50

                # make sure we won't jump off the limits
                if start > self.dataModel.getDataSize():
                    return

                if end > self.dataModel.getDataSize():
                    end = self.dataModel.getDataSize()

                if start == end:
                    return

                iterable = distorm3.Decompose(self._getVA(start), str(self.dataModel.getStream(start, end)), self.plugin.hintDisasm())
                # eat first instruction from the page
                d = iterable[0]
                #print str(hex(start)) + '  ' + str(hex(d.size))

            if dy >= 0:
                # we try to decode from current offset - 50, in this case even if decoding is incorrect (will overlap),
                # in 50 bytes it is possible to correct itself, so hopefully last instruction it's decoded corectly and
                # followed correctly by current_offset instruction
                if self.dataModel.getOffset() < 50:
                    start = 0
                else:
                    start = self.dataModel.getOffset() - 50


                end = self.dataModel.getOffset()
                #print 'end ' + str(hex(end))
                iterable = distorm3.Decompose(self._getVA(start), str(self.dataModel.getStream(start, end)), self.plugin.hintDisasm())

                d = iterable[-1]

            #hexstr = self.hexlify(self.dataModel.getStream(start + d.address, start + d.address + d.size))
            newasm = ASMLine(d, self.plugin)

            if dy < 0:
                self.dataModel.slide(self.OPCODES[0].size)
                del self.OPCODES[0]


            if dy >= 0:
                self.dataModel.slide(-d.size)
                del self.OPCODES[len(self.OPCODES) - 1]

            


            if dy < 0:
                self.OPCODES.append(newasm)

            if dy > 0:
                self.OPCODES.insert(0, newasm)

            if dy < 0:
                #self._drawRow(qp, cemu, self.ROWS - 1, newasm)
                self._drawRow(qp, cemu, self.ROWS - factor + row , newasm)

            if dy > 0:
                #print newasm.instruction
                self._drawRow(qp, cemu, factor - row - 1, newasm)

            qp.setBackgroundMode(0)

          

        qp.end()

        end = time() - start

    def scroll(self, dx, dy, cachePix=None, pageOffset=None):
        if dx != 0:
            if self.dataModel.inLimits((self.dataModel.getOffset() - dx)):
                self.dataModel.slide(dx)
                self.draw(refresh=True)
                #self.scroll_h(dx)

        if dy != 0:
            if dy > 0:
                if self.dataModel.getOffset() == 0:
                    return

            if dy < 0:
                tsize = sum([asm.size for asm in self.OPCODES])

                if self.dataModel.getOffset() + tsize ==  self.dataModel.getDataSize():
                    return

            self.scroll_v(dy, cachePix, pageOffset)


    def moveCursor(self, direction):
        cursorX, cursorY = self.cursor.getPosition()

        if direction == Directions.Left:
            asm = self.OPCODES[cursorY]
            line = asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

            if cursorX == 0:
                if cursorY == 0:
                    self.scroll(0, 1)
                    self.cursor.moveAbsolute(0, 0)
                else:
                    self.cursor.moveAbsolute(0, cursorY - 1)
            else:
                x = cursorX - 1

                while x >= 0 and line[x] in self.ASMSeparators:
                    x -= 1

                while x >= 0 and line[x] not in self.ASMSeparators:
                    x -= 1

                print line[cursorX:]
                print line[x:]


                self.cursor.move(-(cursorX-x) + 1, 0)


        if direction == Directions.Right:
            asm = self.OPCODES[cursorY]
            line = self.DRAW_AREA*' ' + asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

            if cursorX == len(line) - 1:
#            if cursorX == self.COLUMNS-1:
                if cursorY == self.ROWS-1:
                    #self.dataModel.slide(1)
                    self.scroll(0, -1)
                    self.cursor.moveAbsolute(0, cursorY)
                else:
                    self.cursor.moveAbsolute(0, cursorY + 1)
            else:
                x = cursorX
                while x < len(line) - 1 and line[x] not in self.ASMSeparators:
                    x += 1

                while x < len(line) - 1 and line[x] in self.ASMSeparators:
                    x += 1

                self.cursor.move(x-cursorX, 0)
                #self.cursorX += 1

        if direction == Directions.Down:
            if cursorY == self.ROWS-1:
                self.scroll(0, -1)
            else:
                if cursorY < len(self.OPCODES)-1:
                    self.cursor.move(0, 1)

        if direction == Directions.Up:
            if cursorY == 0:
                self.scroll(0, 1)
            else:
                self.cursor.move(0, -1)

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

    def handleKeyEvent(self, modifiers, key):

        if modifiers == QtCore.Qt.ControlModifier:
            if key == QtCore.Qt.Key_Right:
                self.dataModel.slide(1)

                self.addop((self.scroll, -1, 0))
                #self.scroll(-1, 0)

            if key == QtCore.Qt.Key_Left:
                self.dataModel.slide(-1)
                self.addop((self.scroll, 1, 0))
                #self.scroll(1, 0)

            if key == QtCore.Qt.Key_Down:
                self.addop((self.scroll, 0, -1))
                self.addop((self.draw,))

            if key == QtCore.Qt.Key_Up:
                self.addop((self.scroll, 0, 1))
                self.addop((self.draw,))

            if key == QtCore.Qt.Key_End:
                self.moveCursor(Directions.CtrlEnd)
                self.addop((self.draw,))
                #self.draw()

            if key == QtCore.Qt.Key_Home:
                self.moveCursor(Directions.CtrlHome)
                self.addop((self.draw,))
                #self.draw()

            return True

        else:#selif modifiers == QtCore.Qt.NoModifier:

            if key == QtCore.Qt.Key_Left:
                self.moveCursor(Directions.Left)
                self.addop((self.draw,))
                #self.draw()

            if key == QtCore.Qt.Key_Right:
                self.moveCursor(Directions.Right)
                self.addop((self.draw,))
                #self.draw()
                
            if key == QtCore.Qt.Key_Down:
                self.moveCursor(Directions.Down)
                self.addop((self.draw,))
                #self.draw()
                
            if key == QtCore.Qt.Key_End:
                self.moveCursor(Directions.End)
                self.addop((self.draw,))
                #self.draw()
                
            if key == QtCore.Qt.Key_Home:
                self.moveCursor(Directions.Home)
                self.addop((self.draw,))
                #self.draw()

            if key == QtCore.Qt.Key_Up:
                self.moveCursor(Directions.Up)
                self.addop((self.draw,))
                #self.draw()
                
            if key == QtCore.Qt.Key_PageDown:
                self.addop((self.scrollPages, 1))
                self.addop((self.draw,))
    
            if key == QtCore.Qt.Key_PageUp:
                self.addop((self.scrollPages, -1))
                self.addop((self.draw,))

            return True

        return False

    def handleKeyPressEvent(self, modifier, key):
        if modifier == QtCore.Qt.ShiftModifier:
            self.startSelection()
            return True

    def handleKeyReleaseEvent(self, modifier, key):
        if modifier == QtCore.Qt.ShiftModifier:
            self.stopSelection()
            return True


    def addop(self, t):
        self.Ops.append(t)
