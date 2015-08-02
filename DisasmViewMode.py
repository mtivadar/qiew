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
        self._str = ' '.join(self.instruction.split(' ')[1:])

        # gets ref string (only for PUSH and RIP addressing)
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


        # get symbol
        self.symbol = None
        asm = d
        value = None
        if asm.flowControl != 'FC_NONE':
            for o in asm.operands:
                if o.dispSize != 0:
                    if 'FLAG_RIP_RELATIVE' in asm.flags:
                        value =  asm.address + asm.size + o.disp
                    else:
                        value = o.disp
                else:
                    value = o.value

            if value:
                sym = plugin.disasmSymbol(value)

                if sym:
                    self.symbol = sym



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
        asm = self._d

        if 'FLAG_NOT_DECODABLE' in asm.flags:
            return ''
        else:
            #return ', '.join([str(o) for o in asm.operands])
            return self._str

    @restOfInstr.setter
    def restOFInstr(self, value):
        self._str = value

    @property
    def refString(self):
        return self.refString

    @property
    def obj(self):
        return self._d
    
class DisasmViewMode(ViewMode):
    def __init__(self, width, height, data, cursor, widget=None, plugin=None):
        super(DisasmViewMode, self).__init__()

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

        self.FlowHistory = []
        self.OPCODES = []
        self.ASMSeparators = ' ,.[]+-:'
        self.ASM_RE = delim = '|'.join(map(re.escape, self.ASMSeparators))

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
        self.qpix = self._getNewPixmap(self.width, self.height + self.SPACER)
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
        line = asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

        x = cursorX
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
        line = qasm.hex + (30 - len(qasm.hex))*' ' + qasm.mnemonic + (10 - len(qasm.mnemonic))*' ' + qasm.restOfInstr

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
        line = asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

        if asm.obj.flowControl != 'FC_NONE':
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
                    tline = tasm.hex + (30 - len(tasm.hex))*' ' + tasm.mnemonic + (10 - len(tasm.mnemonic))*' ' + tasm.restOfInstr

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
        self.newPix = self._getNewPixmap(self.width, self.height + self.SPACER)
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
            self.OPCODES.append(newline)
            g += 1
            if g == self.ROWS:
                break


    def _opdelegate(self, s, type, qp, cemu):
        qp.save()
        if type == 'VALUE':
            qp.setPen(QtGui.QPen(QtGui.QColor('green')))
        elif type == 'REGISTER':
            qp.setPen(QtGui.QPen(QtGui.QColor('white')))
        elif type == 'SYM':
            qp.setPen(QtGui.QPen(QtGui.QColor('yellow'), 1, QtCore.Qt.SolidLine))
        else:
            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))


        for c in s:
            cemu.write_c(c)

        qp.restore()
        return s


    def _expandOp(self, asm, callback, args):

        SIZE = {}
        SIZE[0] = ''
        SIZE[8]  = 'BYTE'
        SIZE[16] = 'WORD'
        SIZE[32] = 'DWORD'
        SIZE[64] = 'QWORD'

        r = ''
        for i, o in enumerate(asm.operands):
            #print o.size
            # put memory size modifier
            # todo: i don't like this, but i'm not sure how to do it other way
            if len(asm.operands) == 2:

                if i == 0 and o.type == distorm3.OPERAND_MEMORY:
                    g = asm.operands[1]
                    if g.type == distorm3.OPERAND_IMMEDIATE:
                        if len(set([p.size for p in asm.operands])) > 1:
                            r += callback(SIZE[o.size], 'OP', *args)    
                            r += callback(' ', 'OP', *args)

                if i == 1 and o.type == distorm3.OPERAND_MEMORY:
                    g = asm.operands[0]
                    if g.size != o.size and o.size != 0:
                        r += callback(SIZE[o.size], 'OP', *args)
                        r += callback(' ', 'OP', *args)

            if o.type == distorm3.OPERAND_IMMEDIATE:
                if o.value >= 0:
                    r += callback("0x%x" % o.value, 'VALUE', *args)

                else:
                    r += callback("-0x%x" % abs(o.value), 'VALUE', *args)

            elif o.type == distorm3.OPERAND_REGISTER:
                r += callback(o.name, 'REGISTER', *args)

            elif o.type == distorm3.OPERAND_ABSOLUTE_ADDRESS:
                r += callback('[', 'OP', *args)
                r += callback('0x%x'%o.disp, 'VALUE', *args)
                r += callback(']', 'OP', *args)

            elif o.type == distorm3.OPERAND_FAR_MEMORY:
                r += callback('%s' % hex(o.seg), 'REGISTER', *args)
                r += callback(':', 'OP', *args)
                r += callback('%s' % hex(o.off), 'REGISTER', *args)

            elif (o.type == distorm3.OPERAND_MEMORY):
                r += callback('[', 'OP', *args)

                if o.base != None:
                    r += callback(distorm3.Registers[o.base], 'REGISTER', *args)
                    r += callback('+', 'OP', *args)

                if o.index != None:
                    r += callback(distorm3.Registers[o.index], 'REGISTER', *args)
                    if o.scale > 1:
                        r += callback('*%d'%o.scale, 'VALUE', *args)

                if o.disp >= 0:
                    r += callback('+0x%x'%o.disp, 'VALUE', *args)
                else:
                    r += callback('-0x%x'%abs(o.disp), 'VALUE', *args)

                r += callback(']', 'OP', *args)

            if i != len(asm.operands) - 1:
                r += callback(', ', 'OP', *args)

        return r


    def _drawRow(self, qp, cemu, row, asm):
        qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))

        # write hexdump
        cemu.writeAt(0, row, asm.hex)

        # fill with spaces
        cemu.write((30 - len(asm.hex))*' ')

        # let's color some branch instr
        if asm.obj.flowControl != 'FC_NONE':
            qp.setPen(QtGui.QPen(QtGui.QColor(255, 0, 0)))
        else:
            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))
        
        cemu.write(asm.mnemonic)

        # leave some spaces
        cemu.write((10-len(asm.mnemonic))*' ')

        if asm.symbol:
            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write_c('[')

            qp.setPen(QtGui.QPen(QtGui.QColor('yellow'), 1, QtCore.Qt.SolidLine))
            cemu.write(asm.symbol)

            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write_c(']')

            result = '[' + asm.symbol + ']'
        else:
            result = self._expandOp(asm.obj, self._opdelegate, (qp, cemu))

        #print result
        # ugly, but necessary for the cursor move to function well
        # we save the instruction as a string here
        asm.restOfInstr = result        

        if len(asm.refString) > 4:
            cemu.write((30-len(asm.restOfInstr))*' ')

            qp.setPen(QtGui.QPen(QtGui.QColor(82, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write('; "{0}"'.format(asm.refString))


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


    def _getRowInPage(self, offset):

        offset -= self.dataModel.getOffset()
        size = 0
        for i, asm in enumerate(self.OPCODES):
            if size + asm.size > offset:
                return i
            size += asm.size

        return None

    def _getOffsetOfRow(self, row):
        # of course, it could be done nicely, not like this
        size = 0
        for i, asm in enumerate(self.OPCODES):
            if i == row:
                return size

            size += asm.size                

        return None

    def goTo(self, offset):
        tsize = sum([asm.size for asm in self.OPCODES])

        if offset < self.dataModel.getOffset() + tsize and offset > self.dataModel.getOffset():
            # if in current page, move cursor
            row = self._getRowInPage(offset)
            off_row = self._getOffsetOfRow(row)
            diff = offset - self.dataModel.getOffset() - off_row# self.OPCODES[row].size

            if row is not None:
                self.cursor.moveAbsolute((diff)*3, row)

            self.draw(refresh=False)
        else:
            # else, move page
            self.dataModel.goTo(offset)
            self._getOpcodes(offset, str(self.getDisplayablePage()), self.plugin.hintDisasm())            
            self.cursor.moveAbsolute(0, 0)
            self.draw(refresh=True)

        #TODO: getDisplayablePage() won't contain what we want to disasm. we will use dataModel
        #      in this view, getDisplayablePage will contain disasm text, because that is what is displayed

        if self.widget:
            self.widget.update()


    def scrollPages(self, number, cachePix=None, pageOffset=None):
        self.scroll(0, -number*self.ROWS, cachePix=cachePix, pageOffset=pageOffset)

    def scroll_v(self, dy, cachePix=None, pageOffset=None):
        #start = time()        

        RowsToDraw = []


        factor = abs(dy)


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

            if dy >= 0:
                # we try to decode from current offset - 50, in this case even if decoding is incorrect (will overlap),
                # in 50 bytes it is possible to correct itself, so hopefully last instruction it's decoded correctly and
                # followed correctly by current_offset instruction
                if self.dataModel.getOffset() < 50:
                    start = 0
                else:
                    start = self.dataModel.getOffset() - 50


                end = self.dataModel.getOffset()
                #print 'end ' + str(hex(end))
                iterable = distorm3.Decompose(self._getVA(start), str(self.dataModel.getStream(start, end)), self.plugin.hintDisasm())

                if len(iterable) == 0:
                    # maybe we are at beginning cannot scroll more
                    break

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
                #RowsToDraw.append((self.ROWS - factor + row, newasm))
                RowsToDraw.append((self.ROWS + row, newasm))

            if dy > 0:
                #RowsToDraw.append((factor - row - 1, newasm))
                RowsToDraw.append((-row - 1, newasm))

        # draw

        if len(RowsToDraw) < abs(dy):
            # maybe we couldn't draw dy rows (possible we reached the beginning of the data to early), recalculate dy
            dy = len(RowsToDraw)*dy/abs(dy)
            factor = abs(dy)

        if not cachePix:
            self.qpix.scroll(0, dy*self.fontHeight, self.qpix.rect())

        qp = QtGui.QPainter()
        if cachePix:
            qp.begin(cachePix)
        else:
            qp.begin(self.qpix)

        qp.setFont(self.font)
        qp.setPen(self.textPen)

        # erase rows that will disappear
        if dy < 0:
            qp.fillRect(0, (self.ROWS-factor)*self.fontHeight, self.fontWidth*self.COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        if dy > 0:
            qp.fillRect(0, 0, self.fontWidth*self.COLUMNS, factor * self.fontHeight, self.backgroundBrush)

        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        for row, asm in RowsToDraw:
            self._drawRow(qp, cemu, dy + row, asm)


        qp.end()

        #end = time() - start

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

                #print line[cursorX:]
                #print line[x:]


                self.cursor.move(-(cursorX-x) + 1, 0)


        if direction == Directions.Right:
            asm = self.OPCODES[cursorY]
            line = asm.hex + (30 - len(asm.hex))*' ' + asm.mnemonic + (10 - len(asm.mnemonic))*' ' + asm.restOfInstr

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
            pass
            #self.cursor.moveAbsolute(self.COLUMNS-1, self.ROWS-1)
            #self.cursorX = self.COLUMNS-1
            #self.cursorY = self.ROWS-1

        if direction == Directions.Home:
            self.cursor.moveAbsolute(0, 0)
            #self.cursorX = 0
            #self.cursorY = 0

        if direction == Directions.CtrlHome:
            self.goTo(0)

        if direction == Directions.CtrlEnd:
            self.dataModel.slideToLastPage()
            self.draw(refresh=True)
            self.cursor.moveAbsolute(self.COLUMNS-1, self.ROWS-1)

    def _followBranch(self):
        cursorX, cursorY = self.cursor.getPosition()
        asm = self.OPCODES[cursorY]

        asm = asm.obj
        if asm.flowControl != 'FC_NONE':
            for o in asm.operands:
                if o.dispSize != 0:
                    if 'FLAG_RIP_RELATIVE' in asm.flags:
                        value =  asm.address + asm.size + o.disp
                    else:
                        value = o.disp
                else:
                    value = o.value


                fofs = self.plugin.disasmVAtoFA(value)
                if fofs != None:
                    rowOfs = self._getOffsetOfRow(cursorY)
                    if rowOfs != None:
                        self.FlowHistory.append(rowOfs + self.dataModel.getOffset())
                        self.goTo(fofs)

    def _followBranchHistory(self):
        if len(self.FlowHistory) > 0:
            offset = self.FlowHistory[-1]
            del self.FlowHistory[-1]
            self.goTo(offset)

    def handleKeyEvent(self, modifiers, key, event=None):
        if event.type() == QtCore.QEvent.KeyRelease:
            if key == QtCore.Qt.Key_Shift:
                self.stopSelection()
                return True

        if event.type() == QtCore.QEvent.KeyPress:

            if modifiers == QtCore.Qt.ShiftModifier:
                keys = [QtCore.Qt.Key_Right, QtCore.Qt.Key_Left, QtCore.Qt.Key_Down, QtCore.Qt.Key_Up, QtCore.Qt.Key_End, QtCore.Qt.Key_Home]
                if key in keys:
                    self.startSelection()

            if modifiers == QtCore.Qt.ControlModifier:
                if key == QtCore.Qt.Key_Right:
                    self.dataModel.slide(1)
                    self.addop((self.scroll, -1, 0))

                if key == QtCore.Qt.Key_Left:
                    self.dataModel.slide(-1)
                    self.addop((self.scroll, 1, 0))

                if key == QtCore.Qt.Key_Down:
                    self.addop((self.scroll, 0, -1))
                    self.addop((self.draw,))

                if key == QtCore.Qt.Key_Up:
                    self.addop((self.scroll, 0, 1))
                    self.addop((self.draw,))

                if key == QtCore.Qt.Key_End:
                    # not supported
                    pass

                if key == QtCore.Qt.Key_Home:
                    self.moveCursor(Directions.CtrlHome)
                    self.addop((self.draw,))
                    #self.draw()

                return True

            else:#elif modifiers == QtCore.Qt.NoModifier:

                if key == QtCore.Qt.Key_Escape:
                    self.selector.resetSelections()
                    self.addop((self.draw,))

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

                if key == QtCore.Qt.Key_Return:
                    self.addop((self._followBranch,))
                    self.addop((self.draw,))

                if key == QtCore.Qt.Key_Escape:
                    self.addop((self._followBranchHistory,))
                    self.addop((self.draw,))

                return True

        return False

    def addop(self, t):
        self.Ops.append(t)

    def getHeaderInfo(self):
        return 'Disasm listing'
