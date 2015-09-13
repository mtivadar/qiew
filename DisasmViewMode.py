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

import capstone
import capstone.x86

import ply.lex as lex


MNEMONIC_COLUMN = 30
MNEMONIC_WIDTH = 15

class ASMLine:
    def __init__(self, d, plugin):
        self._hexstr = self.hexlify(d.bytes)
        self._instruction = d.op_str
        self._operands = d.op_str
        self._size = d.size
        self._addr = d.address
        self._mnemonic = d.mnemonic

        self._d = d
        self.refString = ''
        #self._str = ' '.join(self.instruction.split(' ')[1:])
        self._str = 'a'

        self.symbol = None

        tokens = ('REGISTER', 'NUMBER', 'ID', 'WHITE', 'PTR')
        t_REGISTER = r'e?r?[abcde]x|ebp|esp|rip|rbp|rsp|r[1-9][1-9]*d?b?|si|di|rsi|rdi|edi|esi|gs|fs|xmm[0-9]|[abcd][lh]|cr[0-9]|ymm[0-9]|dr[0-7]|fp[0-7]|mm[0-7]|dil'
        t_NUMBER = r'0x[0-9a-f]+|[0-9]+'
        t_PTR = r'qword|dword|word|byte|ptr|xmmword'
        t_ignore = r' []-,+:*'

        def t_error(t):
            t.type = t.value[0]
            t.value = t.value[0]
            t.lexer.skip(1)
            print t.value
            print 'LEXER ERROR'
            return t

        self.lexer = lex.lex()
        #print d.op_str
        try:
            #self.lexer.input(d.op_str)
            pass
        except Exception, e:
            print e
            sys.exit()

        self.lexer = list(self.lexer)


        """
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
        """
        # gets ref string (only for PUSH and RIP addressing)
        asm = d

        if len(asm.operands) > 1:
            o = asm.operands[1]

            if o.type == capstone.x86.X86_OP_MEM:
                if o.mem.base == capstone.x86.X86_REG_RIP:
                    x =  asm.address + asm.size + o.mem.disp
                    self.refString = plugin.stringFromVA(x)

        
        # get symbol
        if self.ingroup([capstone.x86.X86_GRP_CALL]):
            value = None
            asm = d

            for o in self._d.operands:
                if o.type == capstone.x86.X86_OP_IMM:
                    value = o.imm

                if o.type == capstone.x86.X86_OP_MEM:
                    value = o.mem.disp + asm.size + asm.address

#                print o, o.type

            if value:
                sym = plugin.disasmSymbol(value)

                if sym:
                    self.symbol = sym



        self.indexTable = []
        H = self.hex.split(' ')
        for i, h in enumerate(H):
            self.indexTable += [(i*3, len(h), h)]

        self.indexTable += [(MNEMONIC_COLUMN, len(self.mnemonic), self.mnemonic)]

        if self.symbol:
            t = (MNEMONIC_COLUMN + MNEMONIC_WIDTH + 1, len(self.symbol), self.symbol)
            self.indexTable += [t]
        else:
            for tok in self.lexer:
                t = (tok.lexpos + MNEMONIC_COLUMN + MNEMONIC_WIDTH, len(tok.value), tok.value)
                self.indexTable += [t]


        #print self.indexTable

    def getSelectedToken(self, cx):
        for i, t in enumerate(self.indexTable):
            idx, length, value = t
            if cx == idx:
                return t

        return None

    def getSelectionWidth(self, cx):
        for i, t in enumerate(self.indexTable):
            idx, length, value = t
            if cx == idx:
                return length

        return None

    def getEndCursor(self):
        idx, length, value = self.indexTable[-1]
        return idx

    def getNearestCursor(self, cx):
        if cx > self.getEndCursor():
            return self.getEndCursor()

        i = len(self.indexTable) - 1
        while i > 0:
            idx, length, value = self.indexTable[i]
            if cx >= idx:
                return idx
            i -= 1

        return 0

    def getNextCursor(self, cx, direction=''):
        for i, t in enumerate(self.indexTable):
            idx, length, value = t
            if cx == idx:
                break

        if direction == Directions.Right:
            if i < len(self.indexTable) - 1:
                idx, length, value = self.indexTable[i + 1]
            else:
                return 0, 1

        if direction == Directions.Left:
            if i > 0:
                idx, length, value = self.indexTable[i - 1]
            else:
                return 0, -1

        return idx, 0


    def ingroup(self, group):
        if len(self._d.groups) > 0:
            for g in self._d.groups:
                for x in group:
                    if x == g:
                        return True

        return False


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

    """
    @property
    def instruction(self):
        return self._instruction
    """

    @property
    def operands(self):
        return self._operands
    
    @property
    def refString(self):
        return self.refString

    @property
    def obj(self):
        return self._d

    def isBranch(self):
        return self.ingroup([capstone.x86.X86_GRP_JUMP, capstone.x86.X86_GRP_CALL])

    def branchAddress(self):
        if not self.isBranch():
            return None

        asm = self.obj
        if len(asm.operands) == 1:
            o = asm.operands[0]

            if o.type == capstone.x86.X86_OP_MEM:
                #if o.mem.base == capstone.x86.X86_REG_RIP:
                x = asm.address + asm.size + o.mem.disp
                return x

            if o.type == capstone.x86.X86_OP_IMM:
                x = o.imm
                return x




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

        xstart = cursorX
        width = asm.getSelectionWidth(xstart)

        qp.setBrush(QtGui.QColor(255, 255, 0))

        qp.setOpacity(0.5)
        qp.drawRect(xstart*self.fontWidth, cursorY*self.fontHeight, width*self.fontWidth, self.fontHeight + 2)
        qp.setOpacity(1)



    def drawSelected(self, qp):
        qp.setFont(self.font)

        cursorX, cursorY = self.cursor.getPosition()

        asm = self.OPCODES[cursorY]
        cx, width, text = asm.getSelectedToken(cursorX)

        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        for i, asm in enumerate(self.OPCODES):
            for idx, length, value in asm.indexTable:
                # skip current cursor position
                if cursorY == i and cursorX == idx:
                    continue

                # check every line, if match, select it
                if value == text:
                    qp.setOpacity(0.4)
                    brush=QtGui.QBrush(QtGui.QColor(0, 255, 0))
                    qp.fillRect(idx*self.fontWidth, i*self.fontHeight + 2 , width*self.fontWidth, self.fontHeight, brush)
                    qp.setOpacity(1)


    def drawBranch(self, qp):

        qp.fillRect(-50, 0, 50,  self.ROWS * self.fontHeight, self.backgroundBrush)

        cursorX, cursorY = self.cursor.getPosition()

        asm = self.OPCODES[cursorY]

        if asm.isBranch():

            tsize = sum([o.size for o in self.OPCODES])
            msize = sum([o.size for o in self.OPCODES[:cursorY]])

            half = self.fontHeight/2

            # branch address
            target = asm.branchAddress()
            if target == None:
                return

            screenVA = self._getVA(self.dataModel.getOffset())
            if target >  screenVA and target < self._getVA(self.dataModel.getOffset()) + tsize - self.OPCODES[-1].size:
                # branch target is in screen

                sz = 0
                for i, t in enumerate(self.OPCODES):
                    sz += t.size
                    if sz+self._getVA(self.dataModel.getOffset()) >= target:
                        break

                qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.SolidLine))

                # draw the three lines

                qp.drawLine(-5, cursorY*self.fontHeight + self.fontHeight/2, -30, cursorY*self.fontHeight + half)

                qp.drawLine(-30, cursorY*self.fontHeight + self.fontHeight/2, -30, (i + 1)*self.fontHeight + half)

                qp.drawLine(-30, (i + 1)*self.fontHeight + half, -15, (i + 1)*self.fontHeight + half)

                # draw arrow
                points = [QtCore.QPoint(-15, (i + 1)*self.fontHeight + half - 5), 
                          QtCore.QPoint(-15, (i + 1)*self.fontHeight + half + 5), 
                          QtCore.QPoint(-5, (i + 1)*self.fontHeight + half), ]
                needle = QtGui.QPolygon(points)
                qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 128, 0)))
                qp.drawPolygon(needle)



            elif target > screenVA:
                # branch is at greater address, out of screen

                qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.DotLine))

                # draw the two lines
                qp.drawLine(-5, cursorY*self.fontHeight + self.fontHeight/2, -30, cursorY*self.fontHeight + half)
                qp.drawLine(-30, cursorY*self.fontHeight + self.fontHeight/2, -30, (self.ROWS - 2)*self.fontHeight + half)

                # draw arrow
                points = [QtCore.QPoint(-25, (self.ROWS - 2)*self.fontHeight + half), 
                          QtCore.QPoint(-35, (self.ROWS - 2)*self.fontHeight + half), 
                          QtCore.QPoint(-30, (self.ROWS - 2)*self.fontHeight + 2*half), ]
                needle = QtGui.QPolygon(points)
                qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 128, 0)))
                qp.drawPolygon(needle)

            else:
                # upper arrow
                # branch is at lower address, out of screen

                qp.setPen(QtGui.QPen(QtGui.QColor(0, 192, 0), 1, QtCore.Qt.DotLine))

                # draw the two lines
                qp.drawLine(-5, cursorY*self.fontHeight + self.fontHeight/2, -30, cursorY*self.fontHeight + half)
                qp.drawLine(-30, cursorY*self.fontHeight + self.fontHeight/2, -30, (1)*self.fontHeight + half)

                # draw arrow
                points = [QtCore.QPoint(-25, (1)*self.fontHeight + half), 
                          QtCore.QPoint(-35, (1)*self.fontHeight + half), 
                          QtCore.QPoint(-30, (1)*self.fontHeight), ]
                needle = QtGui.QPolygon(points)
                qp.setBrush(QtGui.QBrush(QtGui.QColor(0, 128, 0)))
                qp.drawPolygon(needle)



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
        
    def _getVA(self, offset):
        if self.plugin:
            return self.plugin.hintDisasmVA(offset)

        return 0

    def _getOpcodes(self, ofs, code, dt, count):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        
        cnt = 0
        offset = 0
        #self.OPCODES = []
        OPCODES = []

        # how ugly ... don't like capstone on this one..
        while cnt < count and offset < len(code):
            Disasm = md.disasm(code[offset:], self._getVA(ofs) + offset, count=count)

            # disasamble as much as we can
            for d in Disasm:
                cnt += 1
                offset += d.size
                OPCODES.append(ASMLine(d, self.plugin))

            # when we are stopped with errors, inject fake isntructions
            if cnt < self.ROWS and offset < len(code):
                class D:
                    mnemonic = 'db'
                    bytes = ''
                    op_str = ''
                    size = 1
                    address = 0
                    operands = []
                    groups = []

                d = D()
                d.mnemonic = 'db ' + '0x{:02x}'.format(bytearray(code[offset])[0])
                d.bytes = code[offset]

                d.address = self._getVA(ofs) + offset

                OPCODES.append(ASMLine(d, self.plugin))
                cnt += 1
                offset += 1


        return OPCODES


    def _drawRow(self, qp, cemu, row, asm):
        qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))

        # write hexdump
        cemu.writeAt(0, row, asm.hex)

        # fill with spaces
        cemu.write((MNEMONIC_COLUMN - len(asm.hex))*' ')

        # let's color some branch instr
        if asm.isBranch():
            qp.setPen(QtGui.QPen(QtGui.QColor(255, 80, 0)))
            asm.mnemonic = asm.mnemonic.upper()
        else:
            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))

        cemu.write(asm.mnemonic)

        # leave some spaces
        cemu.write((MNEMONIC_WIDTH-len(asm.mnemonic))*' ')

        if asm.symbol:
            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write_c('[')

            qp.setPen(QtGui.QPen(QtGui.QColor('yellow'), 1, QtCore.Qt.SolidLine))
            cemu.write(asm.symbol)

            qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write_c(']')

            result = '[' + asm.symbol + ']'
        else:
            self._write_instruction(asm, qp, cemu)
            #result = asm.operands

        #print result

        if len(asm.refString) > 4:
            cemu.write(30*' ')

            qp.setPen(QtGui.QPen(QtGui.QColor(82, 192, 192), 1, QtCore.Qt.SolidLine))
            cemu.write('; "{0}"'.format(asm.refString))


    def _write_instruction(self, asm, qp, cemu):
        s = asm.operands
        idx = 0
        qp.setPen(QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine))

        for tok in asm.lexer:
            if tok.lexpos > idx:
                cemu.write(s[idx:tok.lexpos])
                idx = tok.lexpos

            qp.save()
            if tok.type == 'REGISTER':
                qp.setPen(QtGui.QPen(QtGui.QColor('white')))
            
            if tok.type == 'NUMBER':
                qp.setPen(QtGui.QPen(QtGui.QColor('green')))

            cemu.write(tok.value)

            qp.restore()
            idx = tok.lexpos + len(tok.value)

        if idx < len(s):
            cemu.write(s[idx:])

    def drawTextMode(self, qp):
        # draw background
        qp.fillRect(0, 0, self.COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight, self.backgroundBrush)

        # set text pen&font
        qp.setFont(self.font)
        qp.setPen(self.textPen)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.COLUMNS)

        if len(self.OPCODES) == 0:
            self.OPCODES = self._getOpcodes(self.dataModel.getOffset(), str(self.getDisplayablePage()), self.plugin.hintDisasm(), count=self.ROWS)


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
            self.OPCODES = self._getOpcodes(offset, str(self.getDisplayablePage()), self.plugin.hintDisasm(), count=self.ROWS)
            self.cursor.moveAbsolute(0, 0)
            self.draw(refresh=True)

        #TODO: getDisplayablePage() won't contain what we want to disasm. we will use dataModel
        #      in this view, getDisplayablePage will contain disasm text, because that is what is displayed

        if self.widget:
            self.widget.update()


    def scrollPages(self, number, cachePix=None, pageOffset=None):
        self.scroll(0, -number*self.ROWS, cachePix=cachePix, pageOffset=pageOffset)

    def _disassamble_one(self, start, end, count=1):
        code = str(self.dataModel.getStream(start, end))
        Disasm = self._getOpcodes(start, code, 0, count)
        """
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        code = str(self.dataModel.getStream(start, end))
        Disasm = list(md.disasm(code, self._getVA(start), count=count))
        """
        return Disasm

    def scroll_v(self, dy, cachePix=None, pageOffset=None):
        #start = time()        

        RowsToDraw = []


        factor = abs(dy)


        # repeat as many rows we have scrolled
        
        for row in range(factor):

            d = None
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

                iterable = self._disassamble_one(start, end, count=1)
                #print iterable
                if len(iterable) > 0:
                    d = iterable[0]
                else:
                    #todo: what should we handle here
                    break
                """
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                md.detail = True
                code = str(self.dataModel.getStream(start, end))
                Disasm = md.disasm(code, self._getVA(start), count=1)

                for d in Disasm:
                    d = d
                    #self.OPCODES.append(ASMLine(d, self.plugin))
                """

                #iterable = distorm3.Decompose(self._getVA(start), str(self.dataModel.getStream(start, end)), self.plugin.hintDisasm())
                # eat first instruction from the page
                #d = iterable[0]

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

                """
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                md.detail = True

                code = str(self.dataModel.getStream(start, end))
                """
                #iterable = list(md.disasm(code, self._getVA(start)))
                iterable = self._disassamble_one(start, end, count=25)
                #print iterable
                if len(iterable) > 0:
                    d = iterable[-1]
                else:
                    # TODO: 
                    print 'bbbbbbbbbbbbbbb'
                    break
            #hexstr = self.hexlify(self.dataModel.getStream(start + d.address, start + d.address + d.size))
            #newasm = ASMLine(d, self.plugin)
            newasm = d

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

            if cursorX == 0:
                if cursorY == 0:
                    # if first line, scroll
                    self.scroll(0, 1)
                    self.cursor.moveAbsolute(0, 0)
                else:
                    # move to last token from previous line
                    asm_prev = self.OPCODES[cursorY - 1]
                    idx = asm_prev.getEndCursor()
                    self.cursor.moveAbsolute(idx, cursorY - 1)
            else:
                x, dy = asm.getNextCursor(cursorX, direction=Directions.Left)
                self.cursor.move(-(cursorX-x), dy)


        if direction == Directions.Right:
            asm = self.OPCODES[cursorY]
            x, dy = asm.getNextCursor(cursorX, direction=Directions.Right)

            if cursorY == self.ROWS-1 and dy > 0:
                self.scroll(0, -1)
                self.cursor.moveAbsolute(0, cursorY)

            else:
                self.cursor.move(x-cursorX, dy)

        if direction == Directions.Down:
            if cursorY == self.ROWS-1:
                # move cursor to first token
                self.scroll(0, -1)
                self.cursor.moveAbsolute(0, cursorY)
            else:
                # move next line, to nearest token on columns
                asm = self.OPCODES[cursorY + 1]
                x = asm.getNearestCursor(cursorX)
                self.cursor.moveAbsolute(x, cursorY + 1)

        if direction == Directions.Up:
            if cursorY == 0:
                # move cursor to first token
                self.scroll(0, 1)
                self.cursor.moveAbsolute(0, cursorY)
            else:
                # move next line, to nearest token on columns
                asm = self.OPCODES[cursorY - 1]
                x = asm.getNearestCursor(cursorX)
                self.cursor.moveAbsolute(x, cursorY - 1)

        if direction == Directions.End:
            pass

        if direction == Directions.Home:
            self.cursor.moveAbsolute(0, 0)


        if direction == Directions.CtrlHome:
            self.goTo(0)

        if direction == Directions.CtrlEnd:
            self.dataModel.slideToLastPage()
            self.draw(refresh=True)
            self.cursor.moveAbsolute(self.COLUMNS-1, self.ROWS-1)

    def _followBranch(self):
        cursorX, cursorY = self.cursor.getPosition()
        asm = self.OPCODES[cursorY]

        if asm.isBranch():
            value = asm.branchAddress()
            if value:
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
