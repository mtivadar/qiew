from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt5 import QtGui, QtCore, QtWidgets
import PyQt5
from cemu import *

import sys, os
import DisasmViewMode
import elftools
from elftools.elf.elffile import ELFFile


class ELF(FileFormat):
    name = 'elf'
    priority = 5

    def recognize(self, dataModel):
        self.dataModel = dataModel
        try:
            self.elf = ELFFile(self.dataModel.getData())
        except Exception as e:
            return False

        return True

    def init(self, viewMode, parent):
        self._viewMode = viewMode

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))        


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'MZ', brush=self.MZbrush, pen=self.greenPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\x7FELF', brush=self.MZbrush, pen=self.greenPen)
        self.textDecorator = HighlightWideChar(self.textDecorator)

        self._viewMode.setTransformationEngine(self.textDecorator)
        return True

    def hintDisasm(self):
        arch = self.elf.get_machine_arch()
        Arch = {
            'x64' : DisasmViewMode.Disasm_x86_64bit,
            'x86' : DisasmViewMode.Disasm_x86_32bit,
            'ARM' : DisasmViewMode.Disasm_ARM,
            'AArch64' : DisasmViewMode.Disasm_ARM64
        }

        if arch in Arch:
            return Arch[arch]

        return DisasmViewMode.Disasm_x86_64bit

    def hintDisasmVA(self, offset):
        return offset

    def disasmVAtoFA(self, va):
        return va

    def getBanners(self):
        self.banners = [ELFBanner(self.dataModel, self._viewMode, self), ELFHeaderBanner(self.dataModel, self._viewMode, self), Banners.BottomBanner(self.dataModel, self._viewMode)]
        return self.banners
        
    def registerShortcuts(self, parent):
        self._parent = parent
        self.w = DialogGoto(parent, self)
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._showit, self._showit)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("s"), parent, self.skip_chars, self.skip_chars)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("e"), parent, self.skip_block, self.skip_block)]

        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("F7"), parent, self.F7, self.F7)]

    def F7(self):
        offset = self.elf.header['e_entry']
        print(self.elf.header['e_phoff'])
        self._viewMode.goTo(offset)

    def _showit(self):
        if not self.w.isVisible():
            self.w.show()
        else:
            self.w.hide()

    def skip_block(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        x = self.dataModel.getData().find(b'\x00'*8, off)
        if x == -1:
            x = off


        if x == off:
            if x < sizeOfData - 1:
                x += 1

        self._viewMode.goTo(x)

        return

    def skip_chars(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off + 1

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        # skip bytes of current value
#        import time

        BYTES = 512
#        k = time.time()
        b = self.dataModel.getStream(off, off + 1)
        z = b * BYTES

        # compare stream of bytes
        z = self.dataModel.getStream(off, off+BYTES)
        while x < sizeOfData - BYTES and self.dataModel.getStream(x, x + BYTES) == z:
            x += BYTES

        while x < sizeOfData - 1 and self.dataModel.getBYTE(x) == ord(b):
            x += 1

#        print time.time() - k

        self._viewMode.goTo(x)

class ELFHeaderBanner(Banners.TopBanner):
    def __init__(self, dataModel, viewMode, elfplugin):
        self.elfplugin = elfplugin
        super(ELFHeaderBanner, self).__init__(dataModel, viewMode)

    def draw(self):
        qp = QtGui.QPainter()
        qp.begin(self.qpix)

        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)

        cemu = ConsoleEmulator(qp, self.height//self.fontHeight, self.width//self.fontWidth)

        cemu.writeAt(1, 0, 'Name')

        offset = 13

        cemu.writeAt(offset, 0, 'FA')

        offset = 21 # for ELF plugin !

        text = ''
        text = self.viewMode.getHeaderInfo()

        cemu.writeAt(offset, 0, text)
        
        qp.end()

class ELFBanner(Banners.Banner):
    def __init__(self, dataModel, viewMode, elfplugin):
        self.width = 0
        self.height = 0
        self.dataModel = dataModel
        self.viewMode = viewMode
        self.qpix = self._getNewPixmap(self.width, self.height)
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        self.elfplugin = elfplugin

        self.elf = self.elfplugin.elf        

        # text font
        self.font = QtGui.QFont('Terminus', 11, QtGui.QFont.Bold)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 0, QtCore.Qt.SolidLine)


    def getOrientation(self):
        return Banners.Orientation.Left

    def getDesiredGeometry(self):
        return self.fontWidth*20# 160

    def get_section_by_offset(self, offset):
        for s in self.elf.iter_sections():
            if offset > s.header['sh_offset'] and offset < s.header['sh_offset'] + s.header['sh_size']:
                return s

        return None
        
    def draw(self):
        #for section in self.PE.sections:
        #    print section.PointerToRawData

        qp = QtGui.QPainter()

        offset = self.viewMode.getPageOffset()
        columns, rows = self.viewMode.getGeometry()

        qp.begin(self.qpix)
        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)
#        for sec in self.elf.iter_sections():
#            print dir(sec.header)

#        print self.elf.get_section(4).header.name

        for i in range(rows):
            s = '--------'
            
            columns = self.viewMode.getColumnsbyRow(i)

            section = self.get_section_by_offset(offset)
            if section:
                s = section.name.replace('\0', ' ')

            s = s[:8]
            s += (8-len(s))*' '
            sOff = ' {0:08x}'.format(offset)
            """
            displayType = self.peplugin.getAddressMode()
            if displayType == 'FA':
                sOff = ' {0:08x}'.format(offset)
            elif displayType == 'RVA':
                sOff = ' {0:08x}'.format(self.PE.get_rva_from_offset(offset))
            else:
                sOff = '{0:08x}'.format(self.PE.get_rva_from_offset(offset) + self.PE.OPTIONAL_HEADER.ImageBase)
                if len(sOff) == 8:
                    sOff = ' ' + sOff
            """
            sDisplay = '{0} {1}'.format(s, sOff)
            qp.drawText(0+5, (i+1) * self.fontHeight, sDisplay)
            offset += columns
            

        qp.end()

    def resize(self, width, height):
        self.width = width
        self.height = height

        self.qpix = self._getNewPixmap(self.width, self.height)
