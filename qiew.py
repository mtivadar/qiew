#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
author: Marius TIVADAR
date: 02/2013
"""

import sys
from StringIO import *
from PyQt4 import QtGui, QtCore, uic
import mmap
import binascii

from TextDecorators import *
from DataModel import *
from BinViewMode import *
from HexViewMode import *
from DisasmViewMode import *
from Banners import *

from yapsy.PluginManager import PluginManager
from FileFormat import *

from time import time
import logging


class binWidget(QtGui.QWidget):
  
    scrolled = QtCore.pyqtSignal(int, name='scroll')
    oldscrolled = QtCore.SIGNAL('scroll')

    def __init__(self, parent, source):
        super(binWidget, self).__init__()

        self.parent = parent
        
        # offset for text window
        #self.data = mapped
        self.dataOffset = 0
        
        self.dataModel = FileDataModel(source)
        self.cursor = Cursor(0, 0)

        
#        self.multipleViewModes = [BinViewMode(self.size().width(), self.size().height(), self.dataModel, self.cursor, self),
#                                  HexViewMode(self.size().width(), self.size().height(), self.dataModel, self.cursor, self)]

        logging.basicConfig(level=logging.ERROR)
        self.manager = PluginManager(categories_filter={ "FileFormat": FileFormat})

        root = os.path.dirname(sys.argv[0])
        self.manager.setPluginPlaces([os.path.join(root, 'plugins', 'format')])
        #self.manager.setPluginPlaces(["plugins"])

        # Load plugins
        self.manager.locatePlugins()
        self.manager.loadPlugins()

        Formats = []
        for plugin in self.manager.getPluginsOfCategory("FileFormat"):
            # plugin.plugin_object is an instance of the plugin
            po = plugin.plugin_object
            if po.recognize(self.dataModel):
                print '[+] ' + po.name
                Formats.append(po)
                

        # sort plugins by priority
        Formats = sorted(Formats, key=lambda x: x.priority, reverse=True)
        po = Formats[0]
        print 'Choosed plugin: ' + po.name

        #print QtGui.QFontDatabase.addApplicationFont(os.path.join('terminus-ttf-4.39', 'TerminusTTF-4.39.ttf'))
        


        self.multipleViewModes = [BinViewMode(self.size().width(), self.size().height(), self.dataModel, self.cursor, self),
                                  HexViewMode(self.size().width(), self.size().height(), self.dataModel, self.cursor, self),
                                  DisasmViewMode(self.size().width(), self.size().height(), self.dataModel, self.cursor, self, plugin=po)]

        self.viewMode = self.multipleViewModes[0]

        self.textDecorator = TextDecorator(self.viewMode)

        self.viewMode.setTransformationEngine(self.textDecorator)

        self.multipleViewModes[1].setTransformationEngine(self.textDecorator)

        self.Banners = Banners()

        self.Banners.add(BottomBanner(self.dataModel, self.viewMode))
#        self.Banners.add(TopBanner(self.dataModel, self.viewMode))


        #self.Banners.add(self.banner)
#        self.filebanner = FileAddrBanner(self.dataModel, self.viewMode)
        #self.filebanner = PEBanner(self.dataModel, self.viewMode)
        #self.Banners.add(PEBanner(self.dataModel, self.viewMode))
        #self.Banners.add(FileAddrBanner(self.dataModel, self.viewMode))
        #self.Banners.add(FileAddrBanner(self.dataModel, self.viewMode))        

        # self.offsetWindow_h = self.filebanner.getDesiredGeometry()[0] + 25
        self.offsetWindow_h = 0
        self.offsetWindow_v = 0

        self.initUI()
        
        po.init(self.viewMode)
        for banner in po.getBanners():
            #self.Banners.add(banner(self.dataModel, self.viewMode))
            self.Banners.add(banner)
        
        po.registerShortcuts(self)
        self.po = po

        #self.scrolled = QtCore.pyqtSignal(int, name='scroll')
        #self.scrolled.connect(self.scroll_from_outside)

        self.connect(self, self.oldscrolled, self.scroll_from_outside)
        #self.scrolled.emit(1)
        self.emit(QtCore.SIGNAL('scroll'), 1)        


    def scroll_from_outside(self, i):
        #print 'slot-signal ' + str(i)
        #self.scroll_pdown = True
        self.update()

    def initUI(self):
        
        self.setMinimumSize(1, 30)
        self.activateWindow()
        self.setFocus()

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
        self.multipleViewModes = self.multipleViewModes[1:] + [self.multipleViewModes[0]]
        self.viewMode = self.multipleViewModes[0]
        self.po.init(self.viewMode)
        self.Banners.setViewMode(self.viewMode)
        #self.banner.setViewMode(self.viewMode)
        #self.filebanner.setViewMode(self.viewMode)        


    def _resize(self):

        self.Banners.resize(self.size().width() - self.offsetWindow_h, self.size().height() - self.offsetWindow_v)
        
        offsetLeft = self.offsetWindow_h + self.Banners.getLeftOffset()
        offsetBottom   = self.offsetWindow_v + self.Banners.getBottomOffset() + self.Banners.getTopOffset()
        
        self.viewMode.resize(self.size().width() - offsetLeft, self.size().height() - offsetBottom)

    # event handlers
    def resizeEvent(self, e):
        self._resize()


    def paintEvent(self, e):
        qp = QtGui.QPainter()
        qp.begin(self)
        qp.setOpacity(1)

        offsetLeft = self.offsetWindow_h + self.Banners.getLeftOffset()
        offsetBottom   = self.offsetWindow_v + self.Banners.getTopOffset()

        #self.viewMode.draw2(qp, refresh=True)
        #start = time()
        qp.drawPixmap(offsetLeft, offsetBottom, self.viewMode.getPixmap())
        #print 'Draw ' + str(time() - start)

        self.Banners.draw(qp, self.offsetWindow_h, self.offsetWindow_v, self.size().height())

      #  qp.drawPixmap(self.offsetWindow_h, self.size().height() - 50, self.banner.getPixmap())

       # qp.drawPixmap(20, 0, self.filebanner.getPixmap())
        qp.end()


    def keyPressEvent(self, event):
        if event.modifiers() & QtCore.Qt.ShiftModifier:
            if self.viewMode.handleKeyPressEvent(QtCore.Qt.ShiftModifier, event.key()):
                self.update()

    def keyReleaseEvent(self, event):
        if event.key() == QtCore.Qt.Key_Shift:
            if self.viewMode.handleKeyReleaseEvent(QtCore.Qt.ShiftModifier, event.key()):
                self.update()

    def eventFilter(self, watched, event):
        
        if event.type() == QtCore.QEvent.KeyPress: 
            #TODO: should we accept only certain keys ?

            key = event.key()
            modifiers = event.modifiers()

            # switch view mode
            if key == QtCore.Qt.Key_Tab:
                    offs = self.viewMode.getCursorOffsetInPage()
                    self.switchViewMode()

                    self._resize()

                    self.viewMode.goTo(offs + self.viewMode.getDataModel().getOffset())

                    self.update()

            import pyperclip
            if event.modifiers() & QtCore.Qt.ControlModifier:
                if key == QtCore.Qt.Key_Insert:
                    if self.viewMode.selector.getCurrentSelection():
                        a, b = self.viewMode.selector.getCurrentSelection()

                        #print a, b
                        hx = ''
                        for s in self.dataModel.getStream(a, b):
                            hx += '{:02x}'.format(s)

                        pyperclip.copy(hx)
                        del pyperclip
                        #print pyperclip.paste()
                     #   print 'coppied'
                
            if event.modifiers() & QtCore.Qt.ShiftModifier:
                if key == QtCore.Qt.Key_Insert:
                    import re
                    hx = pyperclip.paste()
                    #print hx
                    L = re.findall(r'.{1,2}', hx, re.DOTALL)

                    array = ''
                    for s in L:
                        array += chr(int(s, 16))

                    #print 'write '
                    #print 'write'
                    #print array
                    self.dataModel.write(0, array)
                    self.viewMode.draw(True)
                    del pyperclip
                    #print array


            if key == QtCore.Qt.Key_F10:
                import os
                self.w = WHeaders(self, None)
                self.w.show()

            if self.viewMode.handleKeyEvent(modifiers, key):
                self.update()


        return False

    def setTextViewport(self, qp):
        qp.setViewport(self.offsetWindow_h, self.offsetWindow_v, self.size().width(), self.size().height())
        qp.setWindow(0, 0, self.size().width(), self.size().height())



class WHeaders(QtGui.QDialog):
    
    def __init__(self, parent, plugin):
        super(WHeaders, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(WHeaders, self).show

        root = os.path.dirname(sys.argv[0])

        self.ui = PyQt4.uic.loadUi(os.path.join(root, 'dropper.ui'), baseinstance=self)
        self.ui.setWindowTitle('Dropper')

        self.initUI()

    def show(self):

        # TODO: remember position? resize plugin windows when parent resize?
        pwidth = self.parent.parent.size().width()
        pheight = self.parent.parent.size().height()

        width = self.ui.size().width()+15
        height = self.ui.size().height()+15

        self.setGeometry(pwidth - width - 15, pheight - height, width, height)
        self.setFixedSize(width, height)

        self.oshow()

    def initUI(self):      

        self.setSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)

        shortcut = QtGui.QShortcut(QtGui.QKeySequence("F10"), self, self.close, self.close)

        self.ui.rsel.setChecked(True)
        self.ui.rbin.setChecked(True)
        QtCore.QObject.connect(self.ui.ok, QtCore.SIGNAL('clicked()'), self.onClicked)

    def onClicked(self):
        
        dataModel = self.parent.dataModel
        name = os.path.basename(dataModel.source)
        
        if self.ui.rsel.isChecked():
            if self.parent.viewMode.selector.getCurrentSelection():
                a,b = self.parent.viewMode.selector.getCurrentSelection()
            else:
                a, b = None, None

        if self.ui.rwf.isChecked():
            a,b = 0, dataModel.getDataSize()

        if a == None:
            print 'no-selection'
            self.close()
            return

        if self.ui.rbin.isChecked() == True:
            open(name + '.drop', 'wb').write(dataModel.getStream(a, b))

        if self.ui.rhex.isChecked() == True:
            L = ['{0:02X}'.format(o) for o in dataModel.getStream(a, b)]

            l = len(L)
            for i in range(l/20 + 1):
                L.insert((i+0)*20 + i, '\n')
            
            open(name + '.drop' + '.hex', 'wb').write(' '.join(L))

        if self.ui.rpe.isChecked() == True:
            text = 'MZ'

            M = []
            idx = 0

            page = dataModel.getStream(a, b)
            size =  len(dataModel.getStream(a, b))
            while idx < size:
                idx = page.find(text, idx, size)

                if idx == -1:
                    break

                # skip main pe
                if idx != 0:
                    M.append(idx)

                idx += 2


            i = 0

            # for every MZ occourence
            for mz in M:
                # try to make an PE instance
                try:
                    pe = pefile.PE(data=str(dataModel.getStream(mz, size)))
                except pefile.PEFormatError, e:
                    continue


                # iterates sections, computes sum of all raw sizes
                raw = 0
                for s in pe.sections:
                    raw += s.SizeOfRawData

                # drop if < selected/file size
                if mz + raw < size:
                    open(name + ".drop.{0}.mzpe".format(i), 'wb').write(dataModel.getStream(mz, mz + pe.OPTIONAL_HEADER.SizeOfHeaders + raw))
                    print 'dropped from {0} to {1}'.format(hex(mz), hex(mz+raw))
                    i += 1

                """
                print mz
                lfanew = dataModel.getDWORD(mz + 0x3c)
                if mz + lfanew + 4 < size:
                    pe = dataModel.getDWORD(mz + lfanew)
                    if pe == 0x4550:
                        oh = mz + lfanew + 0x18
                        print '  ' + str(oh)
                        if oh + 0x38 + 4 < size:
                            print 'da'
                            sizeofimage = dataModel.getDWORD(oh + 0x38)
                            print '          ' + str(sizeofimage)
                            print 'size   ' + str(size)
                            i += 1
                            if mz + sizeofimage < size:
                                print 'chiar este! '
                                open(name + ".drop.{0}.mzpe".format(i), 'wb').write(dataModel.getStream(mz, mz+sizeofimage))
                                print 'dropped from {0} to {1}'.format(hex(mz), hex(mz+sizeofimage))
                """


        self.close()




class Qiew(QtGui.QWidget):
    
    def __init__(self):
        super(Qiew, self).__init__()
        self.initUI()

    def initUI(self):      

        if len(sys.argv) <= 1:
            print 'usage: qiew.py <file>'
            sys.exit()

        title = sys.argv[1]

        self.wid = binWidget(self, title)
        
        hbox = QtGui.QHBoxLayout()
        hbox.addWidget(self.wid)
        self.setLayout(hbox)

        screen = QtGui.QDesktopWidget().screenGeometry()        
        self.setGeometry(0, 0, screen.width()-100, screen.height()-100)

        self.setWindowTitle('qiew - {0}'.format(sys.argv[1]))
        self.showMaximized()
        self.wid.activateWindow()


def main():
    app = QtGui.QApplication(sys.argv)
    qiew = Qiew()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
