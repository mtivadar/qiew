from FileFormat import *
import Banners
import pefile
from TextTransformations import *
import PyQt4
from PyQt4 import QtGui, QtCore
from cemu import *
import time

from ui_dialog import Ui_Dialog


class PE(FileFormat):
#    def __init__(self):
#        print 'hello'
    name = 'pe'
    priority = 5
    def recognize(self, dataModel):
        self.dataModel = dataModel

        try:
            self.PE = pefile.PE(data=dataModel.getData())
        except:
            return False
        

        return True

    def setData(self, viewMode):
        self._viewMode = viewMode

    def getBanners(self):
    	return [PEBanner]
   
    def writeData(self, w):

        if hasattr(self.PE, 'FileInfo'):
            for f in self.PE.FileInfo:
                if f.Key == 'StringFileInfo':
                    for st in f.StringTable:
                        for entry in st.entries:
                            #print entry
                            w.ui.tableWidget_2.setColumnWidth(0, 300)                        
                            if entry == 'CompanyName':
                                w.ui.tableWidget_2.setItem(0, 0, QtGui.QTableWidgetItem(st.entries[entry]))

                            if entry == 'FileDescription':
                                w.ui.tableWidget_2.setItem(0, 1, QtGui.QTableWidgetItem(st.entries[entry]))

                            if entry == 'FileVersion':
                                w.ui.tableWidget_2.setItem(0, 2, QtGui.QTableWidgetItem(st.entries[entry]))

                            if entry == 'LegalCopyright':
                                w.ui.tableWidget_2.setItem(0, 3, QtGui.QTableWidgetItem(st.entries[entry]))

                            if entry == 'OriginalFilename':
                                w.ui.tableWidget_2.setItem(0, 4, QtGui.QTableWidgetItem(st.entries[entry]))

                            if entry == 'ProductName':
                                w.ui.tableWidget_2.setItem(0, 5, QtGui.QTableWidgetItem(st.entries[entry]))

                            if entry == 'ProductVersion':
                                w.ui.tableWidget_2.setItem(0, 6, QtGui.QTableWidgetItem(st.entries[entry]))



        w.ui.tableWidget.setItem(0, 0, QtGui.QTableWidgetItem('bka'))

        w.ui.treeWidget.resizeColumnToContents(0)

        parent = w.ui.treeWidget


        # add sections

        for section in self.PE.sections:
            child  = QtGui.QTreeWidgetItem(None)            
            child.setText(0, section.Name)            
            parent.topLevelItem(3).addChild(child)


        # add imports
        parent = w.ui.treeWidgetImports
        parent.setColumnWidth(0, 300) 
        for i, entry in enumerate(self.PE.DIRECTORY_ENTRY_IMPORT):
            
            child = QtGui.QTreeWidgetItem(None)
            child.setText(0, entry.dll)
            parent.addTopLevelItem(child)

            for imp in entry.imports:
                child = QtGui.QTreeWidgetItem(None)
                if imp.name:
                    child.setText(0, imp.name)
                    child.setText(1, '0x{0:X}'.format(imp.address-self.PE.OPTIONAL_HEADER.ImageBase))

                    parent.topLevelItem(i).addChild(child)

                if imp.ordinal:
                    child.setText(0, 'ordinal:{0}'.format(imp.ordinal))
                    child.setText(1, '0x{0:X}'.format(imp.address-self.PE.OPTIONAL_HEADER.ImageBase))

                    parent.topLevelItem(i).addChild(child)


        # populate with sections
        parent = w.ui.treeWidgetSections
        parent.setColumnWidth(0, 100) 
        parent.setColumnWidth(1, 80) 
        parent.setColumnWidth(2, 80) 
        parent.setColumnWidth(3, 80) 
        parent.setColumnWidth(4, 80)        

        for section in self.PE.sections:
            child  = QtGui.QTreeWidgetItem(None)
            child.setText(0, section.Name)
            child.setText(1, '{0:X}'.format(section.PointerToRawData))
            child.setText(2, '{0:X}'.format(section.SizeOfRawData))
            child.setText(3, '{0:X}'.format(section.VirtualAddress))
            child.setText(4, '{0:X}'.format(section.Misc_VirtualSize))
            
            # build characteristics string for every section
            fr = 'R' if section.IMAGE_SCN_MEM_READ else '-'
            fw = 'W' if section.IMAGE_SCN_MEM_WRITE else '-'
            fe = 'E' if section.IMAGE_SCN_MEM_EXECUTE else '-'

            fc = 'C' if section.IMAGE_SCN_CNT_CODE else '-'
            fi = 'I' if section.IMAGE_SCN_CNT_INITIALIZED_DATA else '-'
            fu = 'U' if section.IMAGE_SCN_CNT_UNINITIALIZED_DATA else '-'


            
            child.setText(5, '{0:X} {1}'.format(section.Characteristics, '[{0}{1}{2}  {3}{4}{5}]'.format(fr, fw, fe, fc, fi, fu)))

            for i in range(6)[1:]:
                child.setTextAlignment(i, QtCore.Qt.AlignRight)

            parent.addTopLevelItem(child)


        # populate with directories
        parent = w.ui.treeWidgetDirectories
        parent.setColumnWidth(0, 150) 

        for d in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            child  = QtGui.QTreeWidgetItem(None)
            child.setText(0, d.name.replace('IMAGE_DIRECTORY_ENTRY_', ''))

            if d.VirtualAddress != 0 and d.Size != 0:
                for section in self.PE.sections:
                    if section.contains_rva(d.VirtualAddress):
                        child.setText(1, '{0}'.format(section.Name))
                        break
                else:
                    child.setText(1, '{0}'.format('<outside>'))


                child.setText(2, '{0:X}'.format(d.VirtualAddress))
                child.setText(3, '{0:X}'.format(d.Size))
            else:
                child.setTextColor(0, QtGui.QColor('lightgray'))

            parent.addTopLevelItem(child)

            for i in range(4)[1:]:
                child.setTextAlignment(i, QtCore.Qt.AlignRight)


        print self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[0].name


    def doit(self):
        if not self.w.isVisible():
            #self.w.setModal(True)
            self.w.show()
            #self._parent.releaseKeyboard()  #TODO: ugly
            #self.w.activateWindow()
            self.w.ui.treeWidget.setFocus()
            self.w.ui.treeWidget.activateWindow()

  #          self.writeData(self.w)


        else:

            #self._parent.grabKeyboard()
            #self._parent.activateWindow()
            #self._viewMode.grabKeyboard()
            #self._viewMode.activateWindow()
            #self.w.releaseKeyboard()
            self.w.hide()

    def shortVersionInfo(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tableWidget_2.setFocus()
            self.w.ui.tableWidget_2.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(4)
 #           self.writeData(self.w)


        else:
            self.w.hide()


    def shortHeader(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tableWidget_2.setFocus()
            self.w.ui.tableWidget_2.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(0)
 #           self.writeData(self.w)


        else:
            self.w.hide()

    def shortImports(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tableWidget_2.setFocus()
            self.w.ui.tableWidget_2.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(3)
            self.w.ui.treeWidgetImports.setFocus()
 #           self.writeData(self.w)


        else:
            self.w.hide()

    def shortSections(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tableWidget_2.setFocus()
            self.w.ui.tableWidget_2.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(1)
            self.w.ui.treeWidgetSections.setFocus()
#            self.writeData(self.w)


        else:
            self.w.hide()

    def shortDirectories(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tableWidget_2.setFocus()
            self.w.ui.tableWidget_2.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(2)
            self.w.ui.treeWidgetDirectories.setFocus()
#            self.writeData(self.w)


        else:
            self.w.hide()

    def registerShortcuts(self, parent):
        self.w = WHeaders(parent, self)
        self._parent = parent
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+H"), parent, self.doit, self.doit)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+V"), parent, self.shortVersionInfo, self.shortVersionInfo)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+H"), parent, self.shortHeader, self.shortHeader)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+I"), parent, self.shortImports, self.shortImports)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+S"), parent, self.shortSections, self.shortSections)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+D"), parent, self.shortDirectories, self.shortDirectories)

        self.writeData(self.w)


class ImportsEventFilter(QtCore.QObject):
    def __init__(self, plugin, ui):
        super(QtCore.QObject, self).__init__()
        self.ui = ui
        self.plugin = plugin

    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Return:

                # get RVA column from treeView
                item = self.ui.treeWidgetImports.currentItem()
                rva = self.ui.treeWidgetImports.indexFromItem(item, 1).data().toString()
                if rva:
                    # strip 0x
                    rva = int(str(rva[2:]), 16)

                    offset = self.plugin.PE.get_offset_from_rva(rva)

                    self.plugin._viewMode.goTo(offset)
                    #self.plugin._viewMode.transformationEngine.makeSelection(Selection(0x1000+20, 0x1000+20+200, QtGui.QBrush(QtGui.QColor(100, 80, 0))))

        return False


class SectionsEventFilter(QtCore.QObject):
    def __init__(self, plugin, ui):
        super(QtCore.QObject, self).__init__()
        self.ui = ui
        self.plugin = plugin

    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Return:

                # get file-address column from treeView
                item = self.ui.treeWidgetSections.currentItem()
                offset = self.ui.treeWidgetSections.indexFromItem(item, 1).data().toString()
                offset = int(str(offset), 16)

                self.plugin._viewMode.goTo(offset)
                #self.plugin._viewMode.transformationEngine.makeSelection(Selection(0x1000+20, 0x1000+20+200, QtGui.QBrush(QtGui.QColor(100, 80, 0))))

            if event.key() == QtCore.Qt.Key_F9:
                item = self.ui.treeWidgetSections.currentItem()
                offset = self.ui.treeWidgetSections.indexFromItem(item, 1).data().toString()
                offset = int(str(offset), 16)

                size = self.ui.treeWidgetSections.indexFromItem(item, 2).data().toString()
                size = int(str(size), 16)

                #self.plugin._viewMode.transformationEngine.makeSelection(Selection(offset, offset + size, QtGui.QBrush(QtGui.QColor(100, 80, 0))))
                self.plugin._viewMode.selector.addSelection((offset, offset+size))
                self.plugin._viewMode.goTo(offset)

        return False

class DirectoriesEventFilter(QtCore.QObject):
    def __init__(self, plugin, widget):
        super(QtCore.QObject, self).__init__()
        self.widget = widget
        self.plugin = plugin

    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Return:

                # get file-address column from treeView
                item = self.widget.currentItem()
                offset = self.widget.indexFromItem(item, 2).data().toString()
                if offset:
                    offset = int(str(offset), 16)
                    offset = self.plugin.PE.get_offset_from_rva(offset)

                    self.plugin._viewMode.goTo(offset)
                #self.plugin._viewMode.transformationEngine.makeSelection(Selection(0x1000+20, 0x1000+20+200, QtGui.QBrush(QtGui.QColor(100, 80, 0))))

            if event.key() == QtCore.Qt.Key_F9:
                item = self.widget.currentItem()
                offset = self.widget.indexFromItem(item, 2).data().toString()
                size = self.widget.indexFromItem(item, 3).data().toString()

                if offset and size:

                    offset = int(str(offset), 16)
                    size = int(str(size), 16)

                    offset = self.plugin.PE.get_offset_from_rva(offset)
                    #self.plugin._viewMode.transformationEngine.makeSelection(Selection(offset, offset + size, QtGui.QBrush(QtGui.QColor(100, 80, 0))))
                    self.plugin._viewMode.selector.addSelection((offset, offset+size))
                    self.plugin._viewMode.goTo(offset)

        return False


class WHeaders(QtGui.QDialog):
    
    def __init__(self, parent, plugin):
        super(WHeaders, self).__init__(parent)
        
        self._parent = parent
        self.plugin = plugin

        self.ui = PyQt4.uic.loadUi('./plugins/format/dialog_pe.ui', baseinstance=self)

        self.ei = ImportsEventFilter(plugin, self.ui)
        self.ui.treeWidgetImports.installEventFilter(self.ei)

        self.es = SectionsEventFilter(plugin, self.ui)
        self.ui.treeWidgetSections.installEventFilter(self.es)


        self.ed = DirectoriesEventFilter(plugin, self.ui.treeWidgetDirectories)
        self.ui.treeWidgetDirectories.installEventFilter(self.ed)

        self.initUI()

    def doit(self):
        self.close()

    def initUI(self):      

        screen = QtGui.QDesktopWidget().screenGeometry()        
        #self.setGeometry(0, 0, screen.width()-100, screen.height()-100)
        self.setGeometry(100, 100, 624, 510)
        self.setWindowTitle('PE header')
        
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+F"), self, self.doit, self.doit)        


        #self.installEventFilter(self)
        #self.installEventFilter(self.ex.treeWidgetImports)
        

        #self.setWindowFlags(QtCore.Qt.WindowDoesNotAcceptFocus)
        #self.setWindowFlags()
    #def keyPressEvent(self, event):
    #    print 'aaa'
    

    """
    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            #print 'da'
            key = event.key()
            modifiers = event.modifiers()
            if key == QtCore.Qt.Key_Left:
                print 'left'

                # new style?
                self._parent.scrolled.emit(2)

                # old style
                self._parent.emit(QtCore.SIGNAL('scroll'), 10)

                #self.plugin.dataModel.slidePage(1)
                #self.plugin._viewMode.scrollPages(1)                
                #self._parent.update()
                self.keyleft = True


        return True
    """        
#        self.setWindowFlags()



class PEBanner(Banners.Banner):
    def __init__(self, dataModel, viewMode):
        self.width = 0
        self.height = 0
        self.dataModel = dataModel
        self.viewMode = viewMode
        self.qpix = self._getNewPixmap(self.width, self.height)
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        initPE = True
        try:
            self.PE = pefile.PE(data=dataModel.getData())
        except:
            initPE = False
        

        # text font
        self.font = QtGui.QFont('Terminus', 11, QtGui.QFont.Bold)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self.fontWidth  = fm.width('a')
        self.fontHeight = fm.height()

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 0, QtCore.Qt.SolidLine)


        if initPE == False:
            return

        try:
            for t in self.PE.DIRECTORY_ENTRY_RESOURCE.entries:

                for rid in t.directory.entries:

                    for d in rid.directory.entries:
                        offset =  d.data.struct.OffsetToData
                        size = d.data.struct.Size
                        #print d.data.struct
                        #print offset, size
                        #self.viewMode.transformationEngine.addPenInterval(offset, offset + size, QtGui.QPen(QtGui.QColor(128, 128, 0), 0, QtCore.Qt.SolidLine))
        except:
            pass

        start = self.PE.get_overlay_data_start_offset()
        if start:
            self.viewMode.transformationEngine.addPenInterval(start, start + self.dataModel.getDataSize(), QtGui.QPen(QtGui.QColor(128, 128, 128), 0, QtCore.Qt.SolidLine), ignoreHighlights=False)
        #selection = Selection(start, start + self.dataModel.getDataSize(), brush=QtGui.QBrush(QtGui.QColor(128, 128, 128)), opacity=0.4)
        #self.viewMode.transformationEngine.makeSelection(selection)

        

    def getOrientation(self):
        return Banners.Orientation.Left

    def getDesiredGeometry(self):
        return 170
    def setViewMode(self, viewMode):
        self.viewMode = viewMode

    def getPixmap(self):
        return self.qpix

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

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
        
        for i in range(rows):
            s = '--------'
            section = self.PE.get_section_by_offset(offset)
            if section:
                s = section.Name.replace('\0', ' ')
            """
            for section in self.PE.sections:
                if section.PointerToRawData <= offset:
                    if section.PointerToRawData + section.SizeOfRawData >= offset:
                        s = section.Name.replace('\0', ' ')
                        break
            """

            #sOff = '{0:08x}'.format(offset)
            sOff = '{0:08x}'.format(self.PE.get_rva_from_offset(offset) + self.PE.OPTIONAL_HEADER.ImageBase)
            sDisplay = '{0} {1}'.format(s, sOff)
            qp.drawText(0+5, (i+1) * self.fontHeight, sDisplay)
            #qp.drawText(95, (i+1) * self.fontHeight, sDisplay)
            offset += columns
        

        qp.end()

    def resize(self, width, height):
        self.width = width
        self.height = height

        self.qpix = self._getNewPixmap(self.width, self.height)
