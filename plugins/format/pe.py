import sys, os
from FileFormat import *
import Banners
import pefile
from TextDecorators import *
import TextSelection

import PyQt4
from PyQt4 import QtGui, QtCore
from cemu import *
import time

import distorm3

class PE(FileFormat):
    name = 'pe'
    priority = 5
    def recognize(self, dataModel):
        self.dataModel = dataModel

        try:
            self.PE = pefile.PE(data=dataModel.getData())
        except:
            return False
        
        return True


    def getVA(self, offset):
        return self.PE.get_rva_from_offset(offset) + self.PE.OPTIONAL_HEADER.ImageBase

    def init(self, viewMode):
        self._viewMode = viewMode
        self.viewMode = viewMode        

        start = self.PE.get_overlay_data_start_offset()

        self.MZbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
        self.greenPen = QtGui.QPen(QtGui.QColor(255, 255, 0))
        self.grayBrush = QtGui.QBrush(QtGui.QColor(128, 128, 128))
        self.whitePen = QtGui.QPen(QtGui.QColor(255, 255, 255))        


        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'MZ', brush=self.MZbrush, pen=self.greenPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'PE\x00\x00', brush=self.MZbrush, pen=self.greenPen)
        self.textDecorator = HighlightPrefix(self.textDecorator, '\xFF\x15', additionalLength=4, brush=self.grayBrush, pen=self.whitePen)
        self.textDecorator = HighlightWideChar(self.textDecorator)

        if start:
            self.textDecorator = RangePen(self.textDecorator, start, start + self.dataModel.getDataSize(), QtGui.QPen(QtGui.QColor(128, 128, 128), 0, QtCore.Qt.SolidLine), ignoreHighlights=False)


        self.viewMode.setTransformationEngine(self.textDecorator)
        
    def hintDisasm(self):

        if self.PE.FILE_HEADER.Machine & pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return distorm3.Decode64Bits

        if self.PE.FILE_HEADER.Machine & pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return distorm3.Decode32Bits

        return distorm3.Decode32Bits

    def hintDisasmVA(self, offset):
        return self.getVA(offset)

    def stringFromVA(self, va):
        try:
           offset = self.PE.get_offset_from_rva(va - self.PE.OPTIONAL_HEADER.ImageBase)
        except:
            return ''

        doit = True
        s = ''
        data = self.dataModel

        import string
        Special =  string.ascii_letters + string.digits + ' .;\':;=\"?-!()/\\_'
        while doit:
            c = data.getChar(offset)

            if not c:
                break

            if c in Special:
                s += c
                offset += 1

                c1 = data.getChar(offset)
                c2 = data.getChar(offset+1)
                if not c1 or not c2:
                    break

                if c1 == '\0' and c2 in Special:
                    offset += 1
            else:
                doit = False

        return s

    def disasmVAtoFA(self, va):
        try:
            offset = self.PE.get_offset_from_rva(va - self.PE.OPTIONAL_HEADER.ImageBase)
        except:
            return None

        return offset

    def disasmSymbol(self, va):
        if not hasattr(self.PE, 'DIRECTORY_ENTRY_IMPORT'):
            return None

        # TODO: should implement with a lookup table
        for i, entry in enumerate(self.PE.DIRECTORY_ENTRY_IMPORT):

            for imp in entry.imports:
                if imp.address == va:
                    name = ''
                    if imp.name:
                        name = imp.name

                    if imp.ordinal:
                        name = imp.ordinal

                    return '{0}:{1}'.format(entry.dll, name)

        return None




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


        # add imports
        parent = w.ui.treeWidgetImports
        parent.setColumnWidth(0, 300) 
        try:
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
        except Exception, e:
            print e

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

            child.setTextColor(1, QtGui.QColor('green'))
            child.setTextColor(2, QtGui.QColor('green'))


            child.setTextColor(3, QtGui.QColor(183, 72, 197))
            child.setTextColor(4, QtGui.QColor(183, 72, 197))
            
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
                for i, section in enumerate(self.PE.sections):
                    if section.contains_rva(d.VirtualAddress):
                        child.setText(1, '{0} [{1}]'.format(section.Name.strip('\0'), i))
                        child.setTextColor(1, QtGui.QColor('red'))
                        break
                else:
                    child.setText(1, '{0}'.format('<outside>'))


                child.setText(2, '{0:X}'.format(d.VirtualAddress))
                child.setText(3, '{0:X}'.format(d.Size))
                child.setTextColor(2, QtGui.QColor('green'))
                child.setTextColor(3, QtGui.QColor('green'))
            else:
                child.setTextColor(0, QtGui.QColor('lightgray'))

            parent.addTopLevelItem(child)

            for i in range(4)[1:]:
                child.setTextAlignment(i, QtCore.Qt.AlignRight)



        # populate Header
        parent = w.ui.treeWidgetHeader
        parent.setColumnWidth(0, 250) 

        bkbrush = QtGui.QBrush(QtGui.QColor(192, 165, 194))
        bkbrush2 = QtGui.QBrush(QtGui.QColor(232, 194, 229))

        child = QtGui.QTreeWidgetItem(None)

        child.setText(0, 'IMAGE_DOS_HEADER')
        child.setBackground(0, bkbrush)

        ch2 = QtGui.QTreeWidgetItem(['magic', 'word', '{0:X}'.format(int(self.PE.DOS_HEADER.e_magic))])
        ch2.setTextColor(2, QtGui.QColor('green'))
        ch2.setTextColor(1, QtGui.QColor(183, 72, 197))
        child.addChild(ch2)

        ch2 = QtGui.QTreeWidgetItem(['e_lfanew', 'word', '{0:X}'.format(int(self.PE.DOS_HEADER.e_lfanew))])
        ch2.setTextColor(2, QtGui.QColor('green'))
        ch2.setTextColor(1, QtGui.QColor(183, 72, 197))        
        child.addChild(ch2)

        parent.addTopLevelItem(child)


        item = QtGui.QTreeWidgetItem(['IMAGE_NT_HEADERS'])
        item.setBackground(0, bkbrush)

        child = QtGui.QTreeWidgetItem(['Signature', 'word',  '{0:X}'.format(int(self.PE.NT_HEADERS.Signature))])
        child.setTextColor(2, QtGui.QColor('green'))
        child.setTextColor(1, QtGui.QColor(183, 72, 197))

        item.addChild(child)

        subitem = QtGui.QTreeWidgetItem(['IMAGE_FILE_HEADER'])
        subitem.setBackground(0, bkbrush2)

        child = QtGui.QTreeWidgetItem(['Machine', 'word',  '{0:X}'.format(int(self.PE.FILE_HEADER.Machine))])
        child.setTextColor(2, QtGui.QColor('green'))
        child.setTextColor(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)

        child = QtGui.QTreeWidgetItem(['NumberOfSections', 'word',  '{0:X}'.format(int(self.PE.FILE_HEADER.NumberOfSections))])
        child.setTextColor(2, QtGui.QColor('green'))
        child.setTextColor(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)

        child = QtGui.QTreeWidgetItem(['TimeDateStamp', 'dword',  '{0:X}'.format(int(self.PE.FILE_HEADER.TimeDateStamp))])
        child.setTextColor(2, QtGui.QColor('green'))
        child.setTextColor(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)

        child = QtGui.QTreeWidgetItem(['Characteristics', 'dword',  '{0:X}'.format(int(self.PE.FILE_HEADER.Characteristics))])
        child.setTextColor(2, QtGui.QColor('green'))
        child.setTextColor(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)
        item.addChild(subitem)


        subitem = QtGui.QTreeWidgetItem(['IMAGE_OPTIONAL_HEADER'])
        subitem.setBackground(0, bkbrush2)

        Data = [['Magic', 'word',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.Magic))],
                ['SizeOfCode', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfCode))],
                ['SizeOfInitializedData', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfInitializedData))],
                ['SizeOfUninitializedData', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfUninitializedData))],
                ['AddressOfEntryPoint', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.AddressOfEntryPoint))],
                ['BaseOfCode', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.BaseOfCode))],
                ['ImageBase', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.ImageBase))],
                ['SectionAlignment', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SectionAlignment))],
                ['FileAlignment', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.FileAlignment))],
                ['SizeOfImage', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfImage))],
                ['SizeOfHeaders', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfHeaders))],
                ['CheckSum', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.CheckSum))],
                ['Magic', 'word',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.Magic))],
                ['SizeOfCode', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfCode))],
                ['SizeOfInitializedData', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfInitializedData))],
                ['SizeOfUninitializedData', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfUninitializedData))],
                ['AddressOfEntryPoint', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.AddressOfEntryPoint))],
                ['BaseOfCode', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.BaseOfCode))],
                ['ImageBase', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.ImageBase))],
                ['SectionAlignment', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SectionAlignment))],
                ['FileAlignment', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.FileAlignment))],
                ['SizeOfImage', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfImage))],
                ['SizeOfHeaders', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.SizeOfHeaders))],
                ['CheckSum', 'dword',  '{0:X}'.format(int(self.PE.OPTIONAL_HEADER.CheckSum))]]

        for it in Data:
            child = QtGui.QTreeWidgetItem(it)

            child.setTextColor(2, QtGui.QColor('green'))
            child.setTextColor(1, QtGui.QColor(183, 72, 197))

            subitem.addChild(child)


        child = QtGui.QTreeWidgetItem(['IMAGE_DATA_DIRECTORY [16]'])
        child.setBackground(0, bkbrush2)

        for i, d in enumerate(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY):
            subchild = QtGui.QTreeWidgetItem(['[{0}] {1}'.format(i, d.name.replace('IMAGE_DIRECTORY_ENTRY_', ''))])
            if d.VirtualAddress == 0 and d.Size == 0:
                subchild.setTextColor(0, QtGui.QColor('lightgray'))

            c = QtGui.QTreeWidgetItem(['VirtualAddress', 'dword', '{0:X}'.format(int(d.VirtualAddress))])
            c.setTextColor(2, QtGui.QColor('green'))
            c.setTextColor(1, QtGui.QColor(183, 72, 197))
            subchild.addChild(c)

            c = QtGui.QTreeWidgetItem(['Size', 'dword', '{0:X}'.format(int(d.Size))])
            c.setTextColor(2, QtGui.QColor('green'))
            c.setTextColor(1, QtGui.QColor(183, 72, 197))
            subchild.addChild(c)

            child.addChild(subchild)


        subitem.addChild(child)

        item.addChild(subitem)


        parent.addTopLevelItem(item) # NT_HEADERS


        _item =  QtGui.QTreeWidgetItem(['{0}'.format('IMAGE_SECTION_HEADERS []')])
        parent.addTopLevelItem(_item)

        for i, section in enumerate(self.PE.sections):
            item =  QtGui.QTreeWidgetItem(['{0} [{1}]'.format('SECTION_HEADER', i)])
            item.setBackground(0, bkbrush)

            Data = [['Name', 'char[8]',  section.Name],
                    ['VirtualSize', 'dword',  '{0:X}'.format(int(section.Misc_VirtualSize))],
                    ['VirtualAddress', 'dword',  '{0:X}'.format(int(section.VirtualAddress))],
                    ['SizeOfRawData', 'dword',  '{0:X}'.format(int(section.SizeOfRawData))],
                    ['PointerToRawData', 'dword',  '{0:X}'.format(int(section.PointerToRawData))],
                    ['Characteristics', 'dword',  '{0:X}'.format(int(section.Characteristics))]
            ]

            for data in Data:
                child = QtGui.QTreeWidgetItem(data)
                child.setTextColor(2, QtGui.QColor('green'))
                child.setTextColor(1, QtGui.QColor(183, 72, 197))

                item.addChild(child)

            _item.addChild(item)



        #print self.PE


        """
        

        parent = w.ui.treeWidget


        # add sections

        for section in self.PE.sections:
            child  = QtGui.QTreeWidgetItem(None)            
            child.setText(0, section.Name)            
            parent.topLevelItem(3).addChild(child)
        """

    def doit(self):
        if not self.w.isVisible():
            #self.w.setModal(True)
            self.w.show()
            #self._parent.releaseKeyboard()  #TODO: ugly
            #self.w.activateWindow()
            self.w.ui.treeWidgetHeader.setFocus()
            self.w.ui.treeWidgetHeader.activateWindow()

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

    def F7(self):
        offset = self.PE.get_offset_from_rva(self.PE.OPTIONAL_HEADER.AddressOfEntryPoint)
        self._viewMode.goTo(offset)

    def registerShortcuts(self, parent):
        self.w = WHeaders(parent, self)
        self._parent = parent
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+H"), parent, self.doit, self.doit)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+V"), parent, self.shortVersionInfo, self.shortVersionInfo)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+H"), parent, self.shortHeader, self.shortHeader)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+I"), parent, self.shortImports, self.shortImports)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+S"), parent, self.shortSections, self.shortSections)
        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+D"), parent, self.shortDirectories, self.shortDirectories)

        shortcut = QtGui.QShortcut(QtGui.QKeySequence("F7"), parent, self.F7, self.F7)

        self.writeData(self.w)


class ImportsEventFilter(QtCore.QObject):
    def __init__(self, plugin, widget):
        super(QtCore.QObject, self).__init__()
        self.widget = widget
        self.plugin = plugin

    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Return:

                # get RVA column from treeView
                item = self.widget.currentItem()
                rva = self.widget.indexFromItem(item, 1).data().toString()
                if rva:
                    # strip 0x
                    rva = int(str(rva[2:]), 16)

                    offset = self.plugin.PE.get_offset_from_rva(rva)

                    self.plugin._viewMode.goTo(offset)

        return False


class SectionsEventFilter(QtCore.QObject):
    def __init__(self, plugin, widget):
        super(QtCore.QObject, self).__init__()
        self.widget = widget
        self.plugin = plugin

    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Return:

                # get file-address column from treeView
                item = self.widget.currentItem()
                offset = self.widget.indexFromItem(item, 1).data().toString()
                offset = int(str(offset), 16)

                self.plugin._viewMode.goTo(offset)

            if event.key() == QtCore.Qt.Key_F9:
                item = self.widget.currentItem()
                offset = self.widget.indexFromItem(item, 1).data().toString()
                offset = int(str(offset), 16)

                size = self.widget.indexFromItem(item, 2).data().toString()
                size = int(str(size), 16)

                self.plugin._viewMode.selector.addSelection((offset, offset+size), type=TextSelection.SelectionType.NORMAL)
                self.plugin._viewMode.goTo(offset)

        return False


class HeaderEventFilter(QtCore.QObject):
    def __init__(self, plugin, widget):
        super(QtCore.QObject, self).__init__()
        self.widget = widget
        self.plugin = plugin

    def eventFilter(self, watched, event):
        if event.type() == QtCore.QEvent.KeyPress:
            item = self.widget.currentItem()
            txt = self.widget.indexFromItem(item, 0).data().toString()

            if event.key() == QtCore.Qt.Key_Return:

                if txt == 'IMAGE_DOS_HEADER':
                    offset = self.plugin.PE.DOS_HEADER.get_file_offset()
                    self.plugin._viewMode.goTo(offset)




            if event.key() == QtCore.Qt.Key_F9:

                if txt == 'IMAGE_DOS_HEADER':
                    offset = self.plugin.PE.DOS_HEADER.get_file_offset()
                    size = self.plugin.PE.DOS_HEADER.sizeof()

                if txt == 'IMAGE_NT_HEADERS':
                    offset = self.plugin.PE.NT_HEADERS.get_file_offset()
                    size = self.plugin.PE.NT_HEADERS.sizeof()

                if txt == 'IMAGE_FILE_HEADER':
                    offset = self.plugin.PE.FILE_HEADER.get_file_offset()
                    size = self.plugin.PE.FILE_HEADER.sizeof()

                if txt == 'IMAGE_OPTIONAL_HEADER':
                    offset = self.plugin.PE.OPTIONAL_HEADER.get_file_offset()
                    size = self.plugin.PE.OPTIONAL_HEADER.sizeof()

                if offset:
                    self.plugin._viewMode.goTo(offset)
                    self.plugin._viewMode.selector.addSelection((offset, offset+size), type=TextSelection.SelectionType.NORMAL)

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
                    self.plugin._viewMode.selector.addSelection((offset, offset+size), type=TextSelection.SelectionType.NORMAL)
                    self.plugin._viewMode.goTo(offset)

        return False


class WHeaders(QtGui.QDialog):
    
    def __init__(self, parent, plugin):
        super(WHeaders, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(WHeaders, self).show

        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt4.uic.loadUi(os.path.join(root, 'plugins', 'format','pe.ui'), baseinstance=self)

        self.ei = ImportsEventFilter(plugin, self.ui.treeWidgetImports)
        self.ui.treeWidgetImports.installEventFilter(self.ei)

        self.es = SectionsEventFilter(plugin, self.ui.treeWidgetSections)
        self.ui.treeWidgetSections.installEventFilter(self.es)

        self.ed = DirectoriesEventFilter(plugin, self.ui.treeWidgetDirectories)
        self.ui.treeWidgetDirectories.installEventFilter(self.ed)

        self.eh = HeaderEventFilter(plugin, self.ui.treeWidgetHeader)
        self.ui.treeWidgetHeader.installEventFilter(self.eh)

        self.initUI()

    def show(self):

        # TODO: remember position? resize plugin windows when parent resize?
        pwidth = self.parent.parent.size().width()
        pheight = self.parent.parent.size().height()

        width = self.ui.tabWidget.size().width()+15
        height = self.ui.tabWidget.size().height()+15

        self.setGeometry(pwidth - width - 15, pheight - height, width, height)
        self.setFixedSize(width, height)

        self.oshow()

    def initUI(self):      

        self.setWindowTitle('PE plugin')
        self.setSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)

        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+F"), self, self.close, self.close)

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
            
            columns = self.viewMode.getColumnsbyRow(i)

            section = self.PE.get_section_by_offset(offset)
            if section:
                s = section.Name.replace('\0', ' ')

            sOff = '{0:08x}'.format(self.PE.get_rva_from_offset(offset) + self.PE.OPTIONAL_HEADER.ImageBase)
            sDisplay = '{0} {1}'.format(s, sOff)
            qp.drawText(0+5, (i+1) * self.fontHeight, sDisplay)
            offset += columns
        

        qp.end()

    def resize(self, width, height):
        self.width = width
        self.height = height

        self.qpix = self._getNewPixmap(self.width, self.height)
