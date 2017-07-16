import sys, os, logging
from FileFormat import *
import Banners
import pefile
from TextDecorators import *
import TextSelection

import PyQt5
from PyQt5 import QtGui, QtCore, QtWidgets
from cemu import *
import time

import DisasmViewMode

logger = logging.getLogger(__name__)

class PE(FileFormat):
    name = 'pe'
    priority = 5

    DisplayTypes = ['VA', 'RVA', 'FA']

    def recognize(self, dataModel):
        self.dataModel = dataModel

        try:
            self.PE = pefile.PE(data=dataModel.getData())
        except:
            return False
        
        return True


    def getVA(self, offset):
        return self.PE.get_rva_from_offset(offset) + self.PE.OPTIONAL_HEADER.ImageBase

    def changeAddressMode(self):
        self.DisplayTypes = self.DisplayTypes[1:] + [self.DisplayTypes[0]]

    def getAddressMode(self):
        return self.DisplayTypes[0]

    def init(self, viewMode, parent):
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

        ep = self.PE.get_offset_from_rva(self.PE.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.viewMode.selector.addSelection((ep, ep + 30, QtGui.QBrush(QtGui.QColor(51, 153, 255)), 0.5), type=TextSelection.SelectionType.PERMANENT)

        if start:
            # overlay
            self.textDecorator = RangePen(self.textDecorator, start, start + self.dataModel.getDataSize(), QtGui.QPen(QtGui.QColor(128, 128, 128), 0, QtCore.Qt.SolidLine), ignoreHighlights=False)

        for d in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.Size != 0:
                if d.name == 'IMAGE_DIRECTORY_ENTRY_IAT':
                    start = self.PE.get_offset_from_rva(d.VirtualAddress)
                    size  = d.Size
                    self.textDecorator = RangePen(self.textDecorator, start, start + size, QtGui.QPen(QtGui.QColor(0, 200, 0), 0, QtCore.Qt.SolidLine), ignoreHighlights=False)                    

        self.viewMode.setTransformationEngine(self.textDecorator)
        
    def hintDisasm(self):

        if self.PE.FILE_HEADER.Machine & pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return DisasmViewMode.Disasm_x86_64bit

        if self.PE.FILE_HEADER.Machine & pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return DisasmViewMode.Disasm_x86_32bit

        return DisasmViewMode.Disasm_x86_32bit

    def hintDisasmVA(self, offset):
        return self.getVA(offset)

    def hintBanner(self, offset):
        if offset >= self.PE.DOS_HEADER.get_file_offset() and offset < self.PE.DOS_HEADER.sizeof():
            name = 'DOS header'
            return name

        base = self.PE.FILE_HEADER.get_file_offset()
        if offset >= base and offset < base + self.PE.FILE_HEADER.sizeof():
            name = 'File header'
            return name

        base = self.PE.OPTIONAL_HEADER.get_file_offset()
        end = base + self.PE.OPTIONAL_HEADER.sizeof() + len(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY) * 8


        if offset >= base and offset < end:
            name = 'Opt. header'
            return name

        # section headers
        if offset >= end and offset < (end + len(self.PE.sections) * 0x28):
            name = 'Section header'
            return name

        DirectoryNames = ['Export', 'Import', 'Resource', 'Exception', 'Security', 'BaseReloc', 'Debug', 'Copyright', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT',
                          'DelayedImports', 'COM Descr.', 'Reserved']

        end += len(self.PE.sections) * 0x28
        for i, o in enumerate(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY):
            if o.VirtualAddress != 0 and o.Size != 0:
                s = self.PE.get_offset_from_rva(o.VirtualAddress)
                e = s + o.Size
                if offset >= s and offset < e:
                    name = DirectoryNames[i]
                    return name


        if self.PE.get_overlay_data_start_offset() is not None:
            if offset >= self.PE.get_overlay_data_start_offset():
                name = 'Overlay'
                return name

        name = self.PE.get_section_by_offset(offset)
        if name is None:
            name = ''
        else:
            name = name.Name
            
        return name

    def stringFromVA(self, va):
        try:
           offset = self.PE.get_offset_from_rva(va - self.PE.OPTIONAL_HEADER.ImageBase)
        except:
            return ''

        doit = True
        s = bytearray()
        data = self.dataModel

        import string
        Special = (string.ascii_letters + string.digits + ' .;\':;=\"?-!()/\\_').encode('cp437')
        while doit:
            c = data.getChar(offset)

            if not c:
                break

            if c in Special:
                s.append(c)
                offset += 1

                c1 = data.getChar(offset)
                c2 = data.getChar(offset+1)
                if not c1 or not c2:
                    break

                if c1 == '\0' and c2 in Special:
                    offset += 1
            else:
                doit = False

        return s.decode('cp437')

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

                    return '{0}:{1}'.format(entry.dll.decode('cp437'), name.decode('cp437'))

        return None




    def getBanners(self):
        self.banners = [PEBanner(self.dataModel, self.viewMode, self), PEHeaderBanner(self.dataModel, self.viewMode, self), PEBottomBanner(self.dataModel, self.viewMode, self)]
        return self.banners
   
    def writeData(self, w):

        if hasattr(self.PE, 'FileInfo'):
            for f in self.PE.FileInfo:
                if f.Key == 'StringFileInfo':
                    for st in f.StringTable:
                        for entry in st.entries:
                            #print entry
                            w.ui.tableWidget_2.setColumnWidth(0, 300)                        
                            if entry == 'CompanyName':
                                w.ui.tableWidget_2.setItem(0, 0, QtWidgets.QTableWidgetItem(st.entries[entry]))

                            if entry == 'FileDescription':
                                w.ui.tableWidget_2.setItem(0, 1, QtWidgets.QTableWidgetItem(st.entries[entry]))

                            if entry == 'FileVersion':
                                w.ui.tableWidget_2.setItem(0, 2, QtWidgets.QTableWidgetItem(st.entries[entry]))

                            if entry == 'LegalCopyright':
                                w.ui.tableWidget_2.setItem(0, 3, QtWidgets.QTableWidgetItem(st.entries[entry]))

                            if entry == 'OriginalFilename':
                                w.ui.tableWidget_2.setItem(0, 4, QtWidgets.QTableWidgetItem(st.entries[entry]))

                            if entry == 'ProductName':
                                w.ui.tableWidget_2.setItem(0, 5, QtWidgets.QTableWidgetItem(st.entries[entry]))

                            if entry == 'ProductVersion':
                                w.ui.tableWidget_2.setItem(0, 6, QtWidgets.QTableWidgetItem(st.entries[entry]))



        
        if self.PE.is_exe():
            petype = 'EXE'
        elif self.PE.is_dll():
            petype = 'DLL'
        elif self.PE.is_driver():
            petype = 'Driver'
        else:
            petype = 'n/a'

        w.ui.tableWidget.setItem(0, 0, QtWidgets.QTableWidgetItem(petype))
        w.ui.tableWidget.setItem(1, 0, QtWidgets.QTableWidgetItem('{:,} bytes'.format(self.dataModel.getDataSize())))

        # add exports
        parent = w.ui.treeWidgetExports
        parent.setColumnWidth(0, 300) 

      
        if hasattr(self.PE, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                rva = self.PE.get_offset_from_rva(self.PE.DIRECTORY_ENTRY_EXPORT.struct.Name)

                # very ygly, i know
                s = ''
                c = 'z'
                k = 0
                while c != '\0' and k < 50:
                    c = chr(self.dataModel.getBYTE(rva))
                    s += c
                    rva += 1
                    k += 1


                child = QtWidgets.QTreeWidgetItem(None)
                child.setText(0, s)

                parent.addTopLevelItem(child)
                parent.expandItem(child)
                
                for i, exp in enumerate(self.PE.DIRECTORY_ENTRY_EXPORT.symbols):

                    child = QtWidgets.QTreeWidgetItem(None)

                    if exp.name:
                        child.setText(0, exp.name)
                        child.setText(1, '0x{0:X}'.format(exp.address))

                        #parent.topLevelItem(i).addChild(child)

                        #parent.topLevelItem(i).addChild(child)
                    
                    parent.topLevelItem(0).addChild(child)

            except Exception as e:
                logger.error(e, exc_info=1)

        # add imports
        parent = w.ui.treeWidgetImports
        parent.setColumnWidth(0, 300) 
        try:
            for i, entry in enumerate(self.PE.DIRECTORY_ENTRY_IMPORT):
                
                child = QtWidgets.QTreeWidgetItem(None)
                child.setText(0, entry.dll.decode('cp437'))
                parent.addTopLevelItem(child)

                for imp in entry.imports:
                    child = QtWidgets.QTreeWidgetItem(None)
                    if imp.name:
                        child.setText(0, imp.name.decode('cp437'))
                        child.setText(1, '0x{0:X}'.format(imp.address-self.PE.OPTIONAL_HEADER.ImageBase))

                        parent.topLevelItem(i).addChild(child)

                    if imp.ordinal:
                        child.setText(0, 'ordinal:{0}'.format(imp.ordinal.decode('cp437')))
                        child.setText(1, '0x{0:X}'.format(imp.address-self.PE.OPTIONAL_HEADER.ImageBase))

                        parent.topLevelItem(i).addChild(child)
        except Exception as e:
            logger.error(e, exc_info=1)

        # populate with sections
        parent = w.ui.treeWidgetSections
        parent.setColumnWidth(0, 100) 
        parent.setColumnWidth(1, 80) 
        parent.setColumnWidth(2, 80) 
        parent.setColumnWidth(3, 80) 
        parent.setColumnWidth(4, 80)        

        for section in self.PE.sections:
            child  = QtWidgets.QTreeWidgetItem(None)
            child.setText(0, section.Name.decode('cp437'))
            child.setText(1, '{0:X}'.format(section.PointerToRawData))
            child.setText(2, '{0:X}'.format(section.SizeOfRawData))
            child.setText(3, '{0:X}'.format(section.VirtualAddress))
            child.setText(4, '{0:X}'.format(section.Misc_VirtualSize))

            child.setForeground(1, QtGui.QColor('green'))
            child.setForeground(2, QtGui.QColor('green'))


            child.setForeground(3, QtGui.QColor(183, 72, 197))
            child.setForeground(4, QtGui.QColor(183, 72, 197))
            
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
            child  = QtWidgets.QTreeWidgetItem(None)
            child.setText(0, d.name.replace('IMAGE_DIRECTORY_ENTRY_', ''))

            if d.VirtualAddress != 0 and d.Size != 0:
                for i, section in enumerate(self.PE.sections):
                    if section.contains_rva(d.VirtualAddress):
                        child.setText(1, '{0} [{1}]'.format(section.Name.decode('cp437').strip('\0'), i))
                        child.setForeground(1, QtGui.QColor('red'))
                        break
                else:
                    child.setText(1, '{0}'.format('<outside>'))


                child.setText(2, '{0:X}'.format(d.VirtualAddress))
                child.setText(3, '{0:X}'.format(d.Size))
                child.setForeground(2, QtGui.QColor('green'))
                child.setForeground(3, QtGui.QColor('green'))
            else:
                child.setForeground(0, QtGui.QColor('lightgray'))

            parent.addTopLevelItem(child)

            for i in range(4)[1:]:
                child.setTextAlignment(i, QtCore.Qt.AlignRight)



        # populate Header
        parent = w.ui.treeWidgetHeader
        parent.setColumnWidth(0, 250) 

        bkbrush = QtGui.QBrush(QtGui.QColor(192, 165, 194))
        bkbrush2 = QtGui.QBrush(QtGui.QColor(232, 194, 229))

        child = QtWidgets.QTreeWidgetItem(None)

        child.setText(0, 'IMAGE_DOS_HEADER')
        child.setBackground(0, bkbrush)

        ch2 = QtWidgets.QTreeWidgetItem(['magic', 'word', '{0:X}'.format(int(self.PE.DOS_HEADER.e_magic))])
        ch2.setForeground(2, QtGui.QColor('green'))
        ch2.setForeground(1, QtGui.QColor(183, 72, 197))
        child.addChild(ch2)

        ch2 = QtWidgets.QTreeWidgetItem(['e_lfanew', 'word', '{0:X}'.format(int(self.PE.DOS_HEADER.e_lfanew))])
        ch2.setForeground(2, QtGui.QColor('green'))
        ch2.setForeground(1, QtGui.QColor(183, 72, 197))
        child.addChild(ch2)

        parent.addTopLevelItem(child)


        item = QtWidgets.QTreeWidgetItem(['IMAGE_NT_HEADERS'])
        item.setBackground(0, bkbrush)

        child = QtWidgets.QTreeWidgetItem(['Signature', 'word',  '{0:X}'.format(int(self.PE.NT_HEADERS.Signature))])
        child.setForeground(2, QtGui.QColor('green'))
        child.setForeground(1, QtGui.QColor(183, 72, 197))

        item.addChild(child)

        subitem = QtWidgets.QTreeWidgetItem(['IMAGE_FILE_HEADER'])
        subitem.setBackground(0, bkbrush2)

        child = QtWidgets.QTreeWidgetItem(['Machine', 'word',  '{0:X}'.format(int(self.PE.FILE_HEADER.Machine))])
        child.setForeground(2, QtGui.QColor('green'))
        child.setForeground(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)

        child = QtWidgets.QTreeWidgetItem(['NumberOfSections', 'word',  '{0:X}'.format(int(self.PE.FILE_HEADER.NumberOfSections))])
        child.setForeground(2, QtGui.QColor('green'))
        child.setForeground(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)

        child = QtWidgets.QTreeWidgetItem(['TimeDateStamp', 'dword',  '{0:X}'.format(int(self.PE.FILE_HEADER.TimeDateStamp))])
        child.setForeground(2, QtGui.QColor('green'))
        child.setForeground(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)

        child = QtWidgets.QTreeWidgetItem(['Characteristics', 'dword',  '{0:X}'.format(int(self.PE.FILE_HEADER.Characteristics))])
        child.setForeground(2, QtGui.QColor('green'))
        child.setForeground(1, QtGui.QColor(183, 72, 197))

        subitem.addChild(child)
        item.addChild(subitem)


        subitem = QtWidgets.QTreeWidgetItem(['IMAGE_OPTIONAL_HEADER'])
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
            child = QtWidgets.QTreeWidgetItem(it)

            child.setForeground(2, QtGui.QColor('green'))
            child.setForeground(1, QtGui.QColor(183, 72, 197))

            subitem.addChild(child)


        child = QtWidgets.QTreeWidgetItem(['IMAGE_DATA_DIRECTORY [16]'])
        child.setBackground(0, bkbrush2)

        for i, d in enumerate(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY):
            subchild = QtWidgets.QTreeWidgetItem(['[{0}] {1}'.format(i, d.name.replace('IMAGE_DIRECTORY_ENTRY_', ''))])
            if d.VirtualAddress == 0 and d.Size == 0:
                subchild.setForeground(0, QtGui.QColor('lightgray'))

            c = QtWidgets.QTreeWidgetItem(['VirtualAddress', 'dword', '{0:X}'.format(int(d.VirtualAddress))])
            c.setForeground(2, QtGui.QColor('green'))
            c.setForeground(1, QtGui.QColor(183, 72, 197))
            subchild.addChild(c)

            c = QtWidgets.QTreeWidgetItem(['Size', 'dword', '{0:X}'.format(int(d.Size))])
            c.setForeground(2, QtGui.QColor('green'))
            c.setForeground(1, QtGui.QColor(183, 72, 197))
            subchild.addChild(c)

            child.addChild(subchild)


        subitem.addChild(child)

        item.addChild(subitem)


        parent.addTopLevelItem(item) # NT_HEADERS


        _item =  QtWidgets.QTreeWidgetItem(['{0}'.format('IMAGE_SECTION_HEADERS []')])
        parent.addTopLevelItem(_item)

        for i, section in enumerate(self.PE.sections):
            item =  QtWidgets.QTreeWidgetItem(['{0} [{1}]'.format('SECTION_HEADER', i)])
            item.setBackground(0, bkbrush)

            Data = [['Name', 'char[8]',  section.Name.decode('cp437')],
                    ['VirtualSize', 'dword',  '{0:X}'.format(int(section.Misc_VirtualSize))],
                    ['VirtualAddress', 'dword',  '{0:X}'.format(int(section.VirtualAddress))],
                    ['SizeOfRawData', 'dword',  '{0:X}'.format(int(section.SizeOfRawData))],
                    ['PointerToRawData', 'dword',  '{0:X}'.format(int(section.PointerToRawData))],
                    ['Characteristics', 'dword',  '{0:X}'.format(int(section.Characteristics))]
            ]

            for data in Data:
                child = QtWidgets.QTreeWidgetItem(data)
                child.setForeground(2, QtGui.QColor('green'))
                child.setForeground(1, QtGui.QColor(183, 72, 197))

                item.addChild(child)

            _item.addChild(item)



        #print self.PE


        """
        

        parent = w.ui.treeWidget


        # add sections

        for section in self.PE.sections:
            child  = QtWidgets.QTreeWidgetItem(None)            
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

    def shortExports(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tableWidget_2.setFocus()
            self.w.ui.tableWidget_2.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(4)
            self.w.ui.treeWidgetExports.setFocus()
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


    def F3(self):
        self.changeAddressMode()

        self._parent.update()

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


    def skip_block(self):

        off = self._viewMode.getCursorAbsolutePosition()

        x = off

        sizeOfData = self.dataModel.getDataSize()
        if x >= sizeOfData:
            return

        import string

        x = self.dataModel.getData().find(b'\x00'*8, off)
        if x == -1:
            x = off


        if x == off:
            if x < sizeOfData - 1:
                x += 1

        self._viewMode.goTo(x)

        return
        # skip bytes of current value

        #k = time.time()

        """
        # slower
        while x < sizeOfData - 8 and self.dataModel.getQWORD(x) != 0:
            b = self.dataModel.getQWORD(x)
            lastb = b & -b

                              
            pos = 0
            if lastb & 0xFFFFFFFF == 0:
                lastb >>= 32
                pos += 4

            if lastb & 0xFFFF == 0:
                lastb >>=  16
                pos += 2

            if lastb & 0xFF == 0:
                lastb >>= 8
                pos += 1

            x += (8 - pos + 1)

        if x == off:
            if x < sizeOfData - 1:
                x += 1

        self._viewMode.goTo(x)
        """

    def jump_overlay(self):
        overlay = self.PE.get_overlay_data_start_offset()
        self._viewMode.goTo(overlay)

    def skip_section_up(self):
        # cursor pozition in datamodel
        off = self._viewMode.getCursorAbsolutePosition()
        x = off
        
        # get section represented by offset
        section = self.PE.get_section_by_offset(off)

        if section is None:
            # if it's not in a section, find it
            while off < self.dataModel.getDataSize() and self.PE.get_section_by_offset(off) is None:
                off += 1

            section = self.PE.get_section_by_offset(off)

            if section:
                # if found, go to begining
                x = section.PointerToRawData
            else:
                if off == self.dataModel.getDataSize():
                    # if eof, go to the end
                    x = self.dataModel.getDataSize() - 1
                else:
                    # don't know what to do
                    return

        else:
            # we found a section, go to the end + 1 (actually it's the next section physically in file)
            x =  section.PointerToRawData + section.SizeOfRawData

        self._viewMode.goTo(x)

    def skip_section_dw(self):
        # cursor pozition in datamodel
        off = self._viewMode.getCursorAbsolutePosition()

        # get section represented by offset
        section = self.PE.get_section_by_offset(off)
        x = off

        if section is None:
            # if it's not in a section, find it
            while off > 0 and self.PE.get_section_by_offset(off) is None:
                off -= 1

            section = self.PE.get_section_by_offset(off)

            if section:
                # if found, go to begining
                x = section.PointerToRawData
            else:
                if off == 0:
                    # if start of file, go to 0
                    x = off

        else:
            # we found a section, go to the preceding one
            if section.PointerToRawData >= 0:
                x =  section.PointerToRawData - 1
                section = self.PE.get_section_by_offset(x)
                if section:
                    x = section.PointerToRawData
                else:
                    x = 0

        self._viewMode.goTo(x)


    def _showGoto(self):
        if not self.dgoto.isVisible():
            self.dgoto.show()
        else:
            self.dgoto.hide()

    def registerShortcuts(self, parent):
        self.w = WHeaders(parent, self)
        self._parent = parent

        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+H"), parent, self.doit, self.doit)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+V"), parent, self.shortVersionInfo, self.shortVersionInfo)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+H"), parent, self.shortHeader, self.shortHeader)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+I"), parent, self.shortImports, self.shortImports)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+E"), parent, self.shortExports, self.shortExports)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+S"), parent, self.shortSections, self.shortSections)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+D"), parent, self.shortDirectories, self.shortDirectories)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("F7"), parent, self.F7, self.F7)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("F3"), parent, self.F3, self.F3)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("s"), parent, self.skip_chars, self.skip_chars)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("e"), parent, self.skip_block, self.skip_block)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("["), parent, self.skip_section_dw, self.skip_section_dw)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("]"), parent, self.skip_section_up, self.skip_section_up)]
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("0"), parent, self.jump_overlay, self.jump_overlay)]

        self.writeData(self.w)

        self.dgoto = PEDialogGoto(parent, self)
        self._Shortcuts += [QtWidgets.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._showGoto, self._showGoto)]


# GoTo dialog (inheritance from FileFormat DialogGoto)
class PEDialogGoto(DialogGoto):
    def initUI(self):
        super(PEDialogGoto, self).initUI()
        self.ui.comboBox.clear()

        # for PE we support RVA/FileAddress/VA
        self.ui.comboBox.addItems(['RVA', 'FileAddress', 'VirtualAddress'])

        # we support some konstants EP/END (end of file)

        self.konstants = {'EP' : self.kEP, 
                          'END': self.kEND}

        self.GoTos = {'FileAddress' : self.fa, 'VirtualAddress' : self.va, 'RVA' : self.rva}
        
    # constants, calculate them in every way (where possible)
    def kEP(self, k):
        gtype = str(self.ui.comboBox.currentText())

        if gtype == 'RVA':
            return int(self.plugin.PE.OPTIONAL_HEADER.AddressOfEntryPoint)

        elif gtype == 'VirtualAddress':
            return int(self.plugin.PE.OPTIONAL_HEADER.AddressOfEntryPoint + self.plugin.PE.OPTIONAL_HEADER.ImageBase)

        elif gtype == 'FileAddress':
            return self.plugin.PE.get_offset_from_rva(self.plugin.PE.OPTIONAL_HEADER.AddressOfEntryPoint)
        else:
            return None

    def kEND(self, k):
        gtype = str(self.ui.comboBox.currentText())

        if gtype == 'FileAddress':
            return self.plugin.dataModel.getDataSize()

        elif gtype == 'VirtualAddress':
            offset = self.plugin.dataModel.getDataSize()
            return self.plugin.PE.get_rva_from_offset(offset) + self.plugin.PE.OPTIONAL_HEADER.ImageBase
        elif gtype == 'RVA':
            offset = self.plugin.dataModel.getDataSize()
            return self.plugin.PE.get_rva_from_offset(offset)
        else:
            return None

    # goto address type fa/va/rva
    def fa(self, result):
        return result

    def rva(self, rva):
        self.PE = self.plugin.PE
        try:
            result = self.PE.get_offset_from_rva(rva)
        except Exception as e:
            return None

        return result

    def va(self, va):
        self.PE = self.plugin.PE
        try:
            result = self.PE.get_offset_from_rva(va - self.PE.OPTIONAL_HEADER.ImageBase)
        except Exception as e:
            return None

        return result


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

class ExportsEventFilter(QtCore.QObject):
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
                    rva = str(rva)
                    # strip 0x
                    rva = int(rva, 0)

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


class WHeaders(QtWidgets.QDialog):
    
    def __init__(self, parent, plugin):
        super(WHeaders, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(WHeaders, self).show

        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt5.uic.loadUi(os.path.join(root, 'plugins', 'format','pe.ui'), baseinstance=self)

        self.ei = ImportsEventFilter(plugin, self.ui.treeWidgetImports)
        self.ui.treeWidgetImports.installEventFilter(self.ei)

        self.ee = ExportsEventFilter(plugin, self.ui.treeWidgetExports)
        self.ui.treeWidgetExports.installEventFilter(self.ee)

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
        self.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)

        shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+F"), self, self.close, self.close)

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

class PEBottomBanner(Banners.BottomBanner):
    def __init__(self, dataModel, viewMode, plugin):
        self.plugin = plugin
        super(PEBottomBanner, self).__init__(dataModel, viewMode)
        self.gray = QtGui.QPen(QtGui.QColor(128, 128, 128), 0, QtCore.Qt.SolidLine)
        self.yellow = self.textPen
        self.purple = QtGui.QPen(QtGui.QColor(172, 129, 255), 0, QtCore.Qt.SolidLine)
        self.editmode = QtGui.QPen(QtGui.QColor(255, 102, 179), 0, QtCore.Qt.SolidLine)
        self.viewmode = QtGui.QPen(QtGui.QColor(0, 153, 51), 0, QtCore.Qt.SolidLine)

    def draw(self):
        qp = QtGui.QPainter()
        qp.begin(self.qpix)

        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)

        cemu = ConsoleEmulator(qp, self.height//self.fontHeight, self.width//self.fontWidth)

        dword = self.dataModel.getDWORD(self.viewMode.getCursorAbsolutePosition(), asString=True)
        if dword is None:
            dword = '----'

        sd = 'DWORD: {0}'.format(dword)

        pos = 'POS: {0:08x}'.format(self.viewMode.getCursorAbsolutePosition())



        qword = self.dataModel.getQWORD(self.viewMode.getCursorAbsolutePosition(), asString=True)
        if qword is None:
            qword = '----'
        sq = 'QWORD: {0}'.format(qword)

        byte = self.dataModel.getBYTE(self.viewMode.getCursorAbsolutePosition(), asString=True)
        if byte is None:
            byte = '-'

        sb = 'BYTE: {0}'.format(byte)

        cemu.writeAt(1,  0, pos)
        if self.viewMode.isInEditMode():
            qp.setPen(self.editmode)
            cemu.writeAt(1, 1, '[edit mode]')
        else:
            qp.setPen(self.viewmode)
            cemu.writeAt(1,  1, '[view mode]')

        qp.setPen(self.yellow)
        cemu.writeAt(17, 0, sd)
        cemu.writeAt(35, 0, sq)
        cemu.writeAt(62, 0, sb)

        qp.drawLine(15 * self.fontWidth + 5, 0, 15 * self.fontWidth + 5, 50)
        qp.drawLine(33 * self.fontWidth + 5, 0, 33 * self.fontWidth + 5, 50)
        qp.drawLine(59 * self.fontWidth + 5, 0, 59 * self.fontWidth + 5, 50)
        qp.drawLine(71 * self.fontWidth + 5, 0, 71 * self.fontWidth + 5, 50)

        sel = None
        hint = self.plugin.hintBanner(self.viewMode.getCursorAbsolutePosition())
        qp.setPen(self.purple)
        cemu.writeAt(73, 1, hint)

        sel = '<no selection>'
        if self.viewMode.selector.getCurrentSelection():
            u, v = self.viewMode.selector.getCurrentSelection()
            if u != v:
                pen = QtGui.QPen(QtGui.QColor(51, 153, 255), 0, QtCore.Qt.SolidLine)
                qp.setPen(pen)

                #cemu.writeAt(73, 0, 'Selection: ')
                sel = 'Selection: {0:x}:{1}'.format(u, v-u)
                cemu.writeAt(73, 0, sel)
        else:
            pen = QtGui.QPen(QtGui.QColor(128, 128, 128), 0, QtCore.Qt.SolidLine)
            qp.setPen(pen)

            sel = '<no selection>'
            cemu.writeAt(73, 0, sel)

        off = 1
        if sel:
            off += len(sel)

        ovr_line_off = (73 + off) * self.fontWidth + 5

        qp.setPen(self.yellow)
        qp.drawLine(ovr_line_off, 0, ovr_line_off, 50)

        start = self.plugin.PE.get_overlay_data_start_offset()

        if start > 0:
            qp.setPen(self.gray)
            overlay = 'overlay: {0:,} bytes'.format(start)

            if sel:
                off = 73 + 3 + len(sel)

            cemu.writeAt(off, 0, 'overlay: {0:,} bytes'.format(self.dataModel.size() - start))
            cemu.writeAt(off, 1, '         {0}%'.format((self.dataModel.size() - start)*100/self.dataModel.size()))
        
        qp.end()


class PEHeaderBanner(Banners.TopBanner):
    def __init__(self, dataModel, viewMode, peplugin):
        self.peplugin = peplugin
        super(PEHeaderBanner, self).__init__(dataModel, viewMode)

    def draw(self):
        qp = QtGui.QPainter()
        qp.begin(self.qpix)

        qp.fillRect(0, 0, self.width,  self.height, self.backgroundBrush)
        qp.setPen(self.textPen)
        qp.setFont(self.font)

        cemu = ConsoleEmulator(qp, self.height/self.fontHeight, self.width/self.fontWidth)

        cemu.writeAt(1, 0, 'Name')

        displayType = self.peplugin.getAddressMode()

        offset = 10
        if displayType == 'FA':
            offset = 13
        if displayType == 'RVA':
            offset = 13
        if displayType == 'VA':
            offset = 13

        cemu.writeAt(offset, 0, displayType)

        offset = 21 # for PE plugin !

        text = ''
        text = self.viewMode.getHeaderInfo()

        cemu.writeAt(offset, 0, text)
        
        qp.end()

class PEBanner(Banners.Banner):
    def __init__(self, dataModel, viewMode, peplugin):
        self.width = 0
        self.height = 0
        self.dataModel = dataModel
        self.viewMode = viewMode
        self.qpix = self._getNewPixmap(self.width, self.height)
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        self.peplugin = peplugin

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
        return self.fontWidth*20# 160

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
                s = section.Name.replace(b'\0', b' ').decode('cp437')

            displayType = self.peplugin.getAddressMode()
            if displayType == 'FA':
                sOff = ' {0:08x}'.format(offset)
            elif displayType == 'RVA':
                sOff = ' {0:08x}'.format(self.PE.get_rva_from_offset(offset))
            else:
                rva = self.PE.get_rva_from_offset(offset)
                if rva is not None:
                    sOff = '{0:08x}'.format(self.PE.get_rva_from_offset(offset) + self.PE.OPTIONAL_HEADER.ImageBase)
                    if len(sOff) == 8:
                        sOff = ' ' + sOff
                else:
                    # overlay for eg.
                    sOff = '  overlay'

            sDisplay = '{0} {1}'.format(s, sOff)
            qp.drawText(0+5, (i+1) * self.fontHeight, sDisplay)
            offset += columns
        

        qp.end()

    def resize(self, width, height):
        self.width = width
        self.height = height

        self.qpix = self._getNewPixmap(self.width, self.height)
