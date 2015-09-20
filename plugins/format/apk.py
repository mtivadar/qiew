import sys, os
from FileFormat import *
import Banners
from TextDecorators import *
import TextSelection

import DataModel

import PyQt4
from PyQt4 import QtGui, QtCore
from cemu import *
import time

import androguard
from androguard.core import bytecode
from androguard.core.bytecodes import apk
from androguard.core import androconf

class APK(FileFormat):
    name = 'apk'
    priority = 5

    def recognize(self, dataModel):
        self.dataModel = dataModel

        try:
            ret_type = androconf.is_android(self.dataModel.source)
            self.apk = apk.APK(self.dataModel.source)
            if ret_type == "APK":
                return True
        except:
            return False
        
        return False


    def changeAddressMode(self):
        self.DisplayTypes = self.DisplayTypes[1:] + [self.DisplayTypes[0]]

    def init(self, viewMode, parent):
        self._viewMode = viewMode
        self._parent = parent

        self.textDecorator = TextDecorator(viewMode)
        self.textDecorator = HighlightASCII(self.textDecorator)
        self.textDecorator = HighlightPrefix(self.textDecorator, 'PK', brush=FileFormat.redbrush, pen=self.yellowpen)
        self.textDecorator = HighlightWideChar(self.textDecorator)
        self._viewMode.setTransformationEngine(self.textDecorator)

        # plugin window
        self.w = WHeaders(parent, self)
        self.g = DialogGoto(parent, self)
        self.publishAPKInfo()
        return
        

    def getBanners(self):
        self.banners = [Banners.TopBanner(self.dataModel, self._viewMode), Banners.FileAddrBanner(self.dataModel, self._viewMode),
                        APKBottomBanner(self.dataModel, self._viewMode, self.apk)]
        return self.banners
   

    def _add_ep_entity(self, text, acts):
        top = self.w.ui.ep
        child  = QtGui.QTreeWidgetItem(None)
        child.setText(0, text)
        top.setColumnWidth(0, 100)

        top.addTopLevelItem(child)
        for act in acts:
            child1  = QtGui.QTreeWidgetItem(None)
            child1.setText(0, act)
            child1.setTextColor(0, QtGui.QColor('purple'))
            child.addChild(child1)

        top.expandItem(child)


    def publishAPKInfo(self):
        self.w.ui.listPerm.addItems([x.replace('android.permission.', '') for x in self.apk.get_permissions()])

        self._add_ep_entity("Activities", self.apk.get_activities())
        self._add_ep_entity("Services", self.apk.get_services())
        self._add_ep_entity("Receivers", self.apk.get_receivers())
        self._add_ep_entity("Providers", self.apk.get_providers())



        top = self.w.ui.files
        child  = QtGui.QTreeWidgetItem(None)
        child.setText(0, 'Files')
        top.setColumnWidth(0, 100)

        top.addTopLevelItem(child)
        for f in self.apk.get_files():
            child1  = QtGui.QTreeWidgetItem(None)
            child1.setText(0, f)
            child1.setTextColor(0, QtGui.QColor('purple'))
            child.addChild(child1)

        top.expandItem(child)


        return

    def _showGoto(self):
        if not self.dgoto.isVisible():
            self.dgoto.show()
        else:
            self.dgoto.hide()

    def showPermissions(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tabWidget.setFocus()
            self.w.ui.tabWidget.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(0)
            self.w.ui.listPerm.setFocus()

            #q = self._parent.parent.factory(DataModel.BufferDataModel(self.apk.get_dex(), 'classes.dex'), 'classes.dex')
            source = DataModel.BufferDataModel(self.apk.get_dex(), 'classes.dex')
            q = self._parent.parent.factory()(source, 'classes.dex')
            #self._parent.parent.hbox.addWidget(q)
            q.setParent(self._parent.parent, QtCore.Qt.Dialog | QtCore.Qt.WindowMinimizeButtonHint )
            q.resize(900, 600)
            q.show()



    def showEntrypoints(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tabWidget.setFocus()
            self.w.ui.tabWidget.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(1)
            self.w.ui.ep.setFocus()

    def showFiles(self):
        if not self.w.isVisible():
            self.w.show()
            self.w.ui.tabWidget.setFocus()
            self.w.ui.tabWidget.activateWindow()
            self.w.ui.tabWidget.setCurrentIndex(2)
            self.w.ui.files.setFocus()


    def _g_showit(self):
        if not self.g.isVisible():
            self.g.show()
        else:
            self.g.hide()

    def registerShortcuts(self, parent):
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("Alt+P"), parent, self.showPermissions, self.showPermissions)]
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("Alt+E"), parent, self.showEntrypoints, self.showEntrypoints)]
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("Alt+F"), parent, self.showFiles, self.showFiles)]
        self._Shortcuts += [QtGui.QShortcut(QtGui.QKeySequence("Alt+G"), parent, self._g_showit, self._g_showit)]
        
        return

class WHeaders(QtGui.QDialog):
    
    def __init__(self, parent, plugin):
        super(WHeaders, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(WHeaders, self).show

        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt4.uic.loadUi(os.path.join(root, 'plugins', 'format','apk.ui'), baseinstance=self)
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

        self.setWindowTitle('APK plugin')
        self.setSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)

        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+F"), self, self.close, self.close)


class APKBottomBanner(Banners.BottomBanner):
    def __init__(self, dataModel, viewMode, plugin):
        self.plugin = plugin
        super(APKBottomBanner, self).__init__(dataModel, viewMode)
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

        cemu = ConsoleEmulator(qp, self.height/self.fontHeight, self.width/self.fontWidth)

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

        sb = ' BYTE: {0}'.format(byte)

        cemu.writeAt(1,  0, pos)
        if self.viewMode.isInEditMode():
            qp.setPen(self.editmode)
            cemu.writeAt(1, 1, '[edit mode]')
        else:
            qp.setPen(self.viewmode)
            cemu.writeAt(1,  1, '[view mode]')

        qp.setPen(self.yellow)
        cemu.writeAt(17, 1, sd)
        cemu.writeAt(35, 0, sq)
        cemu.writeAt(17, 0, sb)

        qp.drawLine(15 * self.fontWidth + 5, 0, 15 * self.fontWidth + 5, 50)
        qp.drawLine(33 * self.fontWidth + 5, 0, 33 * self.fontWidth + 5, 50)
        qp.drawLine(59 * self.fontWidth + 5, 0, 59 * self.fontWidth + 5, 50)
        #qp.drawLine(71 * self.fontWidth + 5, 0, 71 * self.fontWidth + 5, 50)

        sel = None
        hint = self.plugin.get_package()
        qp.setPen(self.purple)
        
        # threshold for pkgname
        th = 20
        if len(hint) > th:
            hint = hint[:th-2] + '..'
        cemu.writeAt(61, 0, hint)
        version = 'vc: {0}, vn: {1}'.format(self.plugin.get_androidversion_code(), self.plugin.get_androidversion_name())

        if len(version) > th:
            version = version[:th-2] + '..'

        cemu.writeAt(61, 1, version)

        sel = '<no selection>'
        if self.viewMode.selector.getCurrentSelection():
            u, v = self.viewMode.selector.getCurrentSelection()
            if u != v:
                pen = QtGui.QPen(QtGui.QColor(51, 153, 255), 0, QtCore.Qt.SolidLine)
                qp.setPen(pen)

                #cemu.writeAt(73, 0, 'Selection: ')
                sel = 'Selection: {0:x}:{1}'.format(u, v-u)
                cemu.writeAt(35, 1, sel)
        else:
            pen = QtGui.QPen(QtGui.QColor(128, 128, 128), 0, QtCore.Qt.SolidLine)
            qp.setPen(pen)

            sel = '<no selection>'
            cemu.writeAt(35, 1, sel)

        off = 1
        if sel:
            off += len(sel)

        #ovr_line_off = (73 + off) * self.fontWidth + 5

        qp.setPen(self.yellow)
        #qp.drawLine(ovr_line_off, 0, ovr_line_off, 50)
        
        qp.end()

