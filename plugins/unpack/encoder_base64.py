import UnpackPlugin
from TextDecorators import *
from PyQt4 import QtGui, QtCore
import PyQt4
import sys, os

import base64

class EncoderBase64(UnpackPlugin.DecryptPlugin):
    priority = 0

    def init(self, dataModel, viewMode):
        super(EncoderBase64, self).init(dataModel, viewMode)
        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt4.uic.loadUi(os.path.join(root, 'plugins', 'unpack', 'encoder_base64.ui'))

        self.ui.op.activated[QtCore.QString].connect(self._itemchanged)
        return True

    def getUI(self):
        return self.ui

    def _itemchanged(self, text):
        pass

    def proceed(self):

        if self.viewMode.selector.getCurrentSelection():
            op = self.ui.op.currentText()

            u, v = self.viewMode.selector.getCurrentSelection()

            stream = self.dataModel.getStream(u, v)

            encoded = ''

            if op == 'decode':
                try:
                    encoded = base64.b64decode(stream)
                except TypeError:
                    reply = QtGui.QMessageBox.warning(self.viewMode.widget, 'Qiew', "Error decoding...", QtGui.QMessageBox.Ok)
                    return False

            elif op == 'encode':
                try:
                    encoded = base64.b64encode(stream)
                except TypeError:
                    reply = QtGui.QMessageBox.warning(self.viewMode.widget, 'Qiew', "Error encoding...", QtGui.QMessageBox.Ok)
                    return False

            name = self.dataModel.source
            open(name + '.base64', 'w').write(encoded)
            reply = QtGui.QMessageBox.information(self.viewMode.widget, 'Qiew', "Done.", QtGui.QMessageBox.Ok)

        return True
