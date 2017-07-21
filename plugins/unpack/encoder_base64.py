import UnpackPlugin
from TextDecorators import *
from PyQt5 import QtGui, QtCore, QtWidgets
import PyQt5
import sys, os

import base64

class EncoderBase64(UnpackPlugin.DecryptPlugin):
    priority = 0

    def init(self, dataModel, viewMode):
        super(EncoderBase64, self).init(dataModel, viewMode)
        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt5.uic.loadUi(os.path.join(root, 'plugins', 'unpack', 'encoder_base64.ui'))

        self.ui.op.activated[str].connect(self._itemchanged)
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
                    reply = QtWidgets.QMessageBox.warning(self.viewMode.widget, 'Qiew', "Error decoding...", QtWidgets.QMessageBox.Ok)
                    return False

            elif op == 'encode':
                try:
                    encoded = base64.b64encode(stream)
                except TypeError:
                    reply = QtWidgets.QMessageBox.warning(self.viewMode.widget, 'Qiew', "Error encoding...", QtWidgets.QMessageBox.Ok)
                    return False

            name = self.dataModel.source
            open(name + '.base64', 'w').write(encoded)
            reply = QtWidgets.QMessageBox.information(self.viewMode.widget, 'Qiew', "Done.", QtWidgets.QMessageBox.Ok)

        return True
