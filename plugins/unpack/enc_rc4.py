import UnpackPlugin
from TextDecorators import *
from PyQt5 import QtGui, QtCore, QtWidgets
import PyQt5
import sys, os


class rc4(UnpackPlugin.DecryptPlugin):
    priority = 0

    def init(self, dataModel, viewMode):
        super(rc4, self).init(dataModel, viewMode)
        #root = os.path.dirname(sys.argv[0])
        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt5.uic.loadUi(os.path.join(root, 'plugins', 'unpack', 'rc4.ui'))

        self.ui.op.activated[str].connect(self._itemchanged)
        return True

    def getUI(self):
        return self.ui

    def _itemchanged(self, text):
        text = str(text)

        if text == 'Hex':
            # hex validator
            self.ui.key.setText('')
            self.ui.key.setValidator(UnpackPlugin.MyValidator(self.ui.key))
        else:
            # no validator for string
            self.ui.key.setText('')
            self.ui.key.setValidator(None)

    # based on Thimo Kraemer <thimo.kraemer@joonis.de> code
    # modified to use bytearray()
    def rc4decrypt(self, data, key):
        x = 0
        box = list(range(256))
        for i in range(256):
            x = (x + box[i] + ord(key[i % len(key)])) % 256
            box[i], box[x] = box[x], box[i]
        x = 0
        y = 0
        out = bytearray()
        for char in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            out.append(char ^ box[(box[x] + box[y]) % 256])

        return out

    def proceed(self):
        op = self.ui.op.currentText()
        op = str(op)

        key = str(self.ui.key.text())

        if key == '':
            return False

        if op == 'Hex':
            key = UnpackPlugin._convert(key)

            keysize = (key.bit_length() + (8 - key.bit_length()%8)%8)//8
            i = 0

            out = ''
            if keysize == 0:
                out += '\x00'

            # ugly, but it's ok, string is small
            while i < keysize:
                out += chr(key & 0xFF)
                key = key >> 8
                i += 1

            key = out


        if self.viewMode.selector.getCurrentSelection():
            u, v = self.viewMode.selector.getCurrentSelection()

            encrypted = self.rc4decrypt(self.dataModel.getStream(u, v), key)
            self.dataModel.setData_s(u, v, encrypted)

        return True
