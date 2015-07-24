from UnpackPlugin import *
from TextDecorators import *
from PyQt4 import QtGui, QtCore
import PyQt4
import sys, os


class rc4(UnpackPlugin):
    priority = 0

    def init(self, dataModel, viewMode):
        super(rc4, self).init(dataModel, viewMode)

        self.ui = PyQt4.uic.loadUi(os.path.join('.', 'plugins', 'unpack', 'rc4.ui'))
        return True

    def getUI(self):
        return self.ui

    # based on Thimo Kraemer <thimo.kraemer@joonis.de> code
    def rc4decrypt(self, data, key):
		x = 0
		box = range(256)
		for i in range(256):
			x = (x + box[i] + ord(key[i % len(key)])) % 256
			box[i], box[x] = box[x], box[i]
		x = 0
		y = 0
		out = []
		for char in data:
			x = (x + 1) % 256
			y = (y + box[x]) % 256
			box[x], box[y] = box[y], box[x]
			out.append(chr(char ^ box[(box[x] + box[y]) % 256]))

		return ''.join(out)

    def proceed(self):
    	key = str(self.ui.key.text())

        if self.viewMode.selector.getCurrentSelection():
            u, v = self.viewMode.selector.getCurrentSelection()

            encrypted = self.rc4decrypt(self.dataModel.getStream(u, v), key)
            self.dataModel.getData()[u:v] = encrypted
        return True
