from UnpackPlugin import *
from PyQt4.QtGui import *

from PyQt4 import QtGui, QtCore
import PyQt4
import sys, os


class MyValidator(QValidator):
    def __init__(self, parent=None):
        super(MyValidator, self).__init__(parent)

    def validate(self, c, pos):
        c = str(c)
        k = pos - 1

        def _validate(s, k):
            color = '#ffffff'
            YELLOW = '#fff79a'

            # accept empty string
            if s == '':
                return (QValidator.Acceptable, color)

            # must be hex digits, or 'x' on second position
            if s[k] not in ' 0123456789abcdefABCDEFx':
                return (QValidator.Invalid, color)
            else:
                if s[k] == 'x' and k != 1:
                    return (QValidator.Invalid, color)  

            # if we have spaces, must be of form XX XX XX XX
            if ' ' in s:
                L = s.split(' ')
                for l in L:
                    if len(l) != 2:
                        return (QValidator.Acceptable, YELLOW)

                return (QValidator.Acceptable, color)                        

            # else, try at least to convert it to a number
            try:
                x = int(s, 0)
            except ValueError:
                return (QValidator.Acceptable, YELLOW)


            return (QValidator.Acceptable, color)

        state, color = _validate(c, k)
        if state == QValidator.Acceptable:
            self.parent().setStyleSheet('QLineEdit {{ background-color: {} }}'.format(color))

        return (state, k + 1)


class basic(UnpackPlugin):
    priority = 0

    def init(self, dataModel, viewMode):
        super(basic, self).init(dataModel, viewMode)

        self.ui = PyQt4.uic.loadUi(os.path.join('.', 'plugins', 'unpack', 'basic.ui'))

        self.ui.key.textChanged.connect(self._keychanged)
        self.ui.key.setValidator(MyValidator(self.ui.key))
        self.ui.delta.setValidator(MyValidator(self.ui.delta))

        return True


    def _convert(self, s):
        try:
            x = int(s, 0)
        except ValueError:
            x = None

        if not x:
            x = 0
            L = s.split(' ')
            for i, l in enumerate(L):
                if len(l) != 2:
                    return 0
                else:
                    try:
                        z = int('0x' + l, 0)
                    except ValueError:
                        return 0

                    z = z << 8*i
                    x = x | z


        return x

    def _keychanged(self, key):
        key = str(key)
        if key:
            key = self._convert(key)
        else:
            key = 0

        keysize = (key.bit_length() + (8 - key.bit_length()%8)%8)/8
        self.ui.bytes.setText(str(keysize))

    def _rol(self, b, key, size):
        size = size * 8
        key = key % size
        mask = (1 << size) - 1
        return (b << key | b >> (size - key)) & mask
        

    def _ror(self, b, key, size):
        size = size * 8
        key = key % size
        mask = (1 << size) - 1
        return (b >> key | b << (size - key)) & mask

    def _add(self, b, key, size):
        size = size * 8
        mask = (1 << size) - 1
        return (b + key) & mask

    def _sub(self, b, key, size):
        size = size * 8
        mask = (1 << size) - 1
        return (b - key) & mask

    def _xor(self, b, key, size):
        size = size * 8
        mask = (1 << size) - 1
        return (b ^ key) & mask

    def proceed(self):
        if self.viewMode.selector.getCurrentSelection():
            u, v = self.viewMode.selector.getCurrentSelection()

            # prepare values vrom text boxes            
            op = str(self.ui.op.currentText())
            key = str(self.ui.key.text())
            if key:
                key = self._convert(str(self.ui.key.text()))
            else:
                key = 0

            keyop = str(self.ui.keyop.currentText())

            delta = str(self.ui.delta.text())
            if delta:
                delta = self._convert(str(self.ui.delta.text()))
            else:
                delta = 0

            size = str(self.ui.bytes.text())
            if size:
                size = int(size)
            else:
                size = 0

            if size < 1:
                return

            skip = str(self.ui.skip.text())
            if skip:
                skip = int(skip, 0)
            else:
                skip = 0

            OP = {}
            
            OP['ROL'] = self._rol
            OP['ROR'] = self._ror
            OP['ADD'] = self._add
            OP['SUB'] = self._sub
            OP['XOR'] = self._xor

            i = 0
            while i < v-u:
                
                offset = u+i

                b = 0
                j = 0

                # ugly
                while j < size:
                    B = self.dataModel.getBYTE(offset + j)
                    if B:
                        b = b | (B << (8*j))
                    j += 1

                b = OP[op](b, key, size)

                if keyop != '---':
                    # compute key size in bytes
                    keysize = (key.bit_length() + (8 - key.bit_length()%8))/8

                    key = OP[keyop](key, delta, keysize)

                j = 0
                # ugly again
                while j < size:
                    c = b & 0xFF
                    #self.dataModel.setData_b(offset + size - 1 - j, chr(c))
                    self.dataModel.setData_b(offset +  j, chr(c))
                    b = b >> 8
                    j += 1

                i += (size + skip)


    def getUI(self):
        return self.ui
