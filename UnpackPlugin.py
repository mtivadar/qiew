from yapsy.IPlugin import IPlugin
from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import *
import PyQt4
import os, sys

class DecryptPlugin(IPlugin):
    ui = None

    def init(self, dataModel, viewMode):
        self.dataModel = dataModel
        self.viewMode = viewMode

        return True

    def getUI(self):
        return self.ui

    def proceed(self):
        return True

def _convert(s):
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
