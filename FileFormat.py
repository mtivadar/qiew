from yapsy.IPlugin import IPlugin
from PyQt5 import QtGui, QtCore, QtWidgets
import PyQt5
import os, sys

#import DisasmViewMode

class Observer:
    def changeViewMode(self, viewMode):
        self._viewMode = viewMode
        self.viewMode = viewMode
        #NotImplementedError('method not implemented.')

class IDisasm():

    # tells disasm view what to decode
    def hintDisasm(self):
        return None, None
        #return DisasmViewMode.Disasm_x86_32bit

    # calculates va for disasm mode
    def hintDisasmVA(self, offset):
        return offset

    # returns ascii string in disasm view (from a va)
    def stringFromVA(self, va):
        return ''

    def disasmVAtoFA(self, va):
        return None

    def disasmSymbol(self, va):
        return None


class FileFormat(IPlugin, IDisasm, Observer):
    name = ''
    _Shortcuts = []
    redbrush = QtGui.QBrush(QtGui.QColor(128, 0, 0))
    yellowpen = QtGui.QPen(QtGui.QColor(255, 255, 0))

    def isRecognized(self):
        return False

    def init(self, viewMode, parent):
        pass

    def getShortcuts(self):
        return self._Shortcuts

    def registerShortcuts(self, parent):
        pass

   

class DialogGoto(QtWidgets.QDialog):
    
    def __init__(self, parent, plugin):
        super(DialogGoto, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(DialogGoto, self).show

        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt5.uic.loadUi(os.path.join(root, 'plugins', 'format', 'goto.ui'), baseinstance=self)

        self.konstants = {}
        self.GoTos = {'FileAddress' : self.fa}

        self.initUI()

    def show(self):

        # TODO: remember position? resize plugin windows when parent resize?
        pwidth = self.parent.parent.size().width()
        pheight = self.parent.parent.size().height()

        width = self.ui.size().width()
        height = self.ui.size().height()

        self.setGeometry(pwidth - width - 15, pheight - height, width, height)
        self.setFixedSize(width, height)

        self.ui.lineEdit.setFocus()
        self.oshow()

    def initUI(self):      

        self.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)

        shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+G"), self, self.close, self.close)

        self.ui.setWindowTitle('GoTo')

        self.ui.lineEdit.returnPressed.connect(lambda: self.onReturnPressed())

    def onReturnPressed(self):

        expr = str(self.ui.lineEdit.text())


        import ast
        import operator as op
        # supported operators
        operators = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
                     ast.Div: op.floordiv, ast.Pow: op.pow, ast.USub: op.neg}

        def eval_expr(expr):
            return eval_(ast.parse(expr, mode='eval').body)

        def eval_(node):
            if isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return operators[type(node.op)](eval_(node.left), eval_(node.right))
            elif isinstance(node, ast.UnaryOp):
                return operators[type(node.op)](eval_(node.operand))
            elif isinstance(node, object):
                # handle constants
                k = str(node.id).upper()
                if k in self.konstants:
                    return self.konstants[k](k)
                else:
                    raise TypeError(node)
            else:
                raise TypeError(node)

        try:
            result = eval_expr(expr)
        except Exception as e:
            self.ui.label.setText('error.')
            return
        

        self.ui.label.setText('{0} ({1})'.format(hex(result), result))

        self.onResult(result)

    def onResult(self, result):
        gotoType = str(self.ui.comboBox.currentText())

        result = self.GoTos[gotoType](result)

        if result is not None:
            self.plugin.viewMode.goTo(result)
        
    def fa(self, offset):
        return offset
