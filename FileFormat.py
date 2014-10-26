from yapsy.IPlugin import IPlugin
import distorm3 # for interface, should be moved
from PyQt4 import QtGui, QtCore
import PyQt4
import os, sys


class IDisasm():

    # tells disasm view what to decode
    def hintDisasm(self):
        return None

    # calculates va for disasm mode
    def hintDisasmVA(self):
        return None

    # returns ascii string in disasm view (from a va)
    def stringFromVA(self, va):
        return ''

    def disasmVAtoFA(self, va):
        return None

    def disasmSymbol(self, va):
        return None


class FileFormat(IPlugin, IDisasm):
    name = ''

    def isRecognized(self):
        return False

    def init(self, viewMode):
        pass

    def registerShortcuts(self, parent):
        pass

   

class DialogGoto(QtGui.QDialog):
    
    def __init__(self, parent, plugin):
        super(DialogGoto, self).__init__(parent)
        
        self.parent = parent
        self.plugin = plugin
        self.oshow = super(DialogGoto, self).show

        root = os.path.dirname(sys.argv[0])
        self.ui = PyQt4.uic.loadUi(os.path.join(root, 'plugins', 'format', 'goto.ui'), baseinstance=self)

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

        self.setSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)

        shortcut = QtGui.QShortcut(QtGui.QKeySequence("Alt+G"), self, self.close, self.close)

        self.ui.setWindowTitle('GoTo')

        QtCore.QObject.connect(self.ui.lineEdit, QtCore.SIGNAL('returnPressed()'), self.onReturnPressed)


    def onReturnPressed(self):

        expr = str(self.ui.lineEdit.text())


        import ast
        import operator as op
        # supported operators
        operators = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
                     ast.Div: op.div, ast.Pow: op.pow, ast.USub: op.neg}

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
                k = str(node.id)
                if k in self.konstants:
                    return self.konstants[k](k)
                else:
                    raise TypeError(node)
            else:
                raise TypeError(node)

        try:
            result = eval_expr(expr)
        except Exception, e:
            self.ui.label.setText('error.')
            return
        

        self.ui.label.setText('{0} ({1})'.format(hex(result), result))

        self.onResult(result)

    def onResult(self, result):
        gotoType = str(self.ui.comboBox.currentText())

        result = self.GoTos[gotoType](result)

        if result:
            self.plugin.viewMode.goTo(result)
        
    def fa(self, offset):
        return offset
