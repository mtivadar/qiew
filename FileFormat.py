from yapsy.IPlugin import IPlugin

class FileFormat(IPlugin):
    name = ''

    def isRecognized(self):
        return False

    def init(self, viewMode):
        pass

    def registerShortcuts(self, parent):
        pass

    # tells disasm view what to decode
    def hintDisasm(self):
        return None

    # calculates va for disasm mode
    def hintDisasmVA(self):
        return None

    # returns ascii string in disasm view (from a va)
    def stringFromVA(self, va):
        return ''
