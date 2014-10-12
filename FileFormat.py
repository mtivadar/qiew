from yapsy.IPlugin import IPlugin
import distorm3 # for interface, should be moved


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
