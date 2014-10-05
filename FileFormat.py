from yapsy.IPlugin import IPlugin

class FileFormat(IPlugin):
    name = ''

    def isRecognized(self):
        return False

    def init(self, viewMode):
        pass

    def registerShortcuts(self, parent):
        pass
