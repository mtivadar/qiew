from FileFormat import *
import Banners
import pefile
from TextDecorators import *
from PyQt4 import QtGui, QtCore
from cemu import *

class Binary(FileFormat):
#    def __init__(self):
#        print 'hello'
    name = 'binary'
    priority = 0
    def recognize(self, dataModel):
        return True
        print 'world'
        self.dataModel = dataModel

        try:
            self.PE = pefile.PE(data=dataModel.getData())
        except:
            return False
        

        return False

    def hintDisasm(self):
        return distorm3.Decode32Bits

    def hintDisasmVA(self, offset):
        return offset

    def getBanners(self):
        return [Banners.FileAddrBanner]
   
    def init(self, viewMode):
        self.viewMode = viewMode
