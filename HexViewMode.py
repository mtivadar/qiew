from ViewMode import *
from cemu import *
import TextSelection
import string
from PyQt4 import QtGui, QtCore

class HexViewMode(ViewMode):
    def __init__(self, width, height, data, cursor, widget=None):
        super(ViewMode, self).__init__()

        self.dataModel = data
        self.width = width
        self.height = height

        self.refresh = True
        self.selector = TextSelection.HexSelection(self)
        self.widget = widget

        self.addHandler(self.dataModel)

        # background brush
        self.backgroundBrush = QtGui.QBrush(QtGui.QColor(0, 0, 128))

        # text font
        self.font = QtGui.QFont('Terminus', 11, QtGui.QFont.Light)

        # font metrics. assume font is monospaced
        self.font.setKerning(False)
        self.font.setFixedPitch(True)
        fm = QtGui.QFontMetrics(self.font)
        self._fontWidth  = fm.width('a')
        self._fontHeight = fm.height()

        self.Special = string.ascii_letters + string.digits + ' .;\':;=\"?-!()/\\_'

        self.textPen = QtGui.QPen(QtGui.QColor(192, 192, 192), 1, QtCore.Qt.SolidLine)

        self.cursor = cursor

        self.HexColumns = [1, 4, 8, 16, 32, 36, 40]
        self.idxHexColumns = 3 # 32 columns

        self.newPix = None
        self.Ops = []
        self.gap = 5

        self.resize(width, height)


    @property
    def fontWidth(self):
        return self._fontWidth

    @property
    def fontHeight(self):
        return self._fontHeight


    def setTransformationEngine(self, engine):
        self.transformationEngine = engine

    def _getNewPixmap(self, width, height):
        return QtGui.QPixmap(width, height)

    def getPixmap(self):
        #return self.qpix

        for t in self.Ops:
            if len(t) == 1:
                t[0]()

            else:
                t[0](*t[1:])

        self.Ops = []
        
        if not self.newPix:
            self.draw()

        return self.newPix        

    def getGeometry(self):
        return self.COLUMNS, self.ROWS

    def getColumnsbyRow(self, row):
        return self.COLUMNS

    def getDataModel(self):
        return self.dataModel

    def startSelection(self):
        self.selector.startSelection()

    def stopSelection(self):
        self.selector.stopSelection()

    def getPageOffset(self):
        return self.dataModel.getOffset()

    def getCursorAbsolutePosition(self):
        x, y = self.cursor.getPosition()
        return self.dataModel.getOffset() + y*self.COLUMNS + x

    def computeTextArea(self):
        self.COLUMNS = self.HexColumns[self.idxHexColumns]
        self.CON_COLUMNS = self.width/self.fontWidth
        self.ROWS = self.height/self.fontHeight
        self.notify(self.ROWS, self.COLUMNS)

    def resize(self, width, height):
        self.width = width - width%self.fontWidth
        self.height = height - height%self.fontHeight
        self.computeTextArea()
        self.qpix = self._getNewPixmap(self.width, self.height + self.SPACER)
        self.refresh = True

    def changeHexColumns(self):
        if self.idxHexColumns == len(self.HexColumns) - 1:
            self.idxHexColumns = 0
        else:
            self.idxHexColumns += 1

        # if screen is ont big enough, retry
        if self.HexColumns[self.idxHexColumns]*(3+1) + self.gap >= self.CON_COLUMNS:
            self.changeHexColumns()
            return

        self.resize(self.width, self.height)


    def scroll(self, dx, dy):
        if dx != 0:
            if self.dataModel.inLimits((self.dataModel.getOffset() - dx)):
                self.dataModel.slide(-dx)
                self.scroll_h(dx)

        if dy != 0:
            if self.dataModel.inLimits((self.dataModel.getOffset() - dy*self.COLUMNS)):
                self.dataModel.slide(-dy*self.COLUMNS)
                self.scroll_v(dy)
            else:
                if dy <= 0:
                    pass
                    #self.dataModel.slideToLastPage()
                else:
                    self.dataModel.slideToFirstPage()
                self.draw(refresh=True)

        self.draw()

    def scrollPages(self, number):
        self.scroll(0, -number*self.ROWS)

    def drawAdditionals(self):
        self.newPix = self._getNewPixmap(self.width, self.height + self.SPACER)
        qp = QtGui.QPainter()
        qp.begin(self.newPix)
        qp.drawPixmap(0, 0, self.qpix)

        #self.transformationEngine.decorateText()

        # highlight selected text
        self.selector.highlightText()       

        # draw other selections
        self.selector.drawSelections(qp)

        # draw our cursor
        self.drawCursor(qp)

        # draw dword lines
        for i in range(self.COLUMNS/4)[1:]:
            xw = i*4*3*self.fontWidth - 4
            qp.setPen(QtGui.QColor(0, 255, 0))
            qp.drawLine(xw, 0, xw, self.ROWS*self.fontHeight)


        qp.end()


    def scroll_h(self, dx):
        gap = self.gap

        # hex part
        self.qpix.scroll(dx*3*self.fontWidth, 0, QtCore.QRect(0, 0, self.COLUMNS*3*self.fontWidth, self.ROWS*self.fontHeight + self.SPACER))
        # text part
        self.qpix.scroll(dx*self.fontWidth, 0, QtCore.QRect((self.COLUMNS*3 + gap)*self.fontWidth , 0, self.COLUMNS*self.fontWidth, self.ROWS*self.fontHeight + self.SPACER))

        qp = QtGui.QPainter()
        
        qp.begin(self.qpix)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dx)

        # There are some trails from the characters, when scrolling. trail == number of pixel to erase near the character
        trail = 5

        textBegining = self.COLUMNS*3 + gap
        if dx < 0:
            # hex
            qp.fillRect((self.COLUMNS - 1*factor)*3*self.fontWidth, 0, factor * self.fontWidth * 3, self.ROWS*self.fontHeight + self.SPACER, self.backgroundBrush)
            # text
            qp.fillRect((textBegining + self.COLUMNS - 1*factor)*self.fontWidth, 0, factor * self.fontWidth+trail, self.ROWS*self.fontHeight + self.SPACER, self.backgroundBrush)
        if dx > 0:
            # hex
            qp.fillRect(0, 0, factor * 3 * self.fontWidth, self.ROWS*self.fontHeight + self.SPACER, self.backgroundBrush)
            # text
            qp.fillRect(textBegining*self.fontWidth - trail, 0, factor * self.fontWidth + trail, self.ROWS*self.fontHeight + self.SPACER, self.backgroundBrush)

        cemu = ConsoleEmulator(qp, self.ROWS, self.CON_COLUMNS)

        page = self.transformationEngine.decorate()
        # scriem pe fiecare coloana in parte
        for column in range(factor):
            # fiecare caracter de pe coloana
            for i in range(self.ROWS):

                if dx < 0:
                    # cu (column) selectam coloana
                    idx = (i+1)*(self.COLUMNS) - (column + 1)
                if dx > 0:
                    idx = (i)*(self.COLUMNS) + (column)

                if len(self.getDisplayablePage()) > idx:                
                    qp.setPen(self.transformationEngine.choosePen(idx))
                else:
                    break

                if self.transformationEngine.chooseBrush(idx) != None:
                    qp.setBackgroundMode(1)
                    qp.setBackground(self.transformationEngine.chooseBrush(idx))

                c = self.getDisplayablePage()[idx]

                hex_s = str(hex(c)[2:]).zfill(2) + ' '

                if dx < 0:
                    cemu.writeAt((self.COLUMNS - (column + 1))*3, i, hex_s, noBackgroudOnSpaces=True)
                    cemu.writeAt(textBegining + self.COLUMNS - (column + 1), i, self.cp437(c))

                if dx > 0:
                    cemu.writeAt((column)*3, i, hex_s, noBackgroudOnSpaces=True)
                    cemu.writeAt(textBegining + column, i, self.cp437(c))

                qp.setBackgroundMode(0)

        qp.end()

    def scroll_v(self, dy):
        self.qpix.scroll(0, dy*self.fontHeight, self.qpix.rect())

        qp = QtGui.QPainter()
        
        qp.begin(self.qpix)
        qp.setFont(self.font)
        qp.setPen(self.textPen)

        factor = abs(dy)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.CON_COLUMNS)

        if dy < 0:
            cemu.gotoXY(0, self.ROWS - factor)            
            qp.fillRect(0, (self.ROWS-factor)*self.fontHeight, self.fontWidth*self.CON_COLUMNS, factor * self.fontHeight + self.SPACER, self.backgroundBrush)

        if dy > 0:
            cemu.gotoXY(0, 0)            
            qp.fillRect(0, 0, self.fontWidth*self.CON_COLUMNS, factor * self.fontHeight, self.backgroundBrush)


        page = self.transformationEngine.decorate()

        # how many rows
        for row in range(factor):
            # for every column
            for i in range(self.COLUMNS):

                if dy < 0:
                    # we write from top-down, so get index of the first row that will be displayed
                    # this is why we have factor - row
                    idx = i + (self.ROWS - (factor - row))*self.COLUMNS
                if dy > 0:
                    idx = i + (self.COLUMNS*row)

                qp.setPen(self.transformationEngine.choosePen(idx))

                if self.transformationEngine.chooseBrush(idx) != None:
                    qp.setBackgroundMode(1)
                    qp.setBackground(self.transformationEngine.chooseBrush(idx))

                if len(self.getDisplayablePage()) > idx:
                    c = self.getDisplayablePage()[idx]
                else:
                    break

                if i == self.COLUMNS - 1:
                    hex_s = str(hex(c)[2:]).zfill(2)
                else:                
                    hex_s = str(hex(c)[2:]).zfill(2) + ' '

                # write hex representation
                cemu.write(hex_s, noBackgroudOnSpaces=True)
                
                # save hex position
                x, y = cemu.getXY()
                # write text
                cemu.writeAt(self.COLUMNS*3 + self.gap + (i%self.COLUMNS), y, self.cp437(c))

                # go back to hex chars
                cemu.gotoXY(x, y)

                qp.setBackgroundMode(0)


            cemu.writeLn()
        qp.end()

    def draw(self, refresh=False):
        if self.refresh or refresh:
            qp = QtGui.QPainter()
            qp.begin(self.qpix)
            self.drawTextMode(qp)
            self.refresh = False
            qp.end()

        self.drawAdditionals()

    def goTo(self, offset):
        if self.dataModel.offsetInPage(offset):
            # if in current page, move cursore
            x, y = self.dataModel.getXYInPage(offset)
            self.cursor.moveAbsolute(y, x)
        else:
            # else, move page
            self.dataModel.goTo(offset)
            self.cursor.moveAbsolute(0, 0)
            #self.draw(refresh=True)


        self.draw(refresh=True)
        if self.widget:
            self.widget.update()

    def drawTextMode(self, qp):
       
        # draw background
        qp.fillRect(0, 0, self.CON_COLUMNS * self.fontWidth,  self.ROWS * self.fontHeight + self.SPACER, self.backgroundBrush)

        # set text pen&font
        qp.setFont(self.font)
        qp.setPen(self.textPen)
        
        cemu = ConsoleEmulator(qp, self.ROWS, self.CON_COLUMNS)

        page = self.transformationEngine.decorate()

        for i, c in enumerate(self.getDisplayablePage()):     #TODO: does not apply all decorators

            if (i+1)%self.COLUMNS == 0:
                hex_s = str(hex(c)[2:]).zfill(2)
            else:
                hex_s = str(hex(c)[2:]).zfill(2) + ' '

            qp.setPen(self.transformationEngine.choosePen(i))

            if self.transformationEngine.chooseBrush(i) != None:
                qp.setBackgroundMode(1)
                qp.setBackground(self.transformationEngine.chooseBrush(i))
    
            # write hex representation
            cemu.write(hex_s, noBackgroudOnSpaces=True)
            # save hex position
            x, y = cemu.getXY()
            # write text
            cemu.writeAt(self.COLUMNS*3 + self.gap + (i%self.COLUMNS), y, self.cp437(c))
            # go back to hex chars
            cemu.gotoXY(x, y)
            if (i+1)%self.COLUMNS == 0:
                cemu.writeLn()

            qp.setBackgroundMode(0)  

    def moveCursor(self, direction):
        cursorX, cursorY = self.cursor.getPosition()

        if direction == Directions.Left:
            if cursorX == 0:
                if cursorY == 0:
                    self.scroll(1, 0)
                else:
                    self.cursor.moveAbsolute(self.COLUMNS-1, cursorY - 1)
            else:
                self.cursor.move(-1, 0)


        if direction == Directions.Right:
            if self.getCursorAbsolutePosition() + 1 >= self.dataModel.getDataSize():
                return

            if cursorX == self.COLUMNS-1:
                if cursorY == self.ROWS-1:
                    self.scroll(-1, 0)
                else:
                    self.cursor.moveAbsolute(0, cursorY + 1)
            else:
                self.cursor.move(1, 0)


        if direction == Directions.Down:
            if self.getCursorAbsolutePosition() + self.COLUMNS >= self.dataModel.getDataSize():
                y, x = self.dataModel.getXYInPage(self.dataModel.getDataSize()-1)
                self.cursor.moveAbsolute(x, y)
                return

            if cursorY == self.ROWS-1:
                self.scroll(0, -1)
            else:
                self.cursor.move(0, 1)

        if direction == Directions.Up:
            if cursorY == 0:
                self.scroll(0, 1)
            else:
                self.cursor.move(0, -1)

        if direction == Directions.End:
            if self.dataModel.getDataSize() < self.getCursorAbsolutePosition() + self.ROWS * self.COLUMNS:
                y, x = self.dataModel.getXYInPage(self.dataModel.getDataSize()-1)
                self.cursor.moveAbsolute(x, y)

            else:
                self.cursor.moveAbsolute(self.COLUMNS-1, self.ROWS-1)

        if direction == Directions.Home:
            self.cursor.moveAbsolute(0, 0)

        if direction == Directions.CtrlHome:
            self.dataModel.slideToFirstPage()
            self.draw(refresh=True)
            self.cursor.moveAbsolute(0, 0)

        if direction == Directions.CtrlEnd:
            self.dataModel.slideToLastPage()
            self.draw(refresh=True)
            self.moveCursor(Directions.End)



    def drawCursor(self, qp):
        qp.setBrush(QtGui.QColor(255, 255, 0))
        cursorX, cursorY = self.cursor.getPosition()

        columns = self.HexColumns[self.idxHexColumns]
        if cursorX > columns:
            self.cursor.moveAbsolute(columns-1, cursorY)

        # get cursor position again, maybe it was moved
        cursorX, cursorY = self.cursor.getPosition()

        qp.setOpacity(0.8)
        # cursor on text
        qp.drawRect((self.COLUMNS*3 + self.gap + cursorX)*self.fontWidth, cursorY*self.fontHeight+2, self.fontWidth, self.fontHeight)

        # cursor on hex
        qp.drawRect(cursorX*3*self.fontWidth, cursorY*self.fontHeight+2, 2*self.fontWidth, self.fontHeight)
        qp.setOpacity(1)

    def keyFilter(self):
        return [
                (QtCore.Qt.ControlModifier, QtCore.Qt.Key_Right),
                (QtCore.Qt.ControlModifier, QtCore.Qt.Key_Left),
                (QtCore.Qt.ControlModifier, QtCore.Qt.Key_Up),
                (QtCore.Qt.ControlModifier, QtCore.Qt.Key_Down),
                (QtCore.Qt.ControlModifier, QtCore.Qt.Key_End),
                (QtCore.Qt.ControlModifier, QtCore.Qt.Key_Home),


                (QtCore.Qt.NoModifier, QtCore.Qt.Key_Right),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_Left),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_Up),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_Down),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_End),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_Home),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_PageDown),
                (QtCore.Qt.NoModifier, QtCore.Qt.Key_PageUp)


                ]


    def anon(self, dx, dy):
        self.scroll(dx, dy)

        # scroll modifies datamodel offset, so we must do scroll and cursor
        # operations toghether

        y, x = self.dataModel.getXYInPage(self.dataModel.getDataSize() - 1)
        if self.getCursorAbsolutePosition() >= self.dataModel.getDataSize():
            y, x = self.dataModel.getXYInPage(self.dataModel.getDataSize() - 1)
            self.cursor.moveAbsolute(x, y)

        # we call draw() again because it was called before by scroll()
        # and the cursor is already painted but it's not in correct position
        # kinda hack, don't really like it
        self.draw()

    def handleKeyEvent(self, modifiers, key):

        if modifiers == QtCore.Qt.ControlModifier:

            if key == QtCore.Qt.Key_Right:
                self.addop((self.anon, -1, 0))

            if key == QtCore.Qt.Key_Left:
                self.addop((self.scroll, 1, 0))


            if key == QtCore.Qt.Key_Down:
                self.addop((self.anon, 0, -1))

            if key == QtCore.Qt.Key_Up:
                self.addop((self.scroll, 0, 1))

            if key == QtCore.Qt.Key_End:
                self.moveCursor(Directions.CtrlEnd)
                self.addop((self.draw,))

            if key == QtCore.Qt.Key_Home:
                self.moveCursor(Directions.CtrlHome)
                self.addop((self.draw,))

            return True

        else:#selif modifiers == QtCore.Qt.NoModifier:

            if key == QtCore.Qt.Key_Left:
                self.moveCursor(Directions.Left)
                self.addop((self.draw,))

            if key == QtCore.Qt.Key_Right:
                self.moveCursor(Directions.Right)
                self.addop((self.draw,))
                
            if key == QtCore.Qt.Key_Down:
                self.moveCursor(Directions.Down)
                self.addop((self.draw,))
                
            if key == QtCore.Qt.Key_End:
                self.moveCursor(Directions.End)
                self.addop((self.draw,))
                
            if key == QtCore.Qt.Key_Home:
                self.moveCursor(Directions.Home)
                self.addop((self.draw,))

            if key == QtCore.Qt.Key_Up:
                self.moveCursor(Directions.Up)
                self.addop((self.draw,))
                
            if key == QtCore.Qt.Key_PageDown:
                self.addop((self.scrollPages, 1))
    
            if key == QtCore.Qt.Key_PageUp:
                self.addop((self.scrollPages, -1))

            if key == QtCore.Qt.Key_F6:
                self.changeHexColumns()
                x, y = self.cursor.getPosition()

                columns = self.HexColumns[self.idxHexColumns]
                if x > columns:
                    self.cursor.moveAbsolute(columns-1, y)
                self.addop((self.draw,))

            return True

        return False

    def handleKeyPressEvent(self, modifier, key):
        if modifier == QtCore.Qt.ShiftModifier:
            self.startSelection()
            return True

    def handleKeyReleaseEvent(self, modifier, key):
        if modifier == QtCore.Qt.ShiftModifier:
            self.stopSelection()
            return True


    def addop(self, t):
        self.Ops.append(t)

    def getHeaderInfo(self):
        s = ''
        for i in range(self.HexColumns[self.idxHexColumns]):
            s += '{0} '.format('{0:x}'.format(i).zfill(2))

        s += self.gap*' ' + 'Text'
        return s
