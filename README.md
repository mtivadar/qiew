#Qiew - Hex/File format viewer

## Portable Executable (PE) file viewer
Designed to be useful in reverse engineering malware.

features:
  * highlights strings/calls/mz-pe very useful in malware analysis.
  * PE info, able to jump to sections, entry point, overlay, etc.
  * disassembler + referenced strings, API calls
  * "highlight all" for current text selection.

[see wiki for key functions](https://github.com/mtivadar/qiew/wiki)

## Releases/Binaries
Binaries [available](https://github.com/mtivadar/qiew/releases) for Windows AMD64, built with cx_Freeze

## Installation from sources
If you have a C compiler run 
```
pip install -r requirements.txt
``` 
and install [PyQt4](http://www.riverbankcomputing.com/software/pyqt/download).

Otherwise run
```
pip install pefile pyperclip
```
and manually install [**diStorm3**](https://code.google.com/p/distorm/downloads/list) and [**PyQt4**](http://www.riverbankcomputing.com/software/pyqt/download).


## Available plugins
  * **PE**
 
  * **bootsector**

## Binary view mode
![binview](https://github.com/mtivadar/qiew/blob/master/wiki/binview.png)
## Hex view mode
![hexview](https://github.com/mtivadar/qiew/blob/master/wiki/hexview.png)
## Disassembly view mode
![disasmview](https://github.com/mtivadar/qiew/blob/master/wiki/disasmview.png)

Powered by: Python, Qt4, Terminus font, pefile, distorm

[see wiki](https://github.com/mtivadar/qiew/wiki)
