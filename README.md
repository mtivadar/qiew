#Qiew - Hex/File format viewer

## Portable Executable (PE) file viewer
Designed to be useful for reverse engineering malware.

features:
  * highlights strings/calls/mz-pe very useful in malware analysis.
  * PE info, able to jump to sections, entry point, overlay, etc.
  * disassembler + referenced strings, API calls
  * "highlight all" for current text selection.

[see wiki for key functions](https://github.com/mtivadar/qiew/wiki)

This program is licensed under [GPLv2](http://www.gnu.org/licenses/gpl-2.0.en.html).

## Releases/Binaries
Binaries [available](https://github.com/mtivadar/qiew/releases) for Windows AMD64, built with cx_Freeze

## Installation from sources
Install [Terminus font](http://terminus-font.sourceforge.net/), for Windows users download from [here](http://sourceforge.net/projects/terminus-font/files/terminus-font-4.39/terminus-font-4.39.exe/download). For Debian/Ubuntu users: _sudo apt-get install xfonts-terminus_

If you have a C compiler run 
```
pip install -r requirements.txt
``` 
and install [PyQt4](http://www.riverbankcomputing.com/software/pyqt/download).

Otherwise run
```
pip install pefile pyperclip pyaes ply pyelftools
```
and manually install [**Capstone**](http://www.capstone-engine.org/documentation.html) and [**PyQt4**](http://www.riverbankcomputing.com/software/pyqt/download).


## Available plugins
  * **PE**
 
  * **bootsector**

## Binary view mode
![binview](https://github.com/mtivadar/qiew/blob/master/wiki/binview.png)
## Hex view mode
![hexview](https://github.com/mtivadar/qiew/blob/master/wiki/hexview.png)
## Disassembly view mode
![disasmview](https://github.com/mtivadar/qiew/blob/master/wiki/disasmview.png)

Powered by: Python, Qt4, [Terminus font](http://terminus-font.sourceforge.net/), [pefile](https://github.com/erocarrera/pefil), [capstone](http://www.capstone-engine.org/index.html)

[see wiki](https://github.com/mtivadar/qiew/wiki)
