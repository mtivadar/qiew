# Qiew - Hex/File format viewer

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
Install [Terminus font](http://terminus-font.sourceforge.net/), for Windows users download from [here](http://sourceforge.net/projects/terminus-font/files/terminus-font-4.40/terminus-font-4.40.exe/download). For Debian/Ubuntu users: _sudo apt-get install xfonts-terminus_

If you have a C compiler run 
```
pip install -r requirements.txt
``` 

Otherwise run
```
pip install yapsy pefile pyperclip pyaes ply pyelftools androguard PyQt5
```
and manually install [**Capstone**](http://www.capstone-engine.org/documentation.html).

If you develop in a virtualenv on Windows, you need to copy the python3.dll to your virtual env, as only python36.dll is copied automatically.

## Available plugins
  * **PE**
 
  * **bootsector**

  * **ELF**
  
  * **APK**
  
## Binary view mode
![binview](https://github.com/mtivadar/qiew/blob/master/wiki/binview.png)
## Hex view mode
![hexview](https://github.com/mtivadar/qiew/blob/master/wiki/hexview.png)
## Disassembly view mode
![disasmview](https://github.com/mtivadar/qiew/blob/master/wiki/disasmview.png)
![disasmview](https://github.com/mtivadar/qiew/blob/master/wiki/disasmview2.png)

Powered by: Python3, [Qt5](http://doc.qt.io/qt-5/qt5-intro.html), [Terminus font](http://terminus-font.sourceforge.net/), [pefile](https://github.com/erocarrera/pefil), [Capstone](http://www.capstone-engine.org/index.html)

[see wiki](https://github.com/mtivadar/qiew/wiki)
