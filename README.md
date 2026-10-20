# Qiew - Hex/File format viewer

Hex / binary / disassembly viewer designed for reverse engineering malware.
Runs on Windows, macOS and Linux (Python 3.10+, Qt 6 via PySide6).

features:
  * highlights strings / calls / MZ-PE, wide strings, overlay, IAT — very useful in malware analysis
  * PE info: headers, sections, directories, imports, exports, version info, resources; jump to entry point, sections, overlay
  * ELF, MBR/boot sector, NTFS volume and APK support
  * disassembler (x86 16/32/64, ARM, Thumb, ARM64) with referenced strings, resolved API calls, branch arrows, follow/back
  * "highlight all" for the current selection
  * edit mode (binary and nibble-wise hex), decrypt/encrypt selection (xor/rol/ror/add/sub, RC4, AES-CBC, base64)
  * annotations (named, coloured ranges; save/load as JSON), dropper (dump selection, carve embedded PEs)

[see wiki for key functions](https://github.com/mtivadar/qiew/wiki), or press **F1** in the app.

This program is licensed under [GPLv2](http://www.gnu.org/licenses/gpl-2.0.en.html).

## Installation

```
python -m pip install -e .            # or: pip install -r requirements.txt
python -m pip install -e .[all]       # + AES plugin (pyaes) and APK manifest (androguard)
```

All dependencies ship binary wheels for Windows, macOS (Intel + Apple Silicon) and Linux — no C compiler needed.

## Running

```
qiew <file> [<file> ...]
python -m qiew <file>
qiew --font "Terminus (TTF)" --font-size 12 sample.exe
```

### Font
[Terminus](http://terminus-font.sourceforge.net/) is used when installed (Debian/Ubuntu: `sudo apt-get install fonts-terminus`),
or drop the `.ttf` into `~/.qiew/fonts` / `qiew/resources/fonts`. Otherwise the platform
monospace font (Menlo / Consolas / DejaVu Sans Mono) is used.

### Keys (Ctrl = Cmd, Alt = Option on macOS)

| key | action |
|---|---|
| Tab | switch view: binary / hex / disasm |
| F2 | toggle edit mode |
| Shift + move, mouse drag | select; Esc clears |
| / n b | search (text also matches UTF-16LE, or hex), next, previous |
| Alt+G | go to (expressions: `EP+0x10`, `END-0x200`, `401000`; FA/RVA/VA) |
| F3 / F6 | cycle address mode (VA/RVA/FA) / hex columns |
| F7 | entry point (PE, ELF) |
| s / e | skip run of the same byte / skip to next zero block |
| [ ] / 0 | previous / next section (PE, ELF) or partition entry (MBR) / overlay |
| Alt+H/S/D/I/E/V/R | PE headers / sections / directories / imports / exports / version / resources |
| Enter, Backspace (disasm) | follow branch, go back |
| Ctrl+Ins / Ctrl+Shift+C | copy selection as hex |
| Shift+F4 | decrypt / encrypt selection |
| F10 | dropper |
| Ctrl+A / Alt+A / ? | annotate selection (top / child) / annotations window |

In the info windows, **Enter** jumps to the item and **F9** jumps and selects it.

## Plugins

Format and decrypt plugins are plain Python classes — no yapsy, no `.yapsy-plugin` files.
Built-ins live in `qiew/formats` and `qiew/unpack`; your own go in `~/.qiew/plugins/*.py`
(or directories listed in `QIEW_PLUGINS`):

```python
from qiew.formats.base import FileFormat, Action
from qiew import highlight, theme

class MyFormat(FileFormat):
    name = "myfmt"
    priority = 10

    @classmethod
    def recognize(cls, dm):
        return dm.read(0, 4) == b"MYF1"

    def setup(self, doc):
        doc.hl.rules = highlight.default_rules() + [highlight.Prefix(b"MYF1", theme.YELLOW, theme.DARK_RED)]

    def actions(self):
        return super().actions() + [Action("Go to header end", "Alt+X", lambda: self.goto(0x40))]
```

## Building a standalone binary

```
pip install -e .[all,dev]
pyinstaller packaging/qiew.spec      # dist/qiew  (dist/qiew.app on macOS)
```

## What changed in 2.0 (rewrite)

* Python 3.10+, Qt 6 (PySide6); yapsy, ply, pyperclip and the `.ui` files are gone.
* **Rendering**: the old code issued one `QPainter.drawText` + pen switch per character and looked up
  colours in per-byte dicts, so binary mode with many highlighted bytes was slow. Now glyphs are
  rasterised once into an atlas, colour pairs are cached as tiles, and a whole page is composed by a
  single numpy gather (~2 ms for a 200x60 page, independent of the number of colours). Highlighting
  is done with regexes + numpy slices. Cursor moves never re-render the page.
* HiDPI/Retina aware; grid stays aligned with any fallback glyph.
* Disassembly: symbol lookups are O(1) dicts (were linear import scans per call), scrolling
  re-synchronises backwards with `disasm_lite`, ELF uses real segment VA mapping.
* Saving writes only the modified ranges back. Search for text in UTF-16 works (the old BOM bug is fixed).

Powered by: Python 3, [Qt 6 / PySide6](https://doc.qt.io/qtforpython-6/), numpy, [pefile](https://github.com/erocarrera/pefile), [pyelftools](https://github.com/eliben/pyelftools), [Capstone](http://www.capstone-engine.org/)

## Similar tools
* [GView](https://github.com/gdt050579/GView/) is a comprehensive native-app, cross-platform reverse-engineering tool with many plugins and a console-based UI and it served as an inspiration for Qiew, and both got inspired by old-but-actual tool Hiew.
  
## Screenshots (1.x)
![binview](https://github.com/mtivadar/qiew/blob/master/wiki/binview.png)
![hexview](https://github.com/mtivadar/qiew/blob/master/wiki/hexview.png)
![disasmview](https://github.com/mtivadar/qiew/blob/master/wiki/disasmview.png)
