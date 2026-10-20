# PyInstaller spec - works on Windows, macOS and Linux.
#   pip install -e .[all,dev]
#   pyinstaller packaging/qiew.spec
# Produces dist/qiew (dist/qiew.app on macOS).
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_submodules

root = Path(SPECPATH).parent

hidden = collect_submodules("qiew.formats") + collect_submodules("qiew.unpack") + collect_submodules("qiew.views")
binaries = collect_dynamic_libs("capstone")
datas = [(str(root / "qiew" / "resources"), "qiew/resources")]

a = Analysis(
    [str(root / "packaging" / "qiew_launcher.py")],
    pathex=[str(root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtWebEngineCore"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="qiew",
    console=not sys.platform.startswith("win"),  # windowed app on Windows
    upx=False,
)
if sys.platform == "darwin":
    app = BUNDLE(exe, name="qiew.app", bundle_identifier="org.qiew.qiew",
                 info_plist={"NSHighResolutionCapable": True})
