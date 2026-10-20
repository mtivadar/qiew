import os
import struct
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope="session")
def qapp():
    from PySide6 import QtWidgets

    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def make_pe32() -> bytes:
    """Tiny valid PE32 with one .text section containing code + a string."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    fh = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<HBBIIIIII", opt, 0, 0x10B, 1, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<III", opt, 28, 0x400000, 0x1000, 0x200)       # ImageBase, SectAlign, FileAlign
    struct.pack_into("<HHHHHH", opt, 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<IIII", opt, 56, 0x2000, 0x200, 0, 2)            # SizeOfImage, SizeOfHeaders, csum, subsys
    struct.pack_into("<I", opt, 92, 16)                                 # NumberOfRvaAndSizes
    sec = struct.pack("<8sIIIIIIHHI", b".text", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = bytes(dos) + b"PE\x00\x00" + fh + bytes(opt) + sec
    hdr = hdr.ljust(0x200, b"\x00")
    # push 0x401010 ; ret ; ... "Hello, qiew world" at 0x10
    code = bytes.fromhex("6810104000c3") + b"\x90" * 10 + b"Hello qiew world\x00"
    return hdr + code.ljust(0x200, b"\x00") + b"OVERLAYDATA" * 4


@pytest.fixture
def pe_file(tmp_path):
    p = tmp_path / "t.exe"
    p.write_bytes(make_pe32())
    return str(p)


@pytest.fixture
def mbr_file(tmp_path):
    mbr = bytearray(1024)
    mbr[0:3] = b"\xfa\x31\xc0"
    mbr[446] = 0x80
    mbr[446 + 4] = 0x07
    mbr[510:512] = b"\x55\xaa"
    p = tmp_path / "mbr.bin"
    p.write_bytes(bytes(mbr))
    return str(p)
