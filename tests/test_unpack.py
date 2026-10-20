import pytest

from qiew.unpack.base import key_bytes, parse_key
from qiew.unpack.basic import _scalar, transform
from qiew.unpack.rc4 import rc4


def _reference(data, op, key, size, skip, keyop, delta):
    """Straight port of the original per-byte loop (full words only)."""
    out = bytearray(data)
    i = 0
    while i + size <= len(data):
        v = int.from_bytes(out[i:i + size], "little")
        v = _scalar(op, v, key, size)
        out[i:i + size] = v.to_bytes(size, "little")
        if keyop != "---":
            key = _scalar(keyop, key, delta, max(1, (key.bit_length() + 7) // 8))
        i += size + skip
    return bytes(out)


@pytest.mark.parametrize("op", ["XOR", "ROL", "ROR", "ADD", "SUB"])
@pytest.mark.parametrize("size,skip", [(1, 0), (2, 0), (4, 1), (8, 0), (3, 2)])
@pytest.mark.parametrize("keyop,delta", [("---", 0), ("ADD", 3), ("ROL", 1), ("XOR", 0x55)])
def test_transform_matches_reference(op, size, skip, keyop, delta):
    data = bytes((i * 37 + 11) & 0xFF for i in range(203))
    key = 0x1F2E3D4C5B6A7988 & ((1 << (8 * size)) - 1) or 0x41
    assert transform(data, op, key, size, skip, keyop, delta) == _reference(data, op, key, size, skip, keyop, delta)


def test_xor_roundtrip():
    data = b"hello world" * 10
    enc = transform(data, "XOR", 0x42)
    assert enc != data and transform(enc, "XOR", 0x42) == data


def test_rc4_known_vector():
    assert rc4(b"Plaintext", b"Key").hex() == "bbf316e8d940af0ad3"


def test_keys():
    assert parse_key("0x10") == 16
    assert parse_key("01 02") == 0x0201
    assert key_bytes("01 02 03", True) == b"\x01\x02\x03"
    assert key_bytes("abc", False) == b"abc"


def test_aes_roundtrip():
    pytest.importorskip("pyaes")
    from qiew.unpack.aes import aes_cbc

    key, iv = b"k" * 16, b"i" * 16
    data = bytes(range(48)) + b"tail"
    enc = aes_cbc(data, key, iv, True)
    assert enc[-4:] == b"tail" and enc[:48] != data[:48]
    assert aes_cbc(enc, key, iv, False) == data
