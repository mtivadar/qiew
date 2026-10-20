import pytest

from qiew.datamodel import BufferDataModel, FileDataModel, IntervalSet
from qiew.dialogs import Searcher, eval_expr, parse_hex
from qiew.highlight import AsciiStrings, Highlighter, Prefix, Range, WideStrings
from qiew import theme


def test_intervalset_merges():
    s = IntervalSet()
    s.add(10, 20)
    s.add(30, 40)
    s.add(20, 30)
    assert list(s) == [(10, 40)]
    s.add(5, 6)
    assert list(s) == [(5, 6), (10, 40)]
    assert list(s.overlapping(0, 12)) == [(5, 6), (10, 12)]


def test_file_model_saves_only_modified(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(bytes(range(256)) * 4)
    dm = FileDataModel(str(p))
    assert dm.u32(0) == 0x03020100
    assert dm.u64(1020) is None
    dm.write(5, b"\xAA\xBB")
    assert dm.dirty and dm.read(4, 8) == b"\x04\xAA\xBB\x07"
    assert p.read_bytes()[5] == 5          # copy-on-write until save
    assert dm.save()
    dm.close()
    assert p.read_bytes()[4:8] == b"\x04\xAA\xBB\x07"


def test_empty_file(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(b"")
    dm = FileDataModel(str(p))
    assert len(dm) == 0 and dm.byte(0) is None


def test_highlighter_priorities():
    data = b"\x00MZ\x90" + b"hello world" + b"\x00" * 4 + "wide.".encode("utf-16-le") + b"\x00" * 16
    dm = BufferDataModel(data)
    hl = Highlighter([AsciiStrings(), Prefix(b"MZ"), WideStrings(), Range(0, 1, theme.GREEN)])
    c = hl.colorize(dm, 0, len(data))
    assert c.fg[1] == theme.YELLOW and c.bg[1] == theme.DARK_RED       # MZ
    assert c.fg[4] == theme.RED                                        # ascii string
    assert c.fg[0] == theme.GREEN                                      # range on default colour
    w = data.index(b"w\x00")
    assert bytes(c.display[w:w + 5]) == b"wide."                       # compacted wide string
    dm.write(4, b"X")
    assert hl.colorize(dm, 0, 10).fg[4] == theme.EDITED


def test_highlight_margin_consistent_across_pages():
    data = b"\x00" * 100 + b"ABCDEFGH" + b"\x00" * 100
    dm = BufferDataModel(data)
    hl = Highlighter([AsciiStrings()])
    page = hl.colorize(dm, 104, 50)          # starts in the middle of the string
    assert page.fg[0] == theme.RED


def test_searcher_finds_utf16():
    dm = BufferDataModel(b"....h\x00e\x00l\x00l\x00o\x00....hello")
    s = Searcher()
    s.set(b"hello", wide=True)
    assert s.find(dm, 0) == (4, 10)
    assert s.find(dm, 5) == (18, 5)
    assert s.find(dm, len(dm), backward=True) == (18, 5)


def test_eval_expr():
    assert eval_expr("EP+0x10", {"EP": 0x1000}) == 0x1010
    assert eval_expr("401000", {}) == 401000
    assert eval_expr("40100a", {}) == 0x40100A
    assert eval_expr("end - 2*8", {"END": 100}) == 84
    with pytest.raises(Exception):
        eval_expr("__import__('os')", {})
    assert parse_hex("de ad BE EF") == b"\xde\xad\xbe\xef"
    assert parse_hex("abc") is None


def test_render_grid(qapp):
    from qiew.render import GlyphAtlas, GridRenderer, TextGrid
    from qiew.theme import pick_font

    atlas = GlyphAtlas(pick_font(), 2.0)
    r = GridRenderer(atlas)
    g = TextGrid(3, 10)
    g.put(1, 2, "hi", theme.RED, theme.DARK_RED)
    img = r.render(g.chars, g.fg, g.bg)
    assert (img.width(), img.height()) == (10 * atlas.pw, 3 * atlas.ph)
    assert abs(img.devicePixelRatio() - 2.0) < 1e-6
    # background pixel is navy, highlighted cell has dark red background somewhere
    c = img.pixelColor(0, 0)
    assert (c.red(), c.green(), c.blue()) == (0, 0, 128)
    cell = img.copy(2 * atlas.pw, atlas.ph, atlas.pw, atlas.ph)
    colors = {cell.pixelColor(x, y).rgb() for x in range(cell.width()) for y in range(cell.height())}
    assert len(colors) > 1
