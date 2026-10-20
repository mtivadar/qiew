"""Capstone wrapper producing display-ready instruction lines.

Replaces the old ply based lexers with small regex tokenizers and resolves
symbols / referenced strings through O(1) lookups provided by the format
plugin (the old code scanned the whole import table for every call).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

import capstone

# -- architecture presets ---------------------------------------------------
_ARM64 = getattr(capstone, "CS_ARCH_AARCH64", None) or getattr(capstone, "CS_ARCH_ARM64")
X86_16 = (capstone.CS_ARCH_X86, capstone.CS_MODE_16)
X86_32 = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
X86_64 = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
ARM = (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
THUMB = (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
ARM64 = (_ARM64, capstone.CS_MODE_ARM)

CS_OP_IMM = getattr(capstone, "CS_OP_IMM", 2)
CS_OP_MEM = getattr(capstone, "CS_OP_MEM", 3)
GRP_JUMP = getattr(capstone, "CS_GRP_JUMP", 1)
GRP_CALL = getattr(capstone, "CS_GRP_CALL", 2)
GRP_BRANCH_REL = getattr(capstone, "CS_GRP_BRANCH_RELATIVE", 7)

MNEMONIC_COLUMN = 30
MNEMONIC_WIDTH = 15
OPERAND_COLUMN = MNEMONIC_COLUMN + MNEMONIC_WIDTH
MAX_HEX_BYTES = 9  # 9*3 = 27 < MNEMONIC_COLUMN


# -- tokenizers ---------------------------------------------------------------
def _x86_regs() -> list[str]:
    r = []
    for b in "abcd":
        r += [f"r{b}x", f"e{b}x", f"{b}x", f"{b}l", f"{b}h"]
    for n in ("si", "di", "bp", "sp"):
        r += [f"r{n}", f"e{n}", n, f"{n}l"]
    for i in range(8, 16):
        r += [f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"]
    r += ["rip", "eip", "ip", "cs", "ds", "es", "fs", "gs", "ss"]
    for i in range(32):
        r += [f"xmm{i}", f"ymm{i}", f"zmm{i}"]
    for i in range(16):
        r += [f"cr{i}", f"dr{i}"]
    for i in range(8):
        r += [f"st({i})", f"mm{i}", f"k{i}"]
    r += ["st"]
    return r


def _arm_regs() -> list[str]:
    r = [f"r{i}" for i in range(16)] + ["sb", "sl", "fp", "ip", "sp", "lr", "pc", "apsr_nzcv", "cpsr", "spsr"]
    for p in "xwvqdsbh":
        r += [f"{p}{i}" for i in range(32)]
    r += ["xzr", "wzr", "lsl", "lsr", "asr", "ror"]
    return r


def _tokenizer(regs: list[str]) -> re.Pattern:
    regs = sorted(set(regs), key=len, reverse=True)
    reg = "|".join(re.escape(x) for x in regs)
    return re.compile(
        rf"(?P<reg>(?<![\w.])(?:{reg})(?![\w(]))"
        r"|(?P<num>#?-?(?:0x[0-9a-fA-F]+|\d+)\b)"
        r"|(?P<ptr>\b(?:[xyz]?mm)?(?:qword|dword|word|byte|tbyte|ptr|xmmword|ymmword|zmmword)\b)"
        r"|(?P<word>[\w.$@?]+)"
    )


@lru_cache(maxsize=None)
def tokenizer_for(arch: int) -> re.Pattern:
    if arch == capstone.CS_ARCH_X86:
        return _tokenizer(_x86_regs())
    return _tokenizer(_arm_regs())


# -- lines --------------------------------------------------------------------
@dataclass
class Token:
    col: int
    text: str
    kind: str  # hex, mnem, reg, num, ptr, word, sym, str


@dataclass
class Line:
    offset: int            # file offset
    address: int           # VA shown / used by capstone
    size: int
    raw: bytes
    mnemonic: str
    op_str: str
    is_branch: bool = False
    is_call: bool = False
    target: int | None = None      # branch target VA
    symbol: str | None = None      # resolved API name for calls
    refstr: str = ""               # referenced string
    tokens: list[Token] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.offset + self.size

    def hex_text(self) -> str:
        h = " ".join(f"{b:02x}" for b in self.raw[:MAX_HEX_BYTES])
        return h + (" +" if len(self.raw) > MAX_HEX_BYTES else "")

    # cursor helpers -------------------------------------------------------
    def stops(self) -> list[int]:
        return [t.col for t in self.tokens] or [0]

    def token_at(self, col: int) -> Token | None:
        for t in self.tokens:
            if t.col == col:
                return t
        return self.tokens[0] if self.tokens else None

    def nearest(self, col: int) -> int:
        stops = self.stops()
        best = stops[0]
        for s in stops:
            if s <= col:
                best = s
        return best


class Disassembler:
    def __init__(self, arch_mode, fmt) -> None:
        arch, mode = arch_mode
        self.arch = arch
        self.cs = capstone.Cs(arch, mode)
        self.cs.detail = True
        self.lite = capstone.Cs(arch, mode)
        self.fmt = fmt
        self.tok = tokenizer_for(arch)
        self.is_x86 = arch == capstone.CS_ARCH_X86
        if self.is_x86:
            import capstone.x86 as x86
            self._rip = x86.X86_REG_RIP
            self._push = x86.X86_INS_PUSH
        else:
            self._rip = self._push = None

    # ------------------------------------------------------------------ decode
    def decode(self, dm, offset: int, count: int) -> list[Line]:
        """Decode ``count`` lines starting at file offset ``offset``."""
        out: list[Line] = []
        size = len(dm)
        pos = offset
        while len(out) < count and pos < size:
            chunk = dm.read(pos, min(size, pos + max(64, (count - len(out)) * 16)))
            base = self._va(pos)
            n0 = len(out)
            consumed = 0
            for insn in self.cs.disasm(chunk, base):
                out.append(self._line(pos + consumed, insn))
                consumed += insn.size
                if len(out) >= count:
                    break
            pos += consumed
            if len(out) >= count or pos >= size:
                break
            if len(out) == n0 or consumed < len(chunk) - 15:
                # capstone stopped on invalid bytes: emit "db" and continue
                b = dm.byte(pos)
                out.append(self._db(pos, b))
                pos += 1
        return out

    def _va(self, offset: int) -> int:
        va = self.fmt.va(offset)
        return offset if va is None else va

    def _db(self, offset: int, b: int) -> Line:
        ln = Line(offset, self._va(offset), 1, bytes([b]), "db", f"0x{b:02x}")
        self._tokens(ln)
        return ln

    def _line(self, offset: int, insn) -> Line:
        ln = Line(offset, insn.address, insn.size, bytes(insn.bytes), insn.mnemonic, insn.op_str)
        try:
            groups = insn.groups
        except capstone.CsError:
            groups = ()
        ln.is_call = GRP_CALL in groups
        ln.is_branch = ln.is_call or GRP_JUMP in groups
        try:
            ops = insn.operands
        except capstone.CsError:
            ops = []

        refs = []
        for o in ops:
            if o.type == CS_OP_IMM:
                refs.append(o.imm)
            elif o.type == CS_OP_MEM:
                try:
                    base, disp = o.mem.base, o.mem.disp
                except AttributeError:
                    continue
                if self.is_x86 and base == self._rip:
                    refs.append(insn.address + insn.size + disp)
                elif base == 0:
                    refs.append(disp)

        if ln.is_branch and refs:
            ln.target = refs[0]
            ln.symbol = self.fmt.symbol(refs[0])  # call/jmp through the IAT
        if not ln.symbol and not ln.is_branch:
            for v in refs:
                if v and v > 0x100:
                    s = self.fmt.string_at_va(v)
                    if len(s) > 4:
                        ln.refstr = s
                        break
        self._tokens(ln)
        return ln

    def _tokens(self, ln: Line) -> None:
        toks = [Token(i * 3, f"{b:02x}", "hex") for i, b in enumerate(ln.raw[:MAX_HEX_BYTES])]
        toks.append(Token(MNEMONIC_COLUMN, ln.mnemonic, "mnem"))
        if ln.symbol:
            toks.append(Token(OPERAND_COLUMN + 1, ln.symbol, "sym"))
        else:
            for m in self.tok.finditer(ln.op_str):
                toks.append(Token(OPERAND_COLUMN + m.start(), m.group(), m.lastgroup or "word"))
        ln.tokens = toks

    # ------------------------------------------------------------------ navigation
    def prev_offset(self, dm, offset: int) -> int:
        """Best guess for the start of the instruction preceding ``offset``."""
        if offset <= 0:
            return 0
        lo = max(0, offset - 64)
        votes: dict[int, int] = {}
        for s in range(lo, offset):
            chunk = dm.read(s, offset)
            pos, last = s, None
            for (_a, sz, _m, _o) in self.lite.disasm_lite(chunk, 0):
                last = pos
                pos += sz
            if pos == offset and last is not None:
                votes[last] = votes.get(last, 0) + 1
        if not votes:
            return offset - 1
        # the predecessor most decoding paths agree on (ties: the longer instruction)
        return max(votes, key=lambda k: (votes[k], -k))
