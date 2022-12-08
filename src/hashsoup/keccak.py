from __future__ import annotations
from copy import deepcopy

from .hasher import Hasher
from .utils import rol, xorsum

# Implementation mostly from https://keccak.team/files/Keccak-implementation-3.2.pdf
# TODO: Rename constants
class Keccak(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_RC = [
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008
    ]

    CONST_r = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]
    # fmt: on

    def __init__(self, r: int, c: int, d: int, inp: bytes = None, digested: int = None):
        # This allows users to modify constants when they want
        # General constants
        assert r % 8 == 0, "r % 8 must be 0 (fits into bytes)"
        assert d % 8 == 0, "d % 8 must be 0 (fits into bytes)"
        self.b = r + c
        self.w = self.b // 25
        self.d = d
        assert r % self.w == 0, "r % w must be 0 (fits into words)"
        assert r // self.w <= 25, "r // w must be not greater than 25"
        self.num_words = r // self.w
        self.mask = (1 << self.w) - 1

        # Keccak-f-related constants
        self.nr = 10 + 2 * self.w.bit_length()
        self.RC = self.CONST_RC[:]
        self.r = self.CONST_r[:]

        self.state = [[0 for j in range(5)] for i in range(5)]

        self.buffer = bytearray()
        self.digested = digested or 0
        if inp:
            self.update(inp)

    def _f(self) -> None:
        for i in range(self.nr):
            self._f_round(self.state, self.RC[i])

    def _f_round(self, A: list[list[int]], RC: int) -> None:
        # Theta step
        C = [xorsum(A[x]) for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1, self.w) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]

        # Rho & phi step
        B = [[None for j in range(5)] for i in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], self.r[x][y], self.w)

        # Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y])

        # Iota step
        A[0][0] = (A[0][0] ^ RC) & self.mask

    def _absorbing_phase(self):
        while len(self.buffer) >= self.LEN_BLOCK:
            Pi = int.from_bytes(self.buffer[: self.LEN_BLOCK], "little")
            self.buffer = self.buffer[self.LEN_BLOCK :]
            for j in range(self.num_words):
                x, y = j % 5, j // 5
                v = (Pi >> (self.w * j)) & self.mask
                self.state[x][y] ^= v
            self._f()

    def _squeezing_phase(self):
        Z = b""
        while len(Z) < (self.d >> 3):
            v = 0
            for j in range(self.num_words):
                x, y = j % 5, j // 5
                v |= self.state[x][y] << (self.w * j)
            Z += v.to_bytes(self.LEN_BLOCK, "little")
            self._f()

        return Z[: self.d >> 3]

    @classmethod
    def get_padding(cls, len_: int) -> bytes:
        if len_ % cls.LEN_BLOCK == cls.LEN_BLOCK - 1:
            return bytes([0x80 ^ cls.PAD_BYTE])
        padding = bytes([cls.PAD_BYTE])
        padding += b"\x00" * ((-2 - len_) % cls.LEN_BLOCK)
        padding += b"\x80"
        return padding

    def _pad(self):
        self.buffer += self.get_padding(self.digested)

    def update(self, inp: bytes) -> None:
        self.buffer += inp
        self.digested += len(inp)
        self._absorbing_phase()

    def digest(self) -> bytes:
        copy = deepcopy(self)
        copy._pad()
        copy._absorbing_phase()
        assert len(copy.buffer) == 0
        return copy._squeezing_phase()


class SHA3_224(Keccak):
    LEN_BLOCK = 1152 // 8
    PAD_BYTE = 0x06

    def __init__(self, inp: bytes = None, digested: int = None):
        super().__init__(1152, 448, 224, inp, digested)


class SHA3_256(Keccak):
    LEN_BLOCK = 1088 // 8
    PAD_BYTE = 0x06

    def __init__(self, inp: bytes = None, digested: int = None):
        super().__init__(1088, 512, 256, inp, digested)


class SHA3_384(Keccak):
    LEN_BLOCK = 832 // 8
    PAD_BYTE = 0x06

    def __init__(self, inp: bytes = None, digested: int = None):
        super().__init__(832, 768, 384, inp, digested)


class SHA3_512(Keccak):
    LEN_BLOCK = 576 // 8
    PAD_BYTE = 0x06

    def __init__(self, inp: bytes = None, digested: int = None):
        super().__init__(576, 1024, 512, inp, digested)


# Python hashlib's shake_128 and shake_256 have a different structure
# that receives an argument `length` on `digest()` and `hexdigest()`
# May need to change :(


class SHAKE_128(Keccak):
    LEN_BLOCK = 1344 // 8
    PAD_BYTE = 0x1F

    def __init__(self, d: int, inp: bytes = None, digested: int = None):
        super().__init__(1344, 256, d, inp, digested)


class SHAKE_256(Keccak):
    LEN_BLOCK = 1088 // 8
    PAD_BYTE = 0x1F

    def __init__(self, d: int, inp: bytes = None, digested: int = None):
        super().__init__(1088, 512, d, inp, digested)
