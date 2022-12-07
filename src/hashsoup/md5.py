from copy import deepcopy

from .hasher import Hasher
from .utils import rol32


# Implementation mostly from https://en.wikipedia.org/wiki/MD5
class MD5(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_s = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]

    CONST_K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]

    CONST_STATE = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    ]

    LEN_STATE = 16
    LEN_BLOCK = 64
    # fmt: on

    def __init__(self, inp: bytes = None, state: bytes = None, digested: int = None):
        # This allows users to modify constants when they want
        self.s = self.CONST_s[:]
        self.K = self.CONST_K[:]
        if state:
            assert (
                len(state) == self.LEN_STATE
            ), f"The state must be {self.LEN_STATE}-byte"
            self.state = [
                int.from_bytes(state[i : i + 4], "little") for i in range(0, 16, 4)
            ]
        else:
            self.state = self.CONST_STATE[:]

        self.buffer = bytearray()
        # Store byte length
        self.digested = digested or 0

        if inp:
            self.update(inp)

    @classmethod
    def get_padding(cls, len_: int) -> bytes:
        padding = b"\x80"
        padding += b"\x00" * ((55 - len_) % 64)
        padding += (len_ * 8).to_bytes(8, "little")
        return padding

    def _pad(self):
        self.buffer += self.get_padding(self.digested)

    def update(self, inp: bytes) -> None:
        self.buffer += inp
        self.digested += len(inp)
        self._update()

    def _update(self):
        while len(self.buffer) >= self.LEN_BLOCK:
            self._update_chunk(self.buffer[: self.LEN_BLOCK])
            self.buffer = self.buffer[self.LEN_BLOCK :]

    def _update_chunk(self, chunk: bytes):
        M = [int.from_bytes(chunk[i : i + 4], "little") for i in range(0, 64, 4)]
        A, B, C, D = self.state

        for i in range(64):
            if i < 16:
                F = D ^ (B & (C ^ D))
                g = i
            elif i < 32:
                F = C ^ (D & (B ^ C))
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = 7 * i % 16
            F = (F + A + self.K[i] + M[g]) & 0xFFFFFFFF
            A, D, C = D, C, B
            B = (B + rol32(F, self.s[i])) & 0xFFFFFFFF

        self.state = [
            (self.state[0] + A) & 0xFFFFFFFF,
            (self.state[1] + B) & 0xFFFFFFFF,
            (self.state[2] + C) & 0xFFFFFFFF,
            (self.state[3] + D) & 0xFFFFFFFF,
        ]

    def digest(self) -> bytes:
        copy = deepcopy(self)
        copy._pad()
        copy._update()

        assert len(copy.buffer) == 0

        return b"".join(v.to_bytes(4, "little") for v in copy.state)
