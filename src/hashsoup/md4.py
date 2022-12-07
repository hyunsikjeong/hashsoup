from copy import deepcopy

from .hasher import Hasher
from .utils import rol32


# Implementation mostly from https://www.rfc-editor.org/rfc/rfc1186
class MD4(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_s = [
        3,  7, 11, 19,  3,  7, 11, 19,  3,  7, 11, 19,  3,  7, 11, 19,
        3,  5,  9, 13,  3,  5,  9, 13,  3,  5,  9, 13,  3,  5,  9, 13,
        3,  9, 11, 15,  3,  9, 11, 15,  3,  9, 11, 15,  3,  9, 11, 15
    ]
    
    CONST_g = [
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        0,  4,  8, 12,  1,  5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 15,
        0,  8,  4, 12,  2, 10,  6, 14,  1,  9,  5, 13,  3, 11,  7, 15
    ]

    CONST_C = [
        0, 0o13240474631, 0o15666365641
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
        self.g = self.CONST_g[:]
        self.C = self.CONST_C[:]
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

        for i in range(48):
            if i < 16:
                F = D ^ (B & (C ^ D))
                K = self.C[0]
            elif i < 32:
                F = (B & C) | (C & D) | (B & D)
                K = self.C[1]
            else:
                F = B ^ C ^ D
                K = self.C[2]
            A = rol32((F + A + K + M[self.g[i]]) & 0xFFFFFFFF, self.s[i])
            A, D, C, B = D, C, B, A

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
