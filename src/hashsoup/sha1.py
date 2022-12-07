from copy import deepcopy

from .hasher import Hasher
from .utils import rol32


# Implementation mostly from https://en.wikipedia.org/wiki/SHA-1
class SHA1(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_K = [
        0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
    ]
    CONST_STATE = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    ]

    LEN_STATE = 20
    LEN_BLOCK = 64
    # fmt: on

    def __init__(self, inp: bytes = None, state: bytes = None, digested: int = None):
        # This allows users to modify constants when they want
        self.K = self.CONST_K[:]
        if state:
            assert (
                len(state) == self.LEN_STATE
            ), f"The state must be {self.LEN_STATE}-byte"
            self.state = [
                int.from_bytes(state[i : i + 4], "big")
                for i in range(0, self.LEN_STATE, 4)
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
        padding += (len_ * 8).to_bytes(8, "big")
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
        w = [int.from_bytes(chunk[i : i + 4], "big") for i in range(0, 64, 4)]
        a, b, c, d, e = self.state

        for i in range(16, 80):
            w.append(rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        for i in range(80):
            if i < 20:
                f = (b & c) ^ (~b & d)
            elif i < 40:
                f = b ^ c ^ d
            elif i < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                f = b ^ c ^ d

            temp = (rol32(a, 5) + f + e + self.K[i // 20] + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, rol32(b, 30), a, temp

        self.state = [
            (self.state[0] + a) & 0xFFFFFFFF,
            (self.state[1] + b) & 0xFFFFFFFF,
            (self.state[2] + c) & 0xFFFFFFFF,
            (self.state[3] + d) & 0xFFFFFFFF,
            (self.state[4] + e) & 0xFFFFFFFF,
        ]

    def digest(self) -> bytes:
        copy = deepcopy(self)
        copy._pad()
        copy._update()

        assert len(copy.buffer) == 0

        return b"".join(v.to_bytes(4, "big") for v in copy.state)
