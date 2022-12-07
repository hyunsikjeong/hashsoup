from copy import deepcopy

from .hasher import Hasher
from .utils import ror32


# Implementation mostly from https://en.wikipedia.org/wiki/SHA-2
class SHA224(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    CONST_STATE = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ]

    LEN_STATE = 32
    LEN_BLOCK = 64
    # fmt: on

    def __init__(self, inp: bytes = None, state: bytes = None, digested: int = None):
        # This allows users to modify constants when they want
        self.k = self.CONST_k[:]
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
        w = [
            int.from_bytes(chunk[i : i + 4], "big") for i in range(0, self.LEN_BLOCK, 4)
        ]
        a, b, c, d, e, f, g, h = self.state

        for i in range(16, 64):
            s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

        for i in range(64):
            S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            ne, na = (d + temp1) & 0xFFFFFFFF, (temp1 + temp2) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, ne, c, b, a, na

        self.state = [
            (self.state[0] + a) & 0xFFFFFFFF,
            (self.state[1] + b) & 0xFFFFFFFF,
            (self.state[2] + c) & 0xFFFFFFFF,
            (self.state[3] + d) & 0xFFFFFFFF,
            (self.state[4] + e) & 0xFFFFFFFF,
            (self.state[5] + f) & 0xFFFFFFFF,
            (self.state[6] + g) & 0xFFFFFFFF,
            (self.state[7] + h) & 0xFFFFFFFF,
        ]

    def digest(self) -> bytes:
        copy = deepcopy(self)
        copy._pad()
        copy._update()

        assert len(copy.buffer) == 0

        return b"".join(v.to_bytes(4, "big") for v in copy.state[:-1])
