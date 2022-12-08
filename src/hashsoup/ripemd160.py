from copy import deepcopy

from .hasher import Hasher
from .utils import rol32


# Implementation mostly from https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/
class RIPEMD160(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_s1 = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    ]

    CONST_g1 = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    ]

    CONST_C1 = [
        0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
    ]

    CONST_s2 = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    ]

    CONST_g2 = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    ]

    CONST_C2 = [
        0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0
    ]

    CONST_STATE = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    ]

    LEN_STATE = 20
    LEN_BLOCK = 64
    # fmt: on

    def __init__(self, inp: bytes = None, state: bytes = None, digested: int = None):
        # This allows users to modify constants when they want
        self.s1, self.s2 = self.CONST_s1[:], self.CONST_s2[:]
        self.g1, self.g2 = self.CONST_g1[:], self.CONST_g2[:]
        self.C1, self.C2 = self.CONST_C1[:], self.CONST_C2[:]

        if state:
            assert (
                len(state) == self.LEN_STATE
            ), f"The state must be {self.LEN_STATE}-byte"
            self.state = [
                int.from_bytes(state[i : i + 4], "little")
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

        # Round 1-5
        A, B, C, D, E = self.state
        for i in range(80):
            if i < 16:
                F = B ^ C ^ D
            elif i < 32:
                F = (B & C) | (~B & D)
            elif i < 48:
                F = (B | ~C) ^ D
            elif i < 64:
                F = (B & D) | (C & ~D)
            else:
                F = B ^ (C | ~D)

            A = (F + A + M[self.g1[i]] + self.C1[i // 16]) & 0xFFFFFFFF
            A = (rol32(A, self.s1[i]) + E) & 0xFFFFFFFF
            C = rol32(C, 10)
            A, E, D, C, B = E, D, C, B, A

        # Parallel round 1-5
        AA, BB, CC, DD, EE = self.state
        for i in range(80):
            if i < 16:
                F = BB ^ (CC | ~DD)
            elif i < 32:
                F = (BB & DD) | (CC & ~DD)
            elif i < 48:
                F = (BB | ~CC) ^ DD
            elif i < 64:
                F = (BB & CC) | (~BB & DD)
            else:
                F = BB ^ CC ^ DD

            AA = (F + AA + M[self.g2[i]] + self.C2[i // 16]) & 0xFFFFFFFF
            AA = (rol32(AA, self.s2[i]) + EE) & 0xFFFFFFFF
            CC = rol32(CC, 10)
            AA, EE, DD, CC, BB = EE, DD, CC, BB, AA

        self.state = [
            (self.state[1] + C + DD) & 0xFFFFFFFF,
            (self.state[2] + D + EE) & 0xFFFFFFFF,
            (self.state[3] + E + AA) & 0xFFFFFFFF,
            (self.state[4] + A + BB) & 0xFFFFFFFF,
            (self.state[0] + B + CC) & 0xFFFFFFFF,
        ]

    def digest(self) -> bytes:
        copy = deepcopy(self)
        copy._pad()
        copy._update()

        assert len(copy.buffer) == 0

        return b"".join(v.to_bytes(4, "little") for v in copy.state)
