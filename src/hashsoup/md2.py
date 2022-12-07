from copy import deepcopy

from .hasher import Hasher


# Implementation mostly from https://datatracker.ietf.org/doc/html/rfc1115#section-4.2
class MD2(Hasher):
    # Stop Black reformatting these poor arrays
    # fmt: off
    CONST_S = [
         41, 46, 67,201,162,216,124,  1, 61, 54, 84,161,236,240,  6, 19,
         98,167,  5,243,192,199,115,140,152,147, 43,217,188, 76,130,202,
         30,155, 87, 60,253,212,224, 22,103, 66,111, 24,138, 23,229, 18,
        190, 78,196,214,218,158,222, 73,160,251,245,142,187, 47,238,122,
        169,104,121,145, 21,178,  7, 63,148,194, 16,137, 11, 34, 95, 33,
        128,127, 93,154, 90,144, 50, 39, 53, 62,204,231,191,247,151,  3,
        255, 25, 48,179, 72,165,181,209,215, 94,146, 42,172, 86,170,198,
         79,184, 56,210,150,164,125,182,118,252,107,226,156,116,  4,241,
         69,157,112, 89,100,113,135, 32,134, 91,207,101,230, 45,168,  2,
         27, 96, 37,173,174,176,185,246, 28, 70, 97,105, 52, 64,126, 15,
         85, 71,163, 35,221, 81,175, 58,195, 92,249,206,186,197,234, 38,
         44, 83, 13,110,133, 40,132,  9,211,223,205,244, 65,129, 77, 82,
        106,220, 55,200,108,193,171,250, 36,225,123,  8, 12,189,177, 74,
        120,136,149,139,227, 99,232,109,233,203,213,254, 59,  0, 29, 57,
        242,239,183, 14,102, 88,208,228,166,119,114,248,235,117, 75, 10,
         49, 68, 80,180,143,237, 31, 26,219,153,141, 51,159, 17,131, 20,
    ]

    LEN_STATE = 32
    LEN_BLOCK = 16
    # fmt: on

    def __init__(self, inp: bytes = None, state: bytes = None, digested: int = None):
        # This allows users to modify constants when they want
        self.S = self.CONST_S[:]
        self.L = 0
        if state:
            assert (
                len(state) == self.LEN_STATE
            ), f"The state must be {self.LEN_STATE}-byte"
            self.D = bytearray(state[:16]) + bytearray(32)
            self.C = bytearray(state[16:])
        else:
            self.D = bytearray(48)
            self.C = bytearray(16)

        self.buffer = bytearray()

        if inp:
            self.update(inp)

    @classmethod
    def get_padding(cls, len_: int) -> bytes:
        c = cls.LEN_BLOCK - (len_ % cls.LEN_BLOCK)
        return bytes(c for _ in range(c))

    def _pad(self):
        self.buffer += self.get_padding(len(self.buffer))

    def update(self, inp: bytes) -> None:
        self.buffer += inp
        self._update()

    def _update(self):
        while len(self.buffer) >= self.LEN_BLOCK:
            self._update_chunk(self.buffer[: self.LEN_BLOCK])
            self.buffer = self.buffer[self.LEN_BLOCK :]

    def _update_chunk(self, chunk: bytes):
        for i, c in enumerate(chunk):
            self.D[i + 16] = c
            self.D[i + 32] = c ^ self.D[i]
            self.C[i] ^= self.S[0xFF & (c ^ self.L)]
            self.L = self.C[i]

        t = 0
        for j in range(18):
            for i in range(48):
                self.D[i] ^= self.S[t]
                t = self.D[i]
            t = (t + j) & 0xFF

    def digest(self) -> bytes:
        copy = deepcopy(self)
        copy._pad()
        copy._update()
        copy.update(bytes(copy.C))

        assert len(copy.buffer) == 0

        return bytes(copy.D[:16])
