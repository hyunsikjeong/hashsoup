import hashlib
import random

from hashsoup import *

try:
    random.randbytes(1)
    randbytes = lambda rng, len_: rng.randbytes(len_)
except:
    randbytes = lambda rng, len_: bytes(rng.getrandbits(8) for _ in range(len_))


class TestRIPEMD160:
    BASIC_CASES = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        )
        # 1 million times "a": 52783243c1697bdbe16d37f97f68f08325dc1528
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert RIPEMD160(inp).hexdigest() == out, f"Failed with {inp}"


class TestRIPEMD128:
    BASIC_CASES = [
        (b"", "cdf26213a150dc3ecb610f18f6b38b46"),
        (b"a", "86be7afa339d0fc7cfc785e72f578d33"),
        (b"abc", "c14a12199c66e4ba84636b0f69144c77"),
        (b"message digest", "9e327b3d6e523062afc1132d7df9d1b8"),
        (b"abcdefghijklmnopqrstuvwxyz", "fd2aa607f71dc8f510714922b371834e"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "a1aa0689d0fafa2ddc22e88b49133a06",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d1e959eb179c911faea4624c60c5c702",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "3f45ef194732c2dbb2c4a2c769795fa3",
        )
        # 1 million times "a": 4a7f5723f954eba1216c9d8f6320431f
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert RIPEMD128(inp).hexdigest() == out, f"Failed with {inp}"
