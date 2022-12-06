from hashsoup import *
import hashlib
import random

try:
    random.randbytes(1)
    randbytes = lambda rng, len_: rng.randbytes(len_)
except:
    randbytes = lambda rng, len_: bytes(rng.getrandbits(8) for _ in range(len_))


class TestMD5:
    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, MD5.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert MD5(target).digest() == hashlib.md5(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_)
            assert MD5(target).digest() == hashlib.md5(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert MD5(target).digest() == hashlib.md5(target).digest()


class TestMD2:
    BASIC_CASES = [
        (b"", "8350e5a3e24c153df2275c9f80692773"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "03d85a0d629d2c442e987525319fc471",
        ),
        (
            b"The quick brown fox jumps over the lazy cog",
            "6b890c9292668cdbbfda00a4ebf31f05",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert MD2(inp).hexdigest() == out
