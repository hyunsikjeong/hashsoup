import hashlib
import random

from hashsoup import *

try:
    random.randbytes(1)
    randbytes = lambda rng, len_: rng.randbytes(len_)
except:
    randbytes = lambda rng, len_: bytes(rng.getrandbits(8) for _ in range(len_))


class TestSHA1:
    BASIC_CASES = [
        (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        ),
        (
            b"The quick brown fox jumps over the lazy cog",
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA1(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA1.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA1(target).digest() == hashlib.sha1(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA1.LEN_BLOCK)
            assert SHA1(target).digest() == hashlib.sha1(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA1(target).digest() == hashlib.sha1(target).digest()
