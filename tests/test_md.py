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
