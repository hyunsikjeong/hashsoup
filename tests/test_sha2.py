import hashlib
import random

from hashsoup import *

try:
    random.randbytes(1)
    randbytes = lambda rng, len_: rng.randbytes(len_)
except:
    randbytes = lambda rng, len_: bytes(rng.getrandbits(8) for _ in range(len_))


class TestSHA256:
    BASIC_CASES = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA256(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA256.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert len(SHA256(target).digest()) == len(hashlib.sha256(target).digest())
            assert SHA256(target).digest() == hashlib.sha256(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA256.LEN_BLOCK)
            assert SHA256(target).digest() == hashlib.sha256(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA256(target).digest() == hashlib.sha256(target).digest()
