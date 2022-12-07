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


class TestSHA224:
    BASIC_CASES = [
        (b"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
        ),
        (
            b"The quick brown fox jumps over the lazy dog.",
            "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA224(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA224.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA224(target).digest() == hashlib.sha224(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA224.LEN_BLOCK)
            assert SHA224(target).digest() == hashlib.sha224(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA224(target).digest() == hashlib.sha224(target).digest()
