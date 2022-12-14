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


class TestSHA512:
    BASIC_CASES = [
        (
            b"",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA512(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA512.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA512(target).digest() == hashlib.sha512(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA512.LEN_BLOCK)
            assert SHA512(target).digest() == hashlib.sha512(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA512(target).digest() == hashlib.sha512(target).digest()


class TestSHA384:
    BASIC_CASES = [
        (
            b"",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA384(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA384.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA384(target).digest() == hashlib.sha384(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA384.LEN_BLOCK)
            assert SHA384(target).digest() == hashlib.sha384(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA384(target).digest() == hashlib.sha384(target).digest()
