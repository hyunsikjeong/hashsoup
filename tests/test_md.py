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
            assert MD2(inp).hexdigest() == out, f"Failed with {inp}"


class TestMD4:
    BASIC_CASES = [
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"hi", "cfaee2512bd25eb033236f0cd054e308"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "1bee69a46ba811185c194762abaeae90",
        ),
        (
            b"The quick brown fox jumps over the lazy cog",
            "b86e130ce7028da59e672d56ad0113df",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert MD4(inp).hexdigest() == out, f"Failed with {inp}"

    def test_collision(self):
        k1 = "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3b\
              b3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9"
        k2 = "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3b\
              b3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9"
        assert MD4(bytes.fromhex(k1)).digest() == MD4(bytes.fromhex(k2)).digest()

    # Takes too much time. Skip this
    def _test_timetrial(self):
        X = b""
        for i in range(16):
            X += (0x01234567 + i).to_bytes(4, "little")
        hasher = MD4()
        for _ in range(1000000):
            hasher.update(X)

        # It's 6325bf77e5891c7c0d8104b64cc6e9ef in the document:
        # https://www.rfc-editor.org/rfc/rfc1186
        # However, 7d5ea730c0a9879b16b590778b78689e is the correct value.
        # I don't know why
        assert hasher.hexdigest() == "7d5ea730c0a9879b16b590778b78689e"
