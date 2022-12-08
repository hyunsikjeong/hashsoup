import hashlib
import random

from hashsoup import *

try:
    random.randbytes(1)
    randbytes = lambda rng, len_: rng.randbytes(len_)
except:
    randbytes = lambda rng, len_: bytes(rng.getrandbits(8) for _ in range(len_))


class TestSHA3_224:
    BASIC_CASES = [
        (b"", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA3_224(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA3_224.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA3_224(target).digest() == hashlib.sha3_224(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA3_224.LEN_BLOCK)
            assert SHA3_224(target).digest() == hashlib.sha3_224(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA3_224(target).digest() == hashlib.sha3_224(target).digest()


class TestSHA3_256:
    BASIC_CASES = [
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA3_256(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA3_256.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA3_256(target).digest() == hashlib.sha3_256(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA3_256.LEN_BLOCK)
            assert SHA3_256(target).digest() == hashlib.sha3_256(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA3_256(target).digest() == hashlib.sha3_256(target).digest()


class TestSHA3_384:
    BASIC_CASES = [
        (
            b"",
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61"
            + "995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA3_384(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA3_384.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA3_384(target).digest() == hashlib.sha3_384(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA3_384.LEN_BLOCK)
            assert SHA3_384(target).digest() == hashlib.sha3_384(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA3_384(target).digest() == hashlib.sha3_384(target).digest()


class TestSHA3_512:
    BASIC_CASES = [
        (
            b"",
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHA3_512(inp).hexdigest() == out, f"Failed with {inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHA3_512.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHA3_512(target).digest() == hashlib.sha3_512(target).digest()

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHA3_512.LEN_BLOCK)
            assert SHA3_512(target).digest() == hashlib.sha3_512(target).digest()

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHA3_512(target).digest() == hashlib.sha3_512(target).digest()


class TestSHAKE_128:
    BASIC_CASES = [
        (
            b"",
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHAKE_128(256, inp).hexdigest() == out, f"Failed with {d, inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHAKE_128.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHAKE_128(256, target).digest() == hashlib.shake_128(target).digest(
                256 // 8
            )

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHAKE_128.LEN_BLOCK)
            assert SHAKE_128(256, target).digest() == hashlib.shake_128(target).digest(
                256 // 8
            )

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHAKE_128(256, target).digest() == hashlib.shake_128(target).digest(
                256 // 8
            )


class TestSHAKE_256:
    BASIC_CASES = [
        (
            b"",
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        ),
    ]

    def test_basic(self):
        for inp, out in self.BASIC_CASES:
            assert SHAKE_256(512, inp).hexdigest() == out, f"Failed with {d, inp}"

    def test_short(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0, SHAKE_256.LEN_BLOCK):
            target = randbytes(rng, len_)
            assert SHAKE_256(512, target).digest() == hashlib.shake_256(target).digest(
                512 // 8
            )

    def test_blockfit(self):
        rng = random.Random(b"test_seed")
        for len_ in range(1, 5):
            target = randbytes(rng, len_ * SHAKE_256.LEN_BLOCK)
            assert SHAKE_256(512, target).digest() == hashlib.shake_256(target).digest(
                512 // 8
            )

    def test_long(self):
        rng = random.Random(b"test_seed")
        for len_ in range(0x100, 0x1000, 0x100):
            target = randbytes(rng, len_)
            assert SHAKE_256(512, target).digest() == hashlib.shake_256(target).digest(
                512 // 8
            )
