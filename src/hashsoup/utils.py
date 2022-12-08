from __future__ import annotations
from functools import reduce


def rol(v: int, a: int, mod: int) -> int:
    assert v.bit_length() <= mod
    a %= mod
    return ((v << a) | (v >> (mod - a))) & ((1 << mod) - 1)


def rol32(v: int, a: int) -> int:
    return rol(v, a, 32)


def ror32(v: int, a: int) -> int:
    return rol(v, 32 - a, 32)


def ror64(v: int, a: int) -> int:
    return rol(v, 64 - a, 64)


def xorsum(l: list[int]) -> int:
    return reduce(lambda x, y: x ^ y, l, 0)
