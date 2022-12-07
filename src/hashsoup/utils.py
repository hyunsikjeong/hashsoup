def rol32(v: int, a: int) -> int:
    assert v.bit_length() <= 32
    a %= 32
    return ((v << a) | (v >> (32 - a))) & 0xFFFFFFFF
