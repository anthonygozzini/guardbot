#!/usr/bin/env python3
"""keccak256 in pure Python — no dependencies.

Needed to compute function selectors, event topics, storage slots and CREATE2 addresses
ourselves. Python's hashlib ships SHA3-256, which is NOT keccak256 (different padding),
so the Ethereum hash has to be implemented here. Verified against known vectors in
`python3 keccak.py`.
"""

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_RO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M


def _f(a):
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _RO[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= _RC[rnd]
    return a


def keccak256(data):
    """keccak256 digest (32 bytes) of `data` (bytes)."""
    rate = 136
    p = bytearray(data) + b"\x01"
    while len(p) % rate:
        p += b"\x00"
    p[-1] ^= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        blk = p[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(blk[i * 8:i * 8 + 8], "little")
        a = _f(a)
    out = b""
    for i in range(rate // 8):
        out += a[i % 5][i // 5].to_bytes(8, "little")
        if len(out) >= 32:
            break
    return out[:32]


def selector(signature):
    """4-byte function selector, e.g. 'transfer(address,uint256)' -> '0xa9059cbb'."""
    return "0x" + keccak256(signature.encode()).hex()[:8]


def topic(signature):
    """32-byte event topic, e.g. 'Approval(address,address,uint256)'."""
    return "0x" + keccak256(signature.encode()).hex()


if __name__ == "__main__":
    vectors = [
        (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    ]
    ok = all(keccak256(a).hex() == b for a, b in vectors)
    ok = ok and selector("transfer(address,uint256)") == "0xa9059cbb"
    ok = ok and selector("balanceOf(address)") == "0x70a08231"
    ok = ok and selector("approve(address,uint256)") == "0x095ea7b3"
    print("keccak256 self-test:", "PASS" if ok else "FAIL")
