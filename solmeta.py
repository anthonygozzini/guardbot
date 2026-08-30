#!/usr/bin/env python3
"""Solana token names, derived rather than looked up.

An SPL mint account carries decimals and authorities but no name: the human-readable part
lives in a separate Metaplex Metadata account, at an address *derived* from the mint. So the
symbol is not something to fetch from a metadata service — it is something to compute, then
read straight off the chain, which is the same stance the rest of GuardBot takes.

Deriving it needs three things Python doesn't ship: base58, Solana's program-derived-address
rule, and the ed25519 curve test that rule depends on (a PDA is by definition a point that is
NOT on the curve). All three are here, in stdlib only.

  token_meta(rpc, mint) -> {"symbol": …, "name": …} | None
"""

import base64
import hashlib
import json
import urllib.request

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
METADATA_PROGRAM = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
PDA_MARKER = b"ProgramDerivedAddress"
UA = "Mozilla/5.0 (guardbot/0.1; solana metadata; read-only)"


def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


# ---- ed25519 point decompression, only to answer "is this 32-byte value on the curve?" ----
_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _on_curve(b):
    """True if the 32 bytes decode to a valid ed25519 point. Solana defines a PDA as an address
    for which this is False — that is what makes it unsignable, and it is the whole reason the
    derivation loops over a bump byte instead of hashing once."""
    if len(b) != 32:
        return False
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= _P:
        return False
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    try:
        x = (u * pow(v, _P - 2, _P)) % _P
        x = pow(x, (_P + 3) // 8, _P)
    except Exception:
        return False
    if (v * x * x - u) % _P != 0:
        x = (x * _SQRT_M1) % _P
        if (v * x * x - u) % _P != 0:
            return False
    if x == 0 and sign:
        return False
    return True


def find_program_address(seeds, program_id):
    """Solana's PDA rule: hash the seeds with a decreasing bump until the result is off-curve."""
    prog = b58decode(program_id)
    for bump in range(255, -1, -1):
        h = hashlib.sha256(b"".join(seeds) + bytes([bump]) + prog + PDA_MARKER).digest()
        if not _on_curve(h):
            return b58encode(h), bump
    return None, None


def metadata_pda(mint):
    prog = b58decode(METADATA_PROGRAM)
    addr, _ = find_program_address([b"metadata", prog, b58decode(mint)], METADATA_PROGRAM)
    return addr


def _rpc(url, method, params, timeout=20):
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                              "params": params}).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _parse_metadata(raw):
    """Metadata layout: key(1) | update_authority(32) | mint(32) | name | symbol | uri,
    each string a 4-byte LE length followed by fixed padding the on-chain program writes."""
    try:
        off = 1 + 32 + 32
        out = {}
        for field in ("name", "symbol", "uri"):
            ln = int.from_bytes(raw[off:off + 4], "little")
            off += 4
            if ln > 400 or off + ln > len(raw):
                return None
            out[field] = raw[off:off + ln].split(b"\x00")[0].decode("utf-8", "ignore").strip()
            off += ln
        return out
    except Exception:
        return None


def token_meta(rpc, mint):
    """{'symbol','name'} for an SPL mint, or None when the token has no metadata account."""
    pda = metadata_pda(mint)
    if not pda:
        return None
    try:
        r = _rpc(rpc, "getAccountInfo", [pda, {"encoding": "base64"}])
    except Exception:
        return None
    val = ((r.get("result") or {}).get("value")) or None
    if not val:
        return None
    data = val.get("data")
    if not isinstance(data, list) or not data:
        return None
    try:
        meta = _parse_metadata(base64.b64decode(data[0]))
    except Exception:
        return None
    if not meta or not (meta.get("symbol") or meta.get("name")):
        return None
    return {"symbol": meta.get("symbol") or None, "name": meta.get("name") or None}


if __name__ == "__main__":
    import sys
    url = "https://api.mainnet-beta.solana.com"
    mints = sys.argv[1:] or ["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                             "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"]
    for m in mints:
        print(f"{m[:12]}… pda={metadata_pda(m)[:12]}… -> {token_meta(url, m)}")
