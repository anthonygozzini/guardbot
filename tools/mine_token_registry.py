#!/usr/bin/env python3
"""Mine a symbol -> contracts registry, so a token's NAME can never vouch for it.

`symbol()` is whatever the contract says about itself. Among 1209 real, actually-approved BSC
tokens, four different contracts call themselves "USDT" — one real, three impersonating it.
Any tool that prints the self-declared symbol is laundering a scam's disguise.

Identity therefore has to come from something the impersonator cannot cheaply fake. Liquidity
is that: the real USDT sits against tens of thousands of BNB, the fakes against pennies, and
buying enough liquidity to outrank the real one costs more than the scam earns. So for every
symbol we record which contracts claim it and how deep each one's pool is, straight from the
chain. The registry does not decide truth by name — it exposes the collision and the size gap.

Usage:  python3 tools/mine_token_registry.py [chain]
Writes: token_registry.json  {chain: {SYMBOL: [[address, native_reserve], ...]}}
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import approvals as A
from keccak import selector

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "token_registry.json")
UNIVERSE = os.path.join(BASE, "probe_universe.json")
BATCH = 300
KEEP_PER_SYMBOL = 6

WRAPPED = {
    "bsc": "0xbb4CdB9CbD36B01bD1cBaEBF2De08d9173bc095c",
    "ethereum": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "base": "0x4200000000000000000000000000000000000006",
    "arbitrum": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    "polygon": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
}
FACTORY = {
    "bsc": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    "ethereum": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
    "base": "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
    "arbitrum": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
    "polygon": "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32",
}
# V2 alone is not "the market". On Arbitrum, Base and Polygon most real volume sits in
# concentrated-liquidity V3 pools, so a V2-only measurement made the genuine native USDC look
# empty and flagged it as an impostor. Depth is summed across V2 and every V3 fee tier.
FACTORY_V3 = {
    "ethereum": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "arbitrum": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "polygon": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "optimism": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "base": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
    "bsc": "0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865",
}
FEE_TIERS = [100, 500, 3000, 10000]


def _dec_string(hexstr):
    d = hexstr[2:] if hexstr.startswith("0x") else hexstr
    if len(d) < 128:
        return None
    try:
        off = int(d[0:64], 16) * 2
        ln = int(d[off:off + 64], 16) * 2
        s = bytes.fromhex(d[off + 64:off + 64 + ln]).decode("utf-8", "ignore").strip()
        return s or None
    except Exception:
        return None


def _batched(rpc, calls):
    """Run aggregate3 calls in batches; yields (index, ok, returndata)."""
    for i in range(0, len(calls), BATCH):
        chunk = calls[i:i + BATCH]
        try:
            r = A._rpc(rpc, "eth_call",
                       [{"to": A.MULTICALL3, "data": A._enc_aggregate3(chunk)}, "latest"])
            if not r or r == "0x":
                continue
            for j, (ok, val) in enumerate(A._dec_aggregate3(r)):
                yield i + j, ok, val
        except Exception:
            continue


def mine(chain):
    weth = WRAPPED.get(chain)
    factory = FACTORY.get(chain)
    if not (weth and factory):
        raise SystemExit(f"no factory/wrapped-native configured for {chain}")
    with open(UNIVERSE) as f:
        uni = json.load(f)
    if chain not in uni:
        raise SystemExit(f"no probe universe for {chain} — run mine_probe_universe.py first")
    tokens = list(dict.fromkeys(t for t, _ in uni[chain]["pairs"]))
    rpc = A._chain_rpc(chain, A.EVM_CFG[chain])

    symbols = {}
    for idx, ok, val in _batched(rpc, [(t, True, selector("symbol()")) for t in tokens]):
        if ok:
            s = _dec_string(val)
            if s and len(s) <= 32:
                symbols[tokens[idx]] = s

    have = [t for t in tokens if t in symbols]
    # every venue this token might trade on: the V2 pair plus one V3 pool per fee tier
    lookups, owners = [], []
    for t in have:
        lookups.append((factory, True,
                        selector("getPair(address,address)") + A._addr32(t) + A._addr32(weth)))
        owners.append(t)
        f3 = FACTORY_V3.get(chain)
        if f3:
            for fee in FEE_TIERS:
                lookups.append((f3, True, selector("getPool(address,address,uint24)")
                                + A._addr32(t) + A._addr32(weth) + f"{fee:064x}"))
                owners.append(t)
    pools = []            # (token, pool_address)
    for idx, ok, val in _batched(rpc, lookups):
        if ok and val and val != "0x" and int(val, 16) != 0:
            pools.append((owners[idx], "0x" + val[-40:]))

    # depth = wrapped-native actually sitting in those pools, summed per token.
    reserves = {}
    calls = [(weth, True, selector("balanceOf(address)") + A._addr32(p)) for _, p in pools]
    for idx, ok, val in _batched(rpc, calls):
        if ok and val and val != "0x":
            try:
                reserves[pools[idx][0]] = reserves.get(pools[idx][0], 0) + int(val, 16)
            except ValueError:
                pass
    pairs = {t: p for t, p in pools}

    reg = {}
    for t, s in symbols.items():
        reg.setdefault(s.upper(), []).append([t, str(reserves.get(t, 0))])
    for s in reg:
        reg[s].sort(key=lambda e: -int(e[1]))
        reg[s] = reg[s][:KEEP_PER_SYMBOL]

    data = {}
    if os.path.exists(OUT):
        try:
            with open(OUT) as f:
                data = json.load(f)
        except Exception:
            data = {}
    collisions = {s: v for s, v in reg.items() if len(v) > 1}
    # stamp when mined; key is not a valid ticker, so it never collides with a symbol lookup
    reg["__mined_at__"] = int(time.time())
    data[chain] = reg
    with open(OUT, "w") as f:
        json.dump(data, f)
    print(f"{chain}: {len(symbols)} symbols read, {len(pairs)} priced, "
          f"{len(collisions)} symbols claimed by more than one contract -> {OUT}")
    for s, v in sorted(collisions.items(), key=lambda kv: -int(kv[1][0][1]))[:5]:
        print(f"   {s}: {len(v)} contracts, top pool {int(v[0][1])/1e18:.1f} native")


if __name__ == "__main__":
    mine(sys.argv[1] if len(sys.argv) > 1 else "bsc")
