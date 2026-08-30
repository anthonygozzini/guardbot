#!/usr/bin/env python3
"""Mine a spender ESTABLISHMENT signal from the chain — how widely used a spender is.

A human name for a spender ("deBridge", "Rango") is off-chain data; it cannot be derived. But
whether a spender is an established protocol or a random drainer CAN be, and un-fakeably: count
how many DISTINCT wallets have approved it. Thousands of independent approvers is a protocol the
whole market trusts; Sybil-ing thousands of distinct approving wallets costs real gas, so the
signal cannot be bought cheaply. This is the dynamic complement to the small curated name list:
it lets a legit-but-unnamed spender stop reading "unknown / high" without anyone labelling it.

Reuses the samplers and windows of mine_probe_universe.py — the same Approval events, read for a
different field (topic1 = owner, instead of topic2 = spender + emitting contract = token).

Usage:  python3 tools/mine_spender_registry.py [chain]
Writes: spender_registry.json  {chain: {"spenders": {spender: distinct_approvers}, "meta": {...}}}
"""

import collections
import concurrent.futures
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mine_probe_universe import (APPROVAL_TOPIC, SAMPLERS, STRIDE, STRIDE_BY_CHAIN, WINDOW,
                                 WINDOW_BY_CHAIN, WINDOWS, _rpc)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "spender_registry.json")
KEEP = 3000   # keep the most-approved spenders; the long tail is genuinely "unknown"


def mine(chain):
    urls = SAMPLERS.get(chain)
    if not urls:
        raise SystemExit(f"no sampler RPC configured for {chain}")
    latest, url = 0, None
    for u in urls:
        try:
            latest = int(_rpc(u, "eth_blockNumber", [], 15)["result"], 16)
            url = u
            break
        except Exception:
            continue
    if not url:
        raise SystemExit(f"{chain}: no sampler RPC reachable")
    stride = STRIDE_BY_CHAIN.get(chain, STRIDE)
    win = WINDOW_BY_CHAIN.get(chain, WINDOW)
    windows = [(latest - i * stride - win, latest - i * stride) for i in range(WINDOWS)]

    def fetch(w):
        for u in urls:
            try:
                r = _rpc(u, "eth_getLogs", [{"fromBlock": hex(w[0]), "toBlock": hex(w[1]),
                                             "topics": [APPROVAL_TOPIC]}])
                if isinstance(r.get("result"), list):
                    return r["result"]
            except Exception:
                continue
        return []

    approvers = collections.defaultdict(set)   # spender -> set of distinct owner addresses
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for logs in ex.map(fetch, windows):
            for lg in logs:
                t = lg.get("topics") or []
                if len(t) < 3:
                    continue
                owner = "0x" + t[1][-40:]
                spender = "0x" + t[2][-40:]
                approvers[spender].add(owner)
    if not approvers:
        raise SystemExit("sampled 0 events — sampler RPC unavailable")

    breadth = {s: len(o) for s, o in approvers.items()}
    top = sorted(breadth.items(), key=lambda kv: -kv[1])[:KEEP]
    all_owners = set()
    for o in approvers.values():
        all_owners |= o

    data = {}
    if os.path.exists(OUT):
        try:
            with open(OUT) as f:
                data = json.load(f)
        except Exception:
            data = {}
    data[chain] = {
        "spenders": {s: n for s, n in top},
        "meta": {"unique_spenders": len(breadth), "distinct_owners": len(all_owners),
                 "kept": len(top), "max_breadth": top[0][1] if top else 0,
                 "windows": WINDOWS, "window_blocks": win, "stride": stride},
    }
    with open(OUT, "w") as f:
        json.dump(data, f)
    print(f"{chain}: {len(breadth)} spenders, {len(all_owners)} distinct owners; kept top "
          f"{len(top)} (max breadth {top[0][1] if top else 0}) -> {OUT}")


if __name__ == "__main__":
    mine(sys.argv[1] if len(sys.argv) > 1 else "bsc")
