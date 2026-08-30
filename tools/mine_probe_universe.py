#!/usr/bin/env python3
"""Mine the probe universe for chains that have no readable log history.

Some chains (BSC) refuse `eth_getLogs` on every free RPC, so an address's approval history
can't be read. But `eth_call` is never range-limited, and Multicall3 batches thousands of
`allowance()` calls into ONE request — so we can PROBE the present instead of reading the past.

To probe we need candidate (token, spender) pairs. We don't hardcode a guessed list and we
don't buy one: we mine it from the chain itself, by sampling real Approval events across
spread-out block windows and keeping the pairs that actually occur. Measured on BSC:
5.8k unique pairs exist; the top 4000 cover 98.2% of all observed approval activity.

Usage:  python3 tools/mine_probe_universe.py [chain] [--top N]
Writes: probe_universe.json  {chain: {"pairs": [[token, spender], ...], "meta": {...}}}
"""

import collections
import concurrent.futures
import json
import os
import sys
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from keccak import topic as _topic
OUT = os.path.join(BASE, "probe_universe.json")
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
# Candidate universes are mined per KIND, because an ERC-20 allowance, an NFT operator and a
# Permit2 grant are different objects with different events and different live checks.
KIND_TOPICS = {
    "erc20": ("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925", None),
    "nft": (_topic("ApprovalForAll(address,address,bool)"), None),
    "permit2": (_topic("Approval(address,address,address,uint160,uint48)"),
                "0x000000000022d473030f116ddee9f6b43ac78ba3"),
}
UA = "Mozilla/5.0 (guardbot/0.1; universe miner; read-only)"

# RPCs that serve getLogs on SMALL windows — enough to SAMPLE, not to scan history.
# Sampling is a one-off maintenance job, not something a user's look-up depends on.
SAMPLERS = {
    "bsc": ["https://56.rpc.thirdweb.com", "https://bsc.rpc.blxrbdn.com"],
    "ethereum": ["https://1.rpc.thirdweb.com", "https://eth.llamarpc.com",
                 "https://ethereum-rpc.publicnode.com"],
    "base": ["https://mainnet.base.org", "https://base.drpc.org", "https://8453.rpc.thirdweb.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc", "https://42161.rpc.thirdweb.com"],
    "polygon": ["https://rpc-mainnet.matic.quiknode.pro"],
    "optimism": ["https://mainnet.optimism.io", "https://10.rpc.thirdweb.com"],
}
# Busy chains return enormous windows (Polygon: 74k Approval events per 600 blocks), so the
# window is trimmed per chain to keep each sample response manageable.
WINDOW_BY_CHAIN = {"polygon": 60}
# Chains differ wildly in block time (Ethereum 12s vs Arbitrum 0.25s), so the stride is set
# per chain to spread the sample over a comparable span of TIME, not of blocks.
STRIDE_BY_CHAIN = {"ethereum": 3_000, "bsc": 40_000, "base": 60_000,
                   "arbitrum": 400_000, "polygon": 40_000, "optimism": 60_000}
WINDOW = 600        # blocks per sample window (small enough for a throttled RPC)
STRIDE = 40_000     # default gap between windows
WINDOWS = 24


def _rpc(url, method, params, timeout=30):
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def mine(chain, top_n=4000, kind="erc20"):
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
    topic0, only_address = KIND_TOPICS[kind]
    # NFT operator and Permit2 grants are far rarer than ERC-20 approvals. Widening the window
    # is not an option (the RPCs reject it), so rarity is met with MORE windows, packed closer.
    n_win, step = WINDOWS, stride
    if kind != "erc20":
        n_win, step = WINDOWS * 4, max(stride // 4, win + 1)
    windows = [(latest - i * step - win, latest - i * step) for i in range(n_win)]

    def fetch(w):
        flt = {"fromBlock": hex(w[0]), "toBlock": hex(w[1]), "topics": [topic0]}
        if only_address:
            flt["address"] = only_address
        for u in urls:                      # samplers disagree on limits — try each
            try:
                r = _rpc(u, "eth_getLogs", [flt])
                if isinstance(r.get("result"), list):
                    return r["result"]
            except Exception:
                continue
        return []

    pairs, total = collections.Counter(), 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for logs in ex.map(fetch, windows):
            for lg in logs:
                t = lg.get("topics") or []
                if len(t) < 3:
                    continue
                if kind == "permit2":
                    if len(t) < 4:
                        continue
                    # Permit2 indexes (owner, token, spender): the token is a topic, not the
                    # emitting contract, since Permit2 emits for every token it holds.
                    key = ("0x" + t[2][-40:], "0x" + t[3][-40:])
                else:
                    key = (lg["address"].lower(), "0x" + t[2][-40:])
                pairs[key] += 1
                total += 1
    if not total:
        raise SystemExit("sampled 0 events — sampler RPC unavailable")
    keep = pairs.most_common(top_n)
    covered = sum(c for _, c in keep) / total * 100

    data = {}
    if os.path.exists(OUT):
        try:
            with open(OUT) as f:
                data = json.load(f)
        except Exception:
            data = {}
    entry = {
        "pairs": [[t, s] for (t, s), _ in keep],
        "meta": {"sampled_events": total, "unique_pairs": len(pairs),
                 "kept": len(keep), "coverage_pct": round(covered, 1),
                 "windows": n_win, "window_blocks": win, "stride": step},
    }
    if kind == "erc20":
        entry["kinds"] = (data.get(chain) or {}).get("kinds", {})
        data[chain] = entry
    else:
        base_entry = data.get(chain) or {"pairs": [], "meta": {}}
        base_entry.setdefault("kinds", {})[kind] = entry
        data[chain] = base_entry
    with open(OUT, "w") as f:
        json.dump(data, f)
    print(f"{chain}/{kind}: sampled {total} events, {len(pairs)} unique pairs, kept {len(keep)} "
          f"covering {covered:.1f}% -> {OUT}")


if __name__ == "__main__":
    chain = sys.argv[1] if len(sys.argv) > 1 else "bsc"
    n = 4000
    if "--top" in sys.argv:
        n = int(sys.argv[sys.argv.index("--top") + 1])
    k = "erc20"
    if "--kind" in sys.argv:
        k = sys.argv[sys.argv.index("--kind") + 1]
    mine(chain, n, k)
