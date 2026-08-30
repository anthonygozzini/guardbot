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
OUT = os.path.join(BASE, "probe_universe.json")
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
UA = "Mozilla/5.0 (guardbot/0.1; universe miner; read-only)"

# RPCs that serve getLogs on SMALL windows — enough to sample, not to scan history.
SAMPLERS = {
    "bsc": ["https://56.rpc.thirdweb.com"],
}
WINDOW = 600        # blocks per sample window (small enough for a throttled RPC)
STRIDE = 40_000     # gap between windows, to spread the sample over recent history
WINDOWS = 24


def _rpc(url, method, params, timeout=30):
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def mine(chain, top_n=4000):
    urls = SAMPLERS.get(chain)
    if not urls:
        raise SystemExit(f"no sampler RPC configured for {chain}")
    url = urls[0]
    latest = int(_rpc(url, "eth_blockNumber", [])["result"], 16)
    windows = [(latest - i * STRIDE - WINDOW, latest - i * STRIDE) for i in range(WINDOWS)]

    def fetch(w):
        try:
            return _rpc(url, "eth_getLogs", [{"fromBlock": hex(w[0]), "toBlock": hex(w[1]),
                                              "topics": [APPROVAL_TOPIC]}]).get("result") or []
        except Exception:
            return []

    pairs, total = collections.Counter(), 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for logs in ex.map(fetch, windows):
            for lg in logs:
                t = lg.get("topics") or []
                if len(t) < 3:
                    continue
                pairs[(lg["address"].lower(), "0x" + t[2][-40:])] += 1
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
    data[chain] = {
        "pairs": [[t, s] for (t, s), _ in keep],
        "meta": {"sampled_events": total, "unique_pairs": len(pairs),
                 "kept": len(keep), "coverage_pct": round(covered, 1),
                 "windows": WINDOWS, "window_blocks": WINDOW, "stride": STRIDE},
    }
    with open(OUT, "w") as f:
        json.dump(data, f)
    print(f"{chain}: sampled {total} events, {len(pairs)} unique pairs, kept {len(keep)} "
          f"covering {covered:.1f}% -> {OUT}")


if __name__ == "__main__":
    chain = sys.argv[1] if len(sys.argv) > 1 else "bsc"
    n = 4000
    if "--top" in sys.argv:
        n = int(sys.argv[sys.argv.index("--top") + 1])
    mine(chain, n)
