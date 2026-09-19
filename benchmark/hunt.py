#!/usr/bin/env python3
"""Find candidates for the benchmark set and label them with sources that are not GuardBot.

Live honeypots are rare and short-lived: most fresh launches are dead within hours, and the
labelers lag behind the chain. So this is a two-step hunt. Today's new pools are collected and
saved; a later run labels the saved candidates with BOTH GoPlus and honeypot.is, and prints the
ones where the sources agree and the pool is still alive — those are the only ones worth adding
to set.json as traps. Disagreements are printed too, and left out.

Run:   python3 benchmark/hunt.py collect [bsc|base] [--pages N]   # save fresh candidates
       python3 benchmark/hunt.py label                             # label what was collected
"""

import argparse
import datetime
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = os.path.join(HERE, "candidates.json")
UA = "guardbot-benchmark"
GOPLUS_IDS = {"bsc": 56, "base": 8453, "ethereum": 1, "arbitrum": 42161, "polygon": 137}
GECKO_NET = {"bsc": "bsc", "base": "base", "ethereum": "eth", "arbitrum": "arbitrum", "polygon": "polygon_pos"}


def _get(url, tries=3, backoff=6):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.load(r)
            if d.get("code") == 4029:        # GoPlus: too many requests
                raise RuntimeError("rate limited")
            return d
        except Exception:
            if i == tries - 1:
                return None
            time.sleep(backoff * (i + 1))


def collect(chain, pages):
    saved = json.load(open(CANDIDATES)) if os.path.exists(CANDIDATES) else {}
    new = 0
    for pg in range(1, pages + 1):
        d = _get(f"https://api.geckoterminal.com/api/v2/networks/{GECKO_NET[chain]}/new_pools?page={pg}")
        for p in (d or {}).get("data", []):
            at = p["attributes"]
            base = ((p.get("relationships") or {}).get("base_token", {}).get("data") or {}).get("id", "")
            addr = base.split("_", 1)[-1].lower()
            key = f"{chain}:{addr}"
            if addr.startswith("0x") and len(addr) == 42 and key not in saved:
                saved[key] = {"pool": at.get("name"), "reserve_usd_at_collect": float(at.get("reserve_in_usd") or 0),
                              "created": at.get("pool_created_at"),
                              "collected": datetime.date.today().isoformat()}
                new += 1
        time.sleep(3)   # GeckoTerminal allows ~30 requests a minute
    json.dump(saved, open(CANDIDATES, "w"), indent=0)
    print(f"{chain}: {new} new candidates, {len(saved)} saved in total")


def label_one(chain, addr):
    cid = GOPLUS_IDS[chain]
    out = {}
    d = _get(f"https://api.gopluslabs.io/api/v1/token_security/{cid}?contract_addresses={addr}")
    t = ((d or {}).get("result") or {}).get(addr)
    if t:
        out["goplus"] = {"symbol": t.get("token_symbol"), "is_honeypot": t.get("is_honeypot"),
                         "sell_tax": t.get("sell_tax"), "holders": t.get("holder_count"),
                         "liquidity_usd": round(sum(float(x.get("liquidity") or 0) for x in (t.get("dex") or [])))}
    time.sleep(2)
    h = _get(f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID={cid}")
    if h:
        out["honeypotis"] = {"symbol": (h.get("token") or {}).get("symbol"),
                             "is_honeypot": (h.get("honeypotResult") or {}).get("isHoneypot"),
                             "reason": ((h.get("honeypotResult") or {}).get("honeypotReason") or "")[:60],
                             "sell_tax": (h.get("simulationResult") or {}).get("sellTax"),
                             "liquidity_usd": round(float((h.get("pair") or {}).get("liquidity") or 0))}
    time.sleep(1.5)
    return out


def label():
    saved = json.load(open(CANDIDATES))
    today = datetime.date.today().isoformat()
    agreed, disputed = [], []
    for i, (key, meta) in enumerate(saved.items()):
        chain, addr = key.split(":", 1)
        lab = label_one(chain, addr)
        meta["labels"] = lab
        meta["labeled"] = today
        g, h = lab.get("goplus") or {}, lab.get("honeypotis") or {}
        gp, hp = str(g.get("is_honeypot")) == "1", h.get("is_honeypot") is True
        alive = max(g.get("liquidity_usd") or 0, h.get("liquidity_usd") or 0) >= 1000
        if gp and hp and alive:
            agreed.append((key, g.get("symbol"), g.get("liquidity_usd"), h.get("liquidity_usd")))
        elif (gp or hp) and alive:
            disputed.append((key, g.get("symbol") or h.get("symbol"), gp, hp, h.get("reason")))
        if i % 20 == 0:
            json.dump(saved, open(CANDIDATES, "w"), indent=0)
            print(f"{i}/{len(saved)} labeled", file=sys.stderr, flush=True)
    json.dump(saved, open(CANDIDATES, "w"), indent=0)
    print(f"\nTraps both sources agree on, pool alive — add these to set.json with source 'goplus+honeypot.is':")
    for k, s, gl, hl in agreed:
        print(f"  {k}  {s}  goplus ${gl}  honeypot.is ${hl}")
    print(f"\nDisputed (one source only) — do NOT add:")
    for k, s, gp, hp, why in disputed:
        print(f"  {k}  {s}  goplus={'honeypot' if gp else 'clean'}  honeypot.is={'honeypot' if hp else 'clean'}  {why}")
    print(f"\n{len(saved)} candidates, {len(agreed)} agreed, {len(disputed)} disputed", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("chain", nargs="?", default="bsc", choices=sorted(GECKO_NET))
    c.add_argument("--pages", type=int, default=5)
    sub.add_parser("label")
    a = ap.parse_args()
    if a.cmd == "collect":
        collect(a.chain, a.pages)
    else:
        label()


if __name__ == "__main__":
    main()
