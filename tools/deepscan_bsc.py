#!/usr/bin/env python3
"""Deep approval scan for BSC — by walking the wallet's own transactions, not the chain's logs.

BSC publishes no free full-range log source (re-verified 2026-09: Etherscan's free tier excludes
chainid 56, Routescan and Blockscout don't serve it, and free RPCs cap eth_getLogs at 5k/1k/50
blocks — a full-history sweep would be ~65k calls). The way out is a fact about the EVM itself:
an ERC-20 approve() or setApprovalForAll() is ALWAYS a transaction signed by the owner, so the
owner's own transaction list contains every classic approval by construction. And that list can
be recovered without any indexer: eth_getTransactionCount at historical blocks (thirdweb's free
endpoint serves archive state) is monotonic in the nonce, so each of the wallet's N transactions
is found by binary search — ~N*27 light calls instead of tens of thousands of getLogs.

What this cannot see, stated plainly: gasless EIP-2612 permits executed by a relayer (no owner
transaction exists; the Permit2 variety is already covered by present-state probing).

Usage: python3 tools/deepscan_bsc.py <address>
Found (kind, token, spender) pairs go into the local index; the normal scan then resolves their
LIVE allowance instantly, forever, like any other chain.
"""

import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import approvals as A
import revoke as R

ARCHIVE_RPC = "https://56.rpc.thirdweb.com"
SEL = {"0x095ea7b3": "erc20",        # approve(spender, amount)
       "0x39509351": "erc20",        # increaseAllowance(spender, added)
       "0xa22cb465": "nft_operator", # setApprovalForAll(operator, bool)
       "0x87517c45": "permit2"}      # Permit2.approve(token, spender, amount, expiration)
_GATE = [0.0]


def _rpc(method, params, tries=4):
    for att in range(tries):
        wait = _GATE[0] - time.time()
        if wait > 0:
            time.sleep(wait)
        _GATE[0] = time.time() + 0.28
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        req = urllib.request.Request(ARCHIVE_RPC, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "guardbot-deepscan"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.load(r)
            if "result" in d:
                return d["result"]
        except Exception:
            pass
        time.sleep(1.0 * (att + 1))
    raise RuntimeError(f"{method} failed after {tries} tries")


def nonce_at(addr, block):
    return int(_rpc("eth_getTransactionCount", [addr, hex(block)]), 16)


def main(address):
    addr = address.strip()
    latest = int(_rpc("eth_blockNumber", []), 16)
    total = nonce_at(addr, latest)
    print(f"wallet has sent {total} transactions on BSC — walking every one of them")
    if total == 0:
        print("never acted on BSC: nothing to find")
        return 0
    pairs, lo = set(), 1
    blocks = {}
    t0 = time.time()
    for k in range(1, total + 1):
        a, b = lo, latest
        while a < b:                       # first block where nonce >= k
            m = (a + b) // 2
            if nonce_at(addr, m) >= k:
                b = m
            else:
                a = m + 1
        lo = a
        blk = blocks.get(a)
        if blk is None:
            blk = _rpc("eth_getBlockByNumber", [hex(a), True]) or {}
            blocks[a] = blk
        for tx in blk.get("transactions", []):
            if (tx.get("from") or "").lower() != addr.lower() or int(tx.get("nonce", "0x0"), 16) != k - 1:
                continue
            data = tx.get("input") or ""
            kind = SEL.get(data[:10])
            to = (tx.get("to") or "").lower()
            if kind == "permit2" and to == R.PERMIT2.lower() and len(data) >= 10 + 128:
                pairs.add(("permit2", "0x" + data[10:74][-40:], "0x" + data[74:138][-40:]))
                print(f"  tx {k:>3} block {a:,}: Permit2 approve")
            elif kind in ("erc20", "nft_operator") and len(data) >= 10 + 64:
                pairs.add((kind, to, "0x" + data[10:74][-40:]))
                print(f"  tx {k:>3} block {a:,}: {kind} approve on {to[:10]}… -> 0x{data[10:74][-40:][:8]}…")
        if k % 5 == 0:
            print(f"  … {k}/{total} txs walked, {len(pairs)} approval pairs, {time.time()-t0:.0f}s", flush=True)
    print(f"done in {time.time()-t0:.0f}s: {len(pairs)} approval pairs from {total} transactions")
    if pairs:
        old, last = A._cached("bsc", addr)
        A._store("bsc", addr, old | pairs, last or 0)
        print("stored into the local index — the normal scan now resolves their live allowances")
    for k_, t_, s_ in sorted(pairs):
        print(f"  {k_:12} token {t_}  spender {s_}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
