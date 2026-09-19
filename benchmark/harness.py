#!/usr/bin/env python3
"""Measure GuardBot instead of trusting it: replay check_token over a fixed set of tokens whose
nature is established by someone else, and publish how often the verdict is wrong.

Ground truth is never GuardBot's own opinion. A token is in the set as a TRAP only if an
independent source says so — GoPlus's is_honeypot flag, recorded with the date, or a fact anyone
can read on chain (symbol() claims to be USDT while the canonical USDT lives elsewhere). A token is
in the set as SAFE only if it is a blue chip whose tradability nobody disputes.

Traps die: liquidity gets pulled and the pool empties. A dead trap is blocked by anyone, so it
proves nothing; the harness reports those separately and keeps them OUT of the detection rate.

Run:   python3 benchmark/harness.py            # writes benchmark/results.json, prints the table
       python3 benchmark/harness.py --relabel  # also re-asks GoPlus whether each trap still is one
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

SET_PATH = os.path.join(HERE, "set.json")
RESULTS_PATH = os.path.join(HERE, "results.json")

# The failures that demonstrate a trap by trading it. "liquidity" is not one: an empty pool is a
# death, not a detection, and any sell "failure" on top of it proves nothing.
TRAP_FAILS = {"honeypot", "tax", "buy"}
GOPLUS_CHAIN_IDS = {"bsc": 56, "ethereum": 1, "base": 8453, "arbitrum": 42161, "polygon": 137}


def classify(expect, result, kind=None):
    """One outcome per token, from the verdict, which checks failed, and what kind of trap it is."""
    if not result or result.get("error"):
        return "error"
    verdict = result.get("verdict")
    fails = {c["name"] for c in result.get("checks", []) if c.get("status") == "fail"}
    has_pool = bool((result.get("simulation") or {}).get("pair"))
    if expect == "trap":
        # the kind decides what counts as proof: an impostor is proven by its ticker, with or
        # without a pool; a honeypot is proven by trading it, which an empty pool makes meaningless
        if kind == "impostor":
            return "detected" if verdict == "block" and "identity" in fails else \
                   ("softmiss" if verdict == "warn" else "missed")
        if verdict == "block" and ("liquidity" in fails or not has_pool):
            return "dead"
        if verdict == "block" and fails & TRAP_FAILS:
            return "detected"
        if verdict == "warn":
            return "softmiss"
        return "missed"
    if verdict == "safe":
        return "clean"
    if verdict == "warn":
        return "false_alarm"
    return "false_block"


def summarize(rows):
    n = lambda *kinds: sum(1 for r in rows if r["outcome"] in kinds)
    live = n("detected", "missed", "softmiss")
    safe = n("clean", "false_alarm", "false_block")
    pct = lambda a, b: round(100.0 * a / b, 1) if b else None
    return {
        "traps_live": live, "traps_dead": n("dead"),
        "detected": n("detected"), "missed": n("missed"), "soft_miss": n("softmiss"),
        "detection_rate_pct": pct(n("detected"), live),
        "miss_rate_pct": pct(n("missed"), live),
        "safe": safe, "clean": n("clean"), "false_alarm": n("false_alarm"),
        "false_block": n("false_block"),
        "false_block_rate_pct": pct(n("false_block"), safe),
        "false_alarm_rate_pct": pct(n("false_alarm"), safe),
        "errors": n("error"),
    }


def _goplus(chain, address):
    cid = GOPLUS_CHAIN_IDS.get(chain)
    if not cid:
        return None
    url = f"https://api.gopluslabs.io/api/v1/token_security/{cid}?contract_addresses={address.lower()}"
    req = urllib.request.Request(url, headers={"User-Agent": "guardbot-benchmark",
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            t = (json.load(r).get("result") or {}).get(address.lower())
    except Exception as e:
        return {"error": str(e)[:80]}
    if not t:
        return {"error": "no data"}
    return {"is_honeypot": t.get("is_honeypot"), "sell_tax": t.get("sell_tax"),
            "liquidity_usd": round(sum(float(x.get("liquidity") or 0) for x in (t.get("dex") or []))),
            "checked": datetime.date.today().isoformat()}


def _commit():
    try:
        return subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=5).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _one(entry):
    import tokencheck
    t0 = time.time()
    try:
        r = tokencheck.check_token(entry["chain"], entry["address"])
    except Exception as e:
        r = {"error": f"exception: {e}"}
    fails = [c["name"] for c in r.get("checks", []) if c.get("status") == "fail"]
    sim = r.get("simulation") or {}
    return {"chain": entry["chain"], "address": entry["address"], "name": entry.get("name"),
            "expect": entry["expect"], "kind": entry.get("kind"), "source": entry.get("source"),
            "verdict": r.get("verdict"), "score": r.get("score"), "symbol": r.get("symbol"),
            "fails": fails, "pool": sim.get("pair"), "round_trip_pct": sim.get("round_trip_pct"),
            "outcome": classify(entry["expect"], r, entry.get("kind")), "error": r.get("error"),
            "seconds": round(time.time() - t0, 1)}


def markdown(summary, rows):
    s = summary
    out = ["| | count |", "|---|---|",
           f"| Live traps in the set | {s['traps_live']} |",
           f"| Detected (blocked with the trap demonstrated) | {s['detected']} — **{s['detection_rate_pct']}%** |",
           f"| Missed (answered *safe*) | {s['missed']} — {s['miss_rate_pct']}% |",
           f"| Soft miss (answered *warn*) | {s['soft_miss']} |",
           f"| Dead traps (pool empty, excluded) | {s['traps_dead']} |",
           f"| Blue chips in the set | {s['safe']} |",
           f"| Wrongly blocked | {s['false_block']} — **{s['false_block_rate_pct']}%** |",
           f"| Wrongly warned | {s['false_alarm']} — {s['false_alarm_rate_pct']}% |",
           f"| Errors (no verdict) | {s['errors']} |"]
    bad = [r for r in rows if r["outcome"] in ("missed", "softmiss", "false_block", "false_alarm", "error")]
    if bad:
        out += ["", "Every wrong or missing answer, by name:", ""]
        for r in bad:
            out.append(f"- `{r['chain']}` {r['address']} ({r.get('name') or r.get('symbol')}) — "
                       f"expected {r['expect']}, got {r['verdict'] or r['error']} → {r['outcome']}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default=SET_PATH)
    ap.add_argument("--out", default=RESULTS_PATH)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--chain")
    ap.add_argument("--relabel", action="store_true")
    a = ap.parse_args()

    spec = json.load(open(a.set))
    entries = [e for e in spec["tokens"] if not a.chain or e["chain"] == a.chain]
    print(f"{len(entries)} tokens, {a.jobs} in parallel", file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        rows = list(ex.map(_one, entries))
    if a.relabel:
        for r in rows:
            if r["expect"] == "trap" and r.get("source") == "goplus":
                r["label_now"] = _goplus(r["chain"], r["address"])
                time.sleep(1.3)
    summary = summarize(rows)
    run = {"date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "guardbot_commit": _commit(), "set_version": spec.get("version"),
           "criterion": spec.get("criterion")}
    json.dump({"run": run, "summary": summary, "rows": rows}, open(a.out, "w"), indent=1)
    print(markdown(summary, rows))
    print(f"\nwritten: {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
