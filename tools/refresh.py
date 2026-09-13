#!/usr/bin/env python3
"""Re-mine everything GuardBot derives from the chain, in one command.

The probe universes, the symbol registry and the spender registry are SNAPSHOTS of chain
activity. They do not rot loudly — a scam token deployed last week simply isn't in the candidate
set, and the scan comes back clean without lying and without warning. That is why the scan
reports the data's age, and why refreshing has to be one command instead of ten.

  python3 tools/refresh.py              # everything, all chains
  python3 tools/refresh.py --chain bsc  # one chain
  python3 tools/refresh.py --what probe # probe universes only (probe|symbols|spenders)

Takes a while (it samples real log windows across every chain); safe to re-run, and each part
writes only after it succeeds, so a failure leaves the previous snapshot in place.
"""

import os
import subprocess
import sys
import time

TOOLS = os.path.dirname(os.path.abspath(__file__))
CHAINS = ["bsc", "ethereum", "base", "arbitrum", "polygon", "optimism"]
KINDS = ["erc20", "nft", "permit2"]
TOPN = {"erc20": {"ethereum": 12000}, "nft": {}, "permit2": {}}


def run(script, args, label):
    t = time.time()
    try:
        p = subprocess.run([sys.executable, os.path.join(TOOLS, script)] + args,
                           capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        print(f"  {label}: TIMED OUT (previous snapshot kept)")
        return False
    tail = (p.stdout or p.stderr or "").strip().splitlines()
    msg = tail[-1] if tail else "no output"
    ok = p.returncode == 0
    print(f"  {label}: {'ok' if ok else 'FAILED'} [{time.time()-t:.0f}s] {msg[:110]}")
    return ok


def main():
    chains = CHAINS
    if "--chain" in sys.argv:
        chains = [sys.argv[sys.argv.index("--chain") + 1]]
    what = sys.argv[sys.argv.index("--what") + 1] if "--what" in sys.argv else "all"

    started = time.time()
    if what in ("all", "probe"):
        print("probe universes (candidate token/spender pairs per grant kind)")
        for c in chains:
            for k in KINDS:
                n = str(TOPN.get(k, {}).get(c, 4000 if k == "erc20" else 3000))
                run("mine_probe_universe.py", [c, "--kind", k, "--top", n], f"{c}/{k}")
    if what in ("all", "symbols"):
        print("symbol registry (which contracts claim each ticker, and how deep their pools run)")
        for c in chains:
            run("mine_token_registry.py", [c], c)
    if what in ("all", "spenders"):
        print("spender registry (distinct approvers per spender)")
        for c in chains:
            run("mine_spender_registry.py", [c], c)
    print(f"done in {(time.time()-started)/60:.1f} min")


if __name__ == "__main__":
    main()
