#!/usr/bin/env python3
"""GuardBot — the "fix" side: view risky token approvals across chains.

approvals(address) -> {address, chains_scanned, items[], count, risky_count}.
Covers what revoke.cash does NOT: paste any address and see standing approvals on
  - EVM (Ethereum, BSC, Base, Arbitrum, Polygon)  via GoPlus
  - TRON (TRC-20)                                  via TronScan
  - Solana (SPL delegates)                         via RPC
Read-only, no wallet connection. The "revoke" action (a signed tx) is a later step;
this is the view that tells you what to clean up.
"""

import concurrent.futures
import json
import os
import queue
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request


def _load_env():
    """Load a local .env (KEY=VALUE lines) so secrets stay in a gitignored file, not the shell."""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
    except OSError:
        pass


_load_env()

UA = "Mozilla/5.0 (guardbot/0.1; +pre-trade safety; read-only)"
TIMEOUT = 20

from keccak import selector, topic as _topic

# ERC-20 Approval(owner,spender,value) event topic0
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
# An ERC-20 allowance is not the only thing you can hand out, and the others are worse:
#  - ApprovalForAll gives an operator EVERY NFT in a collection, present and future. It is one
#    of the most used drainer vectors, and reading only ERC-20 Approval events missed it whole.
#  - Permit2 holds its own allowances INSIDE itself. The ERC-20 approval you see is just the
#    door to it; the real exposure (which token, to whom, until when) lives in Permit2's books
#    and stayed invisible while Permit2 was scored as a trusted spender — lowering the alarm.
APPROVAL_FOR_ALL_TOPIC = _topic("ApprovalForAll(address,address,bool)")
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
PERMIT2_APPROVAL_TOPIC = _topic("Approval(address,address,address,uint160,uint48)")
PERMIT2_PERMIT_TOPIC = _topic("Permit(address,address,address,uint160,uint48,uint48)")
SEL_IS_APPROVED_FOR_ALL = selector("isApprovedForAll(address,address)")
SEL_PERMIT2_ALLOWANCE = selector("allowance(address,address,address)")
KIND_ERC20, KIND_NFT, KIND_PERMIT2 = "erc20", "nft_operator", "permit2"
# Free Etherscan V2 key (one key, all chains) unlocks full-history getLogs on every chain.
# Without it we fall back to direct public RPC, which only allows full-range getLogs on a
# few chains (e.g. Arbitrum); the others are reported as 'degraded', never silently missed.
ETHERSCAN_KEY = os.environ.get("GUARDBOT_ETHERSCAN_KEY", "")
# Etherscan's FREE tier answers only these chains; elsewhere the key buys nothing and the
# request falls through to our own scanner. Gating on the key alone quietly launched four
# full-history sweeps on chains it never covered.
ETHERSCAN_FREE_CHAINS = {"ethereum", "arbitrum", "polygon"}
# free, keyless, Etherscan-compatible log APIs for chains the Etherscan free tier excludes
BLOCKSCOUT = {"base": "https://base.blockscout.com"}

# Etherscan free allows 5 req/s for the WHOLE process, but 4 event families × N chains fire their
# getLogs together: the burst tripped the limiter, every retry failed too, and the chain fell back
# to the windowed RPC scanner — surfacing as "partial" on chains that have full history available.
# One shared gate spaces calls to ~4/s (threshold = ×0.8 of Etherscan's own published limit).
_ESCAN_LOCK = threading.Lock()
_ESCAN_NEXT = [0.0]


def _escan_gate():
    with _ESCAN_LOCK:
        now = time.time()
        wait = _ESCAN_NEXT[0] - now
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _ESCAN_NEXT[0] = now + 0.26


# same idea for Blockscout, spaced wider (its public API is touchier than Etherscan's 5/s)
_BS_LOCK = threading.Lock()
_BS_NEXT = [0.0]


def _bs_gate():
    with _BS_LOCK:
        now = time.time()
        wait = _BS_NEXT[0] - now
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _BS_NEXT[0] = now + 1.1
# No keyed RPC provider. Everything runs on free public RPCs — proven to give the same result as
# a keyed setup (see README), so there is nothing to rate-limit, pay for, or leak. eth_call
# (allowance/symbol/name/nonce/Multicall3) goes to the public endpoints below.
# per chain: id + public RPCs for eth_call (several, because free endpoints die without notice —
# polygon-rpc.com started returning 401 and a single hardcoded RPC turned that into a false clean).
EVM_CFG = {
    "ethereum": {"id": "1", "rpcs": ["https://eth.llamarpc.com",
                                     "https://ethereum-rpc.publicnode.com",
                                     "https://1.rpc.thirdweb.com"]},
    "bsc": {"id": "56", "rpcs": ["https://bsc-dataseed.binance.org",
                                 "https://bsc-rpc.publicnode.com",
                                 "https://56.rpc.thirdweb.com"]},
    "base": {"id": "8453", "rpcs": ["https://base-rpc.publicnode.com", "https://8453.rpc.thirdweb.com",
                                    "https://base-mainnet.public.blastapi.io", "https://mainnet.base.org"]},
    "arbitrum": {"id": "42161", "rpcs": ["https://arb1.arbitrum.io/rpc",
                                         "https://arbitrum-one-rpc.publicnode.com"]},
    "polygon": {"id": "137", "rpcs": ["https://polygon-bor-rpc.publicnode.com",
                                      "https://polygon.drpc.org", "https://1rpc.io/matic"]},
    "optimism": {"id": "10", "rpcs": ["https://mainnet.optimism.io",
                                      "https://optimism-rpc.publicnode.com"]},
}
_RPC_PICK = {}
_pick_lock = threading.Lock()


def _chain_rpc(name, cfg):
    """RPC for eth_call (allowance/symbol/name): the first public endpoint that actually answers
    (probed once per process, then remembered). No keyed provider."""
    with _pick_lock:
        hit = _RPC_PICK.get(name)
    if hit:
        return hit
    urls = cfg.get("rpcs") or []
    for u in urls:
        try:
            if _rpc(u, "eth_blockNumber", []):
                with _pick_lock:
                    _RPC_PICK[name] = u
                return u
        except Exception:
            continue
    return urls[0] if urls else ""
# Testnet mode is how signing gets verified WITHOUT spending: Solana devnet (free airdrop) and
# TRON Nile (free faucet). Same code paths, different endpoints; the viewer shows a TESTNET chip.
SOL_RPC = os.environ.get("GUARDBOT_SOLANA_RPC", "https://api.mainnet-beta.solana.com")
TRON_NETWORK = os.environ.get("GUARDBOT_TRON_NETWORK", "mainnet").lower()
TRONSCAN = {"mainnet": "https://apilist.tronscanapi.com", "nile": "https://nileapi.tronscan.org",
            "shasta": "https://shastapi.tronscan.org"}.get(TRON_NETWORK, "https://apilist.tronscanapi.com")
SPL_PROGRAMS = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",   # SPL Token
                "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"]   # Token-2022
UNLIMITED = 10 ** 30  # heuristic threshold for "unlimited-ish" allowance


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def _big(v):
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


def detect_chain(address):
    a = address.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        return "evm"
    if re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", a):
        return "tron"
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", a):
        return "solana"
    return None


# ---------------- EVM: read Approval events + current allowance (revoke.cash method) --------
def _rpc(url, method, params):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r).get("result")


def _getlogs(url, owner_topic):
    """eth_getLogs for Approval events; returns the log list, or None on error (not empty)."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
            "params": [{"fromBlock": "0x0", "toBlock": "latest",
                        "topics": [APPROVAL_TOPIC, owner_topic]}]}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        d = json.load(r)
    return d["result"] if isinstance(d.get("result"), list) else None


# Free public RPCs that accept ~10k-block getLogs (no key). Our own scanner uses these.
RPC_POOL = {
    "base": ["https://mainnet.base.org", "https://base.drpc.org"],
    "optimism": ["https://mainnet.optimism.io", "https://optimism.drpc.org"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc"],
    # bsc: public RPCs block getLogs — the one chain still to crack.
}
# Adaptive scanning: start WIDE (owner-filtered queries return few logs, so a huge block
# range passes in one call) and split only when a provider says the response is too large.
# A normal wallet collapses full history into a handful of calls; a bot with thousands of
# approvals self-subdivides down to MIN_SPAN. No fixed 10k-chunk march over dead history.
INIT_SPAN = 3_000_000   # first attempt span per range
MIN_SPAN = 5_000        # floor before we accept a possibly-capped result at a dense range
RESULT_CAP = 9500       # provider silently caps ~10k logs → treat as "split me"
SCAN_WORKERS = 24       # concurrent range workers
# provider phrasings for "your range/response is too big — narrow it" (→ split, don't fail)
_TOOBIG = ("too large", "more than", "limit exceeded", "response size", "query timeout",
           "block range", "range is too", "exceeds", "result set", "too many", "10000",
           "up to a", "requested too", "logs matched")


def _nonce(rpc, owner, block="latest"):
    r = _rpc(rpc, "eth_getTransactionCount", [owner, block])
    return int(r, 16) if r else 0


def _first_active_block(rpc, owner, latest):
    """Binary-search the first block where the owner had sent a tx (nonce>0).
    Bounds the scan to the address's real activity window instead of genesis."""
    lo, hi = 0, latest
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            n = _nonce(rpc, owner, hex(mid))
        except Exception:
            return 0   # can't narrow safely → scan from genesis
        if n > 0:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _getlogs_try(url, owner_topic, lo, hi, topic0=APPROVAL_TOPIC, address=None):
    """One owner-filtered getLogs. Returns ('ok', logs) | ('toobig', None) | ('err', None).
    'toobig' means the RANGE was too wide for the provider (split it), not a real failure."""
    flt = {"fromBlock": hex(lo), "toBlock": hex(hi), "topics": [topic0, owner_topic]}
    if address:
        flt["address"] = address
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs", "params": [flt]}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            txt = e.read().decode()[:400].lower()
        except Exception:
            txt = str(e).lower()
        return ("toobig" if any(s in txt for s in _TOOBIG) else "err"), None
    except Exception:
        return "err", None
    if isinstance(d.get("result"), list):
        return "ok", d["result"]
    msg = str((d.get("error") or {}).get("message", "")).lower()
    return ("toobig" if any(s in msg for s in _TOOBIG) else "err"), None


MAX_TRIES = 3   # per-range retries on transient RPC errors before recording an honest gap


def _chunked_scan(pool, owner_topic, start, latest, topic0=APPROVAL_TOPIC, address=None):
    """Adaptive parallel scanner over a free-RPC pool. Seeds wide ranges; for each range it tries
    EVERY RPC in the pool (they disagree on limits) before deciding. A range all providers reject
    as too large is split; one that keeps erroring after retries is recorded as a GAP, never
    dropped silently. Returns (logs, gaps) — gaps make the chain 'partial', not falsely clean."""
    if latest <= 0 or start > latest:
        return [], []
    work = queue.Queue()

    def put(lo, hi, tries=0):
        work.put((lo, hi, tries))

    b = start
    while b <= latest:
        put(b, min(b + INIT_SPAN - 1, latest))
        b += INIT_SPAN
    logs, gaps, lock = [], [], threading.Lock()
    rr = [0]
    rr_lock = threading.Lock()

    def next_url():
        with rr_lock:
            u = pool[rr[0] % len(pool)]
            rr[0] += 1
        return u

    def split(lo, hi):
        mid = (lo + hi) // 2
        put(lo, mid)
        put(mid + 1, hi)

    def worker():
        while True:
            item = work.get()
            if item is None:
                work.task_done()
                return
            lo, hi, tries = item
            span = hi - lo + 1
            ok_logs, toobig = None, False
            for _ in range(len(pool)):        # try EVERY provider before giving up on this range
                st, got = _getlogs_try(next_url(), owner_topic, lo, hi, topic0, address)
                if st == "ok":
                    ok_logs = got
                    break
                if st == "toobig":
                    toobig = True             # this provider can't, but another might → keep trying
            if ok_logs is not None:
                if len(ok_logs) >= RESULT_CAP and span > 1:
                    split(lo, hi)             # silently capped → subdivide
                else:
                    with lock:
                        logs.extend(ok_logs)
            elif toobig and span > MIN_SPAN:
                split(lo, hi)
            elif toobig:
                with lock:
                    gaps.append((lo, hi))     # dense sub-floor window no free RPC would serve
            elif tries + 1 < MAX_TRIES:
                time.sleep(0.3)
                put(lo, hi, tries + 1)        # transient error → retry
            else:
                with lock:
                    gaps.append((lo, hi))     # persistent error → honest gap, not silent loss
            work.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(SCAN_WORKERS)]
    for t in threads:
        t.start()
    work.join()
    for _ in threads:
        work.put(None)
    for t in threads:
        t.join()
    return logs, gaps


# ---------------- local incremental index (private, on your disk) ----------------
# Repeat scans read cached (token,spender) pairs and re-scan ONLY the blocks added since last
# time, so a re-check is milliseconds instead of a full-history sweep. The DB lives OUTSIDE the
# repo in ~/.guardbot (never committed, never uploaded); disable with GUARDBOT_NO_CACHE=1.
_CACHE_OFF = os.environ.get("GUARDBOT_NO_CACHE", "") not in ("", "0", "false")
_DB_PATH = os.environ.get("GUARDBOT_CACHE",
                          os.path.join(os.path.expanduser("~"), ".guardbot", "approvals.db"))
_db_lock = threading.Lock()
_DB = None


def _db():
    global _DB
    if _CACHE_OFF:
        return None
    if _DB is None:
        try:
            os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
            c = sqlite3.connect(_DB_PATH, check_same_thread=False)
            c.execute("CREATE TABLE IF NOT EXISTS grants(chain TEXT, owner TEXT, kind TEXT,"
                      " token TEXT, spender TEXT,"
                      " PRIMARY KEY(chain, owner, kind, token, spender))")
            c.execute("CREATE TABLE IF NOT EXISTS state(chain TEXT, owner TEXT,"
                      " last_block INTEGER, PRIMARY KEY(chain, owner))")
            c.execute("CREATE TABLE IF NOT EXISTS result(owner TEXT PRIMARY KEY,"
                      " blob TEXT, ts REAL)")
            _DB = c
        except Exception:
            return None
    return _DB


def _cached(chain, owner):
    """(set_of_(token,spender), last_scanned_block_or_None) from the local index."""
    db = _db()
    if db is None:
        return set(), None
    owner = owner.lower()
    with _db_lock:
        try:
            pr = db.execute("SELECT kind, token, spender FROM grants WHERE chain=? AND owner=?",
                            (chain, owner)).fetchall()
            st = db.execute("SELECT last_block FROM state WHERE chain=? AND owner=?",
                            (chain, owner)).fetchone()
        except Exception:
            return set(), None
    return {(k, t, s) for k, t, s in pr}, (st[0] if st else None)


def _store(chain, owner, pairs, last_block):
    db = _db()
    if db is None:
        return
    owner = owner.lower()
    with _db_lock:
        try:
            db.executemany("INSERT OR IGNORE INTO grants(chain, owner, kind, token, spender)"
                           " VALUES(?,?,?,?,?)",
                           [(chain, owner, k, t, s) for k, t, s in pairs])
            db.execute("INSERT OR REPLACE INTO state(chain, owner, last_block) VALUES(?,?,?)",
                       (chain, owner, int(last_block)))
            db.commit()
        except Exception:
            pass


def _store_result(owner, out):
    db = _db()
    if db is None:
        return
    with _db_lock:
        try:
            db.execute("INSERT OR REPLACE INTO result(owner, blob, ts) VALUES(?,?,?)",
                       (owner.lower(), json.dumps(out), time.time()))
            db.commit()
        except Exception:
            pass


def _load_result(owner):
    """Last full result for this owner from the local index, or None. For instant paint."""
    db = _db()
    if db is None:
        return None
    with _db_lock:
        try:
            row = db.execute("SELECT blob, ts FROM result WHERE owner=?",
                             (owner.lower(),)).fetchone()
        except Exception:
            return None
    if not row:
        return None
    try:
        out = json.loads(row[0])
    except Exception:
        return None
    out["stale"] = True
    out["cached_age_s"] = int(time.time() - (row[1] or 0))
    return out


def _block_number(rpc):
    try:
        bn = _rpc(rpc, "eth_blockNumber", [])
        return int(bn, 16) if bn else 0
    except Exception:
        return 0


def _approval_logs(name, cfg, owner_topic, owner, from_block=0, nonce_checked=False,
                   topic0=APPROVAL_TOPIC, address=None):
    """Return (logs, latest_block, ok, partial) for Approval events in [from_block, latest].
    from_block=0 = full history; >0 = incremental (only new blocks, driven by the local index).
    Fast pre-check skips fresh scans of chains the address never used (nonce==0). Source order:
    Etherscan free (Ethereum/Arbitrum/Polygon) → our own adaptive scanner over a free public-RPC
    pool. All eth_call goes to public RPCs — no keyed provider.
    ok=False = no source could scan this chain (degraded). partial=True = scanned but some block
    ranges could not be read (reported, never silently treated as clean)."""
    rpc = _chain_rpc(name, cfg)
    latest = _block_number(rpc)
    if latest <= 0:
        # couldn't even read the head: that is a FAILURE, not "no blocks to scan". Returning
        # ok=True here would report an unreadable chain as clean — the exact false-negative
        # that makes a safety tool dangerous. Hand over to the probe instead.
        return [], 0, False, False
    if from_block == 0 and not nonce_checked:
        try:
            if _nonce(rpc, owner) == 0:
                return [], latest, True, False   # never acted here → no approvals possible
        except Exception:
            pass
    # Etherscan V2 free — covers Ethereum, Arbitrum, Polygon; honors incremental fromBlock.
    if ETHERSCAN_KEY:
        url = (f"https://api.etherscan.io/v2/api?chainid={cfg['id']}&module=logs&action=getLogs"
               f"&fromBlock={from_block}&toBlock=latest&topic0={topic0}&topic0_1_opr=and"
               f"&topic1={owner_topic}&apikey={ETHERSCAN_KEY}"
               + (f"&address={address}" if address else ""))
        for _ in range(4):
            try:
                _escan_gate()
                d = _get(url)
            except Exception:
                time.sleep(0.7)
                continue
            res = d.get("result")
            if isinstance(res, list):
                return res, latest, True, False
            msg = str(d.get("message", "")).lower()
            if msg.startswith("no records"):
                return [], latest, True, False
            if "rate limit" in msg or "max" in str(res).lower():
                time.sleep(0.9)
                continue
            break   # chain not on the free tier → fall through to our scanner
    # Blockscout — Etherscan-compatible getLogs, free and keyless, on chains the Etherscan free
    # tier locks out (Base said "upgrade your plan" while a real USDC approval sat unread there;
    # the windowed RPC scanner ran >10 min on the same wallet and the mined probe universe didn't
    # contain that (token, spender) pair — this is raw chain history, not a verdict service).
    # Owner-filtered queries return few rows; a full page (1000) may be truncated, so page forward.
    bs = BLOCKSCOUT.get(name)
    if bs:
        logs, lo, ok_bs = [], from_block, True
        for _page in range(20):
            url = (f"{bs}/api?module=logs&action=getLogs&fromBlock={lo}&toBlock=latest"
                   f"&topic0={topic0}&topic0_1_opr=and&topic1={owner_topic}"
                   + (f"&address={address}" if address else ""))
            # the four event families query together, and Blockscout rate-limits the burst: a
            # transient 429 must RETRY behind the shared gate, never hand the whole chain to the
            # windowed scanner (that fallback is the >10-minute path this source exists to replace)
            res = None
            for _try in range(5):
                _bs_gate()
                try:
                    d = _get(url)
                except Exception:
                    time.sleep(1 << _try)   # 429s answer in ~0.2s; exponential backoff outlives
                    continue                # the per-minute quota window instead of burning tries
                r = d.get("result")
                if isinstance(r, list):
                    res = r
                    break
                msg = str(d.get("message", "")).lower()
                if msg.startswith("no records") or msg.startswith("no logs"):
                    res = []
                    break
                time.sleep(1 << _try)
            if res is None:
                ok_bs = False
                break
            logs.extend(res)
            if len(res) < 1000:
                break
            try:
                lo = int(res[-1]["blockNumber"], 16) + 1
            except Exception:
                ok_bs = False
                break
        else:
            ok_bs = False   # 20 full pages → can't prove completeness
        if ok_bs:
            return logs, latest, True, False
        # On a Blockscout chain the windowed pool scanner is NOT a fallback: Base means thousands
        # of 10k-block windows (>10 min measured on a real wallet) inside a viewer that waits 150s.
        # An honest fast "history unreadable" hands the chain to the probe + cached pairs instead.
        return [], latest, False, False
    # our own adaptive scanner over a free public-RPC pool (Base, Optimism, …).
    pool = RPC_POOL.get(name)
    if pool:
        start = from_block if from_block > 0 else _first_active_block(rpc, owner, latest)
        try:
            logs, gaps = _chunked_scan(pool, owner_topic, start, latest, topic0, address)
            return logs, latest, True, bool(gaps)
        except Exception:
            pass
    return [], latest, False, False   # no source could scan this chain → degraded, honestly


def _allowance(rpc, owner, token, spender):
    data = "0xdd62ed3e" + owner[2:].lower().rjust(64, "0") + spender[2:].lower().rjust(64, "0")
    try:
        r = _rpc(rpc, "eth_call", [{"to": token, "data": data}, "latest"])
        return int(r, 16) if r and r != "0x" else 0
    except Exception:
        return -1   # unknown (call failed) — treat as "still present" to avoid false clear


def _erc20_string(rpc, token, sel):
    try:
        r = _rpc(rpc, "eth_call", [{"to": token, "data": sel}, "latest"])
        if r and r != "0x":
            b = bytes.fromhex(r[2:])
            return b[64:].split(b"\x00")[0].decode("utf-8", "ignore").strip() or None
    except Exception:
        pass
    return None


def _symbol(rpc, token):
    return _erc20_string(rpc, token, "0x95d89b41")   # symbol()


def _name(rpc, token):
    return _erc20_string(rpc, token, "0x06fdde03")   # name() — the fuller label explorers show


# ---------------- probe: read the PRESENT when the PAST is unreadable ----------------
# Some chains (BSC) refuse eth_getLogs on every free RPC, so approval history can't be read.
# But eth_call is never range-limited, and Multicall3 — same address on every EVM chain —
# batches thousands of allowance() calls into ONE request (measured: 4000 calls / 2.6s on BSC).
# So instead of reading the past we probe the present: check candidate (token,spender) pairs
# mined from the chain's own Approval events (tools/mine_probe_universe.py). This finds real
# standing approvals with zero getLogs, zero API keys and zero third-party services.
# It is a PROBE, not an exhaustive scan: coverage is reported, never implied.
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
AGG3_SELECTOR = "82ad56cb"    # aggregate3((address,bool,bytes)[])
PROBE_BATCH = 500             # calls per multicall request (~0.7s each, measured)
PROBE_WORKERS = 8
_PROBE = None


def _probe_metas(chain):
    """Every mined meta block for a chain — the base ERC-20 set plus each extra grant kind."""
    global _PROBE
    if _PROBE is None:
        _probe_universe(chain)
    entry = (_PROBE or {}).get(chain) or {}
    out = [entry.get("meta") or {}] if entry.get("pairs") else []
    for k in (entry.get("kinds") or {}).values():
        if k.get("pairs"):
            out.append(k.get("meta") or {})
    return [m for m in out if m]


def _probe_universe(chain, kind="erc20"):
    """Mined candidate pairs for a chain and grant kind, or ([], {}) if none shipped."""
    global _PROBE
    if _PROBE is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe_universe.json")
        try:
            with open(p) as f:
                _PROBE = json.load(f)
        except Exception:
            _PROBE = {}
    entry = _PROBE.get(chain) or {}
    if kind != "erc20":
        entry = (entry.get("kinds") or {}).get(kind) or {}
    return entry.get("pairs") or [], entry.get("meta") or {}


def _w(x):
    return f"{int(x):064x}"


def _addr32(a):
    return a.lower().replace("0x", "").rjust(64, "0")


def _enc_aggregate3(calls):
    """ABI-encode aggregate3((address target, bool allowFailure, bytes callData)[])."""
    head, bodies = [AGG3_SELECTOR, _w(0x20), _w(len(calls))], []
    for target, allow, cd in calls:
        cd = cd[2:] if cd.startswith("0x") else cd
        nbytes = len(cd) // 2
        pad = "0" * (((32 - (nbytes % 32)) % 32) * 2)
        bodies.append(_addr32(target) + _w(1 if allow else 0) + _w(0x60) + _w(nbytes) + cd + pad)
    off = 32 * len(calls)
    for b in bodies:
        head.append(_w(off))
        off += len(b) // 2
    return "0x" + "".join(head) + "".join(bodies)


def _dec_aggregate3(hexstr):
    """Decode Result[] = (bool success, bytes returnData)[]."""
    d = hexstr[2:] if hexstr.startswith("0x") else hexstr

    def word(i):
        return int(d[i * 64:(i + 1) * 64], 16)

    base = word(0) // 32
    out = []
    for i in range(word(base)):
        e = base + 1 + word(base + 1 + i) // 32
        ok = word(e) == 1
        b = e + word(e + 1) // 32
        ln = word(b)
        out.append((ok, "0x" + d[(b + 1) * 64:(b + 1) * 64 + ln * 2]))
    return out


ZERO_ADDR = "0x0000000000000000000000000000000000000000"
# The probe queries token contracts we did not choose, so their answers cannot be trusted.
# Scam tokens exist whose allowance() returns "unlimited" for a specific spender (the
# scammer's drainer) no matter WHO the owner is, so that transferFrom works against anyone.
# Measured: 8 such contracts among Ethereum's top-12k pairs alone.
# Canary test: re-ask the same (token, spender) for an owner that cannot possibly have
# approved anything — a fixed address with no history. A truthful ERC-20 answers 0; a
# nonzero answer proves the contract fabricates allowances, and its hits are dropped.
CANARY_OWNER = "0x00000000000000000000000000000000deadbe01"


def _mc_allowances(rpc, owner, pairs):
    """Batch allowance(owner, spender) via Multicall3 → {(token, spender): value}."""
    batches = [pairs[i:i + PROBE_BATCH] for i in range(0, len(pairs), PROBE_BATCH)]
    out, lock = {}, threading.Lock()

    def run(batch):
        calls = [(t, True, "0xdd62ed3e" + _addr32(owner) + _addr32(s)) for t, s in batch]
        try:
            r = _rpc(rpc, "eth_call", [{"to": MULTICALL3, "data": _enc_aggregate3(calls)}, "latest"])
            if not r or r == "0x":
                return
            res = _dec_aggregate3(r)
        except Exception:
            return
        got = {}
        for (t, s), (ok, val) in zip(batch, res):
            if ok and val and val != "0x":
                try:
                    got[(t.lower(), s.lower())] = int(val, 16)
                except ValueError:
                    pass
        if got:
            with lock:
                out.update(got)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        list(ex.map(run, batches))
    return out


def _probe_allowances(rpc, owner, pairs):
    """Probe candidate pairs and return the (token, spender) set with a REAL standing allowance.
    Hits are validated against lying token contracts via the CANARY check above."""
    vals = _mc_allowances(rpc, owner, pairs)
    hits = {p for p, v in vals.items() if v > 0 and p[1] != ZERO_ADDR}
    if not hits:
        return set()
    canary = _mc_allowances(rpc, CANARY_OWNER, sorted(hits))
    return {p for p in hits if canary.get(p, 0) == 0}


EXPAND_ROUNDS = 3          # safety bound; in practice it converges in one or two
EXPAND_MAX_CALLS = 400_000  # ceiling per round, so a pathological wallet cannot run away


def _probe_erc20(rpc, owner, universe):
    """Seed the probe from the mined pairs and the address's own holdings, then expand."""
    seed = _probe_allowances(rpc, owner, universe)
    tokens = sorted({t for t, _ in universe})
    held = _held_tokens(rpc, owner, tokens)
    if held:
        spenders = sorted({s for _, s in universe})
        seed |= _probe_allowances(rpc, owner, [(t, s) for t in held for s in spenders])
    return _probe_expand(rpc, owner, universe, seed)


def _probe_expand(rpc, owner, universe, seed):
    """Grow the probe outward from what was already found.

    The mined universe holds pairs that were OBSERVED together, but an approval can be any
    (token, spender) combination — the third BSC approval on the test wallet used a token and
    a spender that were both in the universe, just never seen paired. Spenders are the useful
    axis: people reuse a handful of them, so once one is known, sweeping every token against it
    is cheap and high-yield. Same in reverse for a token. Repeat until nothing new appears."""
    tokens = sorted({t for t, _ in universe})
    spenders = sorted({s for _, s in universe})
    if not tokens or not spenders:
        return set(seed)
    hits = set(seed)
    probed = {tuple(p) for p in universe}
    frontier = set(seed)
    for _ in range(EXPAND_ROUNDS):
        if not frontier:
            break
        new_spenders = {s for _, s in frontier}
        new_tokens = {t for t, _ in frontier}
        cand = [(t, s) for s in new_spenders for t in tokens]
        cand += [(t, s) for t in new_tokens for s in spenders]
        cand = [p for p in dict.fromkeys(cand) if p not in probed][:EXPAND_MAX_CALLS]
        if not cand:
            break
        probed.update(cand)
        found = _probe_allowances(rpc, owner, cand)
        frontier = found - hits
        hits |= found
    return hits


def _held_tokens(rpc, owner, tokens):
    """Tokens from the universe this address actually holds — a second seed for the expansion.
    (Not sufficient on its own: an approval outlives the balance that motivated it.)"""
    if not tokens:
        return set()
    call = lambda t, _u: (t, True, selector("balanceOf(address)") + _addr32(owner))
    vals = _mc_generic(rpc, [(t, t) for t in tokens], call)
    return {t for (t, _), v in vals.items() if v > 0}


def _mc_generic(rpc, pairs, build_call):
    """Batch arbitrary per-pair calls through Multicall3 -> {(a, b): int result}."""
    batches = [pairs[i:i + PROBE_BATCH] for i in range(0, len(pairs), PROBE_BATCH)]
    out, lock = {}, threading.Lock()

    def run(batch):
        calls = [build_call(a, b) for a, b in batch]
        try:
            r = _rpc(rpc, "eth_call", [{"to": MULTICALL3, "data": _enc_aggregate3(calls)}, "latest"])
            if not r or r == "0x":
                return
            res = _dec_aggregate3(r)
        except Exception:
            return
        got = {}
        for (a, b), (ok, val) in zip(batch, res):
            if ok and val and val != "0x":
                try:
                    got[(a.lower(), b.lower())] = int(val[:66], 16)
                except ValueError:
                    pass
        if got:
            with lock:
                out.update(got)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        list(ex.map(run, batches))
    return out


def _probe_nft_operators(rpc, owner, pairs):
    """isApprovedForAll(owner, operator) over candidate (collection, operator) pairs.
    Same canary discipline: a collection that answers 'yes' for an owner who cannot have
    approved anything is lying, and all of its hits are dropped."""
    if not pairs:
        return set()
    call = lambda c, op: (c, True, SEL_IS_APPROVED_FOR_ALL + _addr32(owner) + _addr32(op))
    hits = {p for p, v in _mc_generic(rpc, pairs, call).items() if v == 1 and p[1] != ZERO_ADDR}
    if not hits:
        return set()
    ccall = lambda c, op: (c, True, SEL_IS_APPROVED_FOR_ALL + _addr32(CANARY_OWNER) + _addr32(op))
    canary = _mc_generic(rpc, sorted(hits), ccall)
    return {p for p in hits if canary.get(p, 0) != 1}


def _probe_permit2(rpc, owner, pairs):
    """Permit2.allowance(owner, token, spender) over candidate (token, spender) pairs.
    Permit2 is a single audited contract, so there is no lying-contract problem here."""
    if not pairs:
        return set()
    call = lambda t, sp: (PERMIT2, True,
                          SEL_PERMIT2_ALLOWANCE + _addr32(owner) + _addr32(t) + _addr32(sp))
    return {p for p, v in _mc_generic(rpc, pairs, call).items() if v > 0}


def _abi_string(hexdata):
    """Decode an ABI-encoded string return (offset+length+bytes), tolerating junk."""
    try:
        b = bytes.fromhex((hexdata or "0x")[2:])
        if len(b) < 64:
            return None
        ln = int.from_bytes(b[32:64], "big")
        if ln == 0 or 64 + ln > len(b):
            return None
        return b[64:64 + ln].split(b"\x00")[0].decode("utf-8", "ignore").strip() or None
    except Exception:
        return None


def _batch_strings(name, tokens, sel):
    """symbol()/name() for many tokens in as few Multicall3 requests as possible → {token: str}.
    One request per PROBE_BATCH instead of one eth_call each — the fix for '—' on rate-limited
    RPCs — and it ROTATES across the chain's RPCs until one answers, since a single public node
    (Base's) 429s constantly. allowFailure is set, so a token missing the method yields None."""
    rpcs = (EVM_CFG.get(name) or {}).get("rpcs") or []
    if not rpcs:
        return {t: None for t in tokens}
    out = {t: None for t in tokens}
    for i in range(0, len(tokens), PROBE_BATCH):
        chunk = tokens[i:i + PROBE_BATCH]
        data = _enc_aggregate3([(t, True, sel) for t in chunk])
        for u in rpcs:                          # try each RPC until the batch comes back
            try:
                r = _rpc(u, "eth_call", [{"to": MULTICALL3, "data": data}, "latest"])
                dec = _dec_aggregate3(r) if r and r != "0x" else []
            except Exception:
                dec = []
            if dec:
                for t, (ok, val) in zip(chunk, dec):
                    if ok:
                        out[t] = _abi_string(val)
                break
    return out


def _permit2_allowance(rpc, owner, token, spender):
    """Permit2.allowance(user, token, spender) -> (amount uint160, expiration uint48, nonce).
    This is the exposure the plain ERC-20 view cannot see: approving Permit2 only opens the
    door; what actually got granted, to whom and until when is written inside Permit2."""
    data = (SEL_PERMIT2_ALLOWANCE + owner[2:].lower().rjust(64, "0")
            + token[2:].lower().rjust(64, "0") + spender[2:].lower().rjust(64, "0"))
    try:
        r = _rpc(rpc, "eth_call", [{"to": PERMIT2, "data": data}, "latest"])
        if not r or len(r) < 194:
            return 0, 0
        return int(r[2:66], 16), int(r[66:130], 16)
    except Exception:
        return 0, 0


def _resolve_pairs(rpc, name, owner, pairs):
    """Live allowance for every known (token,spender) pair, in parallel. cur==0 = revoked
    (skip); this is the current on-chain truth, re-checked every scan even when pairs are cached."""
    if not pairs:
        return []
    # symbol()/name() were one eth_call PER token — on a rate-limited RPC (Base's public nodes
    # 429 constantly) most of them failed and the token showed as "—". Read them all in ONE
    # Multicall3 batch instead: a single request for every symbol, one for every name.
    tokens = sorted({t for _k, t, _s in pairs})
    sym_cache = _batch_strings(name, tokens, "0x95d89b41")   # symbol()
    name_cache = _batch_strings(name, tokens, "0x06fdde03")  # name()

    def symbol(token):
        # last resort is the locally mined registry (zero network): when every RPC read fails,
        # a top-liquidity token like USDC must still get its ticker, never a "—".
        return sym_cache.get(token) or _registry_symbol(name, token)

    def tname(token):
        return name_cache.get(token)

    def resolve(grant):
        kind, token, spender = grant
        if kind == KIND_NFT:
            # An operator approval is all-or-nothing: it covers every token in the collection,
            # including ones bought after it was granted. There is no "amount" to read — only
            # whether it is still on.
            try:
                r = _rpc(rpc, "eth_call", [{"to": token,
                                            "data": SEL_IS_APPROVED_FOR_ALL
                                            + owner[2:].lower().rjust(64, "0")
                                            + spender[2:].lower().rjust(64, "0")}, "latest"])
                on = bool(r) and r != "0x" and int(r, 16) == 1
            except Exception:
                return None
            if not on:
                return None
            return {
                "chain": name, "kind": "nft_operator",
                "token": token, "token_symbol": symbol(token), "token_name": tname(token),
                "spender": spender,
                "amount": "every NFT in this collection", "unlimited": True, "risky": True,
                "evidence": {"isApprovedForAll": True},
            }
        if kind == KIND_PERMIT2:
            amount, expiration = _permit2_allowance(rpc, owner, token, spender)
            if amount <= 0:
                return None
            expired = 0 < expiration <= int(time.time())
            if expired:
                return None   # Permit2 grants carry a deadline; a lapsed one is not exposure
            unlimited = amount >= (1 << 160) - 1
            return {
                "chain": name, "kind": "permit2",
                "token": token, "token_symbol": symbol(token), "token_name": tname(token),
                "spender": spender,
                "amount": "unlimited" if unlimited else str(amount),
                "unlimited": unlimited, "risky": True,
                "evidence": {"via": "Permit2", "permit2_amount": str(amount),
                             "expires_unix": expiration or None},
            }
        cur = _allowance(rpc, owner, token, spender)
        if cur == 0:
            return None   # revoked / zero — nothing to clean
        unlimited = cur >= UNLIMITED
        return {
            "chain": name, "kind": "approval",
            "token": token, "token_symbol": symbol(token), "token_name": tname(token),
            "spender": spender,
            "amount": "unknown" if cur < 0 else ("unlimited" if unlimited else str(cur)),
            "unlimited": unlimited, "risky": unlimited,
            "evidence": {"current_allowance_raw": None if cur < 0 else str(cur)},
        }

    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(pairs))) as ex:
        for r in ex.map(resolve, list(pairs)):
            if r is not None:
                out.append(r)
    return out


def _scan_chain(name, cfg, owner_topic, address):
    """One chain's whole pipeline. Two independent sources run CONCURRENTLY and are unioned:
      - log history (Etherscan / our adaptive RPC scanner) — exhaustive where it is available;
      - Multicall3 present-probing over the chain-mined candidate universe — needs no logs and
        no API key, so it is the keyless floor on every chain and catches what history misses.
    Returns (name, status, items); status names the HISTORY source
    ('scanned' | 'partial' | 'probed' | 'cached' | 'degraded')."""
    rpc = _chain_rpc(name, cfg)
    pairs, last = _cached(name, address)
    from_block = (last + 1) if last is not None else 0
    if not pairs:
        # never acted on this chain → no approval can exist here; skip both sources. Checked on
        # every run with no known pairs (not just the first), otherwise a re-scan would probe
        # chains the address never touched and surface junk from hostile token contracts.
        try:
            if _nonce(rpc, address) == 0:
                _store(name, address, set(), _block_number(rpc))
                return name, "scanned", []
        except Exception:
            pass
    universe, _meta = _probe_universe(name)

    # Three different things can be handed out, each with its own event, so each is asked for
    # separately: an ERC-20 allowance, an NFT operator (ApprovalForAll), and a grant recorded
    # inside Permit2. Reading only the first was the blind spot.
    # All four event families are walked on every chain. Measured on a heavy Base address:
    # the ERC-20 sweep alone costs 137s and the three extra topics add ~27s, so gating them off
    # bought 20% speed and lost every long-tail NFT grant — the log scan is the only source that
    # finds a collection outside the mined universe. Correctness wins that trade.
    sources = [(KIND_ERC20, APPROVAL_TOPIC, None),
               (KIND_NFT, APPROVAL_FOR_ALL_TOPIC, None),
               (KIND_PERMIT2, PERMIT2_APPROVAL_TOPIC, PERMIT2),
               (KIND_PERMIT2, PERMIT2_PERMIT_TOPIC, PERMIT2)]
    nft_universe = _probe_universe(name, KIND_NFT)[0]
    p2_universe = _probe_universe(name, KIND_PERMIT2)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources) + 3) as ex:
        f_logs = {k_t: ex.submit(_approval_logs, name, cfg, owner_topic, address, from_block,
                                 True, k_t[1], k_t[2])
                  for k_t in sources}
        f_probe = ex.submit(_probe_erc20, rpc, address, universe) if universe else None
        f_nft = ex.submit(_probe_nft_operators, rpc, address, nft_universe) if nft_universe else None
        f_p2 = ex.submit(_probe_permit2, rpc, address, p2_universe) if p2_universe else None
        results, latest, ok, partial = {}, 0, False, False
        for k_t, fut in f_logs.items():
            try:
                lg, lb, o, p = fut.result()
            except Exception:
                lg, lb, o, p = [], 0, False, False
            results[k_t] = (lg, o)
            latest = max(latest, lb)
            # the ERC-20 pass decides the chain's status; it is the one that must be exhaustive
            if k_t[0] == KIND_ERC20 and k_t[1] == APPROVAL_TOPIC:
                ok, partial = o, p
        def _res(f):
            if f is None:
                return set()
            try:
                return f.result()
            except Exception:
                return set()

        probe_hits, nft_hits, p2_hits = _res(f_probe), _res(f_nft), _res(f_p2)

    if ok:
        for (kind, topic0, _addr), (logs, source_ok) in results.items():
            if not source_ok:
                continue
            for lg in logs:
                topics = lg.get("topics") or []
                if len(topics) < 3:
                    continue
                if kind == KIND_PERMIT2:
                    # Permit2 indexes (owner, token, spender) — the token is a topic, not the
                    # emitting contract, because Permit2 emits for every token it holds.
                    if len(topics) < 4:
                        continue
                    pairs.add((kind, "0x" + topics[2][-40:], "0x" + topics[3][-40:]))
                else:
                    pairs.add((kind, lg["address"].lower(), "0x" + topics[2][-40:]))
        status = "partial" if partial else "scanned"
    elif probe_hits or nft_hits or p2_hits or universe:
        status = "probed"         # no readable history; the probe is the source
    elif pairs:
        status = "cached"         # nothing live worked; show last-known pairs
    else:
        return name, "degraded", []

    pairs |= {(KIND_ERC20, t, sp) for t, sp in probe_hits}
    pairs |= {(KIND_NFT, c, op) for c, op in nft_hits}
    pairs |= {(KIND_PERMIT2, t, sp) for t, sp in p2_hits}
    # only advance the index watermark on a COMPLETE log scan; anything else must re-read.
    if ok and not partial:
        _store(name, address, pairs, latest)
    items = _resolve_pairs(rpc, name, address, pairs)
    return name, status, items


def _evm(address):
    owner_topic = "0x" + "0" * 24 + address[2:].lower()
    items, scanned, degraded, partial, probed = [], [], [], [], []
    # fan every chain out concurrently: wall-clock = the slowest single chain, not the sum.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(EVM_CFG)) as ex:
        results = ex.map(lambda kv: _scan_chain(kv[0], kv[1], owner_topic, address),
                         list(EVM_CFG.items()))
    for name, status, chain_items in results:
        if status == "degraded":
            degraded.append(name)
            continue
        if status == "partial":
            partial.append(name)
        if status == "probed":
            probed.append(name)
        scanned.append(name if status == "scanned" else name + " (" + status + ")")
        items.extend(chain_items)
    return items, scanned, degraded, partial, probed


# ---------------- TRON via TronScan ----------------
def _tron(address):
    items = []
    try:
        d = _get(f"{TRONSCAN}/api/account/approve/list?address={address}&start=0&limit=50")
    except Exception:
        return [], ["tron?"]
    cinfo = d.get("contractInfo") or {}
    for row in (d.get("data") or []):
        unlimited = bool(row.get("unlimited"))
        token = row.get("contract_address")
        spender = row.get("to_address")
        # the token's own details ride along with each row; the spender's public identity and
        # risk flag sit in contractInfo. Both were being dropped, leaving every TRON row as
        # "— / unknown" while the answer was already in the response.
        tinfo = row.get("tokenInfo") or {}
        sinfo = cinfo.get(spender) or {}
        name = sinfo.get("tag1") or sinfo.get("name") or None
        item = {
            "chain": "tron", "kind": "approval",
            "token": token, "token_symbol": tinfo.get("tokenAbbr") or None,
            "token_name": tinfo.get("tokenName") or None,
            "spender": spender, "spender_name": name,
            "amount": str(row.get("amount", "")), "unlimited": unlimited,
            "risky": unlimited,   # on TRON an unlimited approval (often USDT) is the #1 risk
            "evidence": {"raw_amount": row.get("amount")},
        }
        if sinfo.get("risk"):
            item["spender_flagged"] = True
            item["evidence"]["spender_risk"] = sinfo.get("publicTagDesc") or "flagged by TronScan"
        elif name:
            item["spender_known"] = True
        items.append(item)
    return items, ["tron"]


# ---------------- Solana via RPC ----------------
def _solana(address):
    items = []
    for program in SPL_PROGRAMS:
        try:
            d = _post(SOL_RPC, {"jsonrpc": "2.0", "id": 1, "method": "getTokenAccountsByOwner",
                                "params": [address, {"programId": program}, {"encoding": "jsonParsed"}]})
        except Exception:
            continue
        for acc in (d.get("result", {}) or {}).get("value", []):
            info = acc.get("account", {}).get("data", {}).get("parsed", {}).get("info", {})
            delegate = info.get("delegate")
            if not delegate:
                continue   # no delegate set = nothing to revoke
            damt = (info.get("delegatedAmount") or {}).get("uiAmountString") or info.get("delegatedAmount")
            items.append({
                "chain": "solana", "kind": "delegate",
                "token": info.get("mint"), "token_symbol": None,
                "spender": delegate,
                "amount": str(damt), "unlimited": False,
                "risky": True,   # an active delegate on a token account is worth reviewing
                "evidence": {"token_account": acc.get("pubkey"), "state": info.get("state")},
            })
    _name_solana_tokens(items)
    return items, ["solana"]


def _name_solana_tokens(items):
    """Fill in SPL token names. The mint holds no symbol — it lives in a Metaplex account whose
    address is DERIVED from the mint, so this is computed and read from the chain, not looked up
    in anyone's token list (see solmeta.py)."""
    mints = sorted({i["token"] for i in items if i.get("token")})
    if not mints:
        return items
    try:
        import solmeta
    except Exception:
        return items

    def fetch(m):
        try:
            return m, solmeta.token_meta(SOL_RPC, m)
        except Exception:
            return m, None

    meta = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(mints))) as ex:
        for m, info in ex.map(fetch, mints):
            if info:
                meta[m] = info
    for it in items:
        info = meta.get(it.get("token"))
        if info:
            it["token_symbol"] = info.get("symbol")
            it["token_name"] = info.get("name")
    return items


# ---------------- leveled risk (exposure + spender trust) ----------------
# Common, legitimate spenders — a known interaction here is genuine, not a threat.
# A human name for a spender is off-chain data — it cannot be derived, so the well-known ones are
# curated here (as revoke.cash does too). These contracts sit at the SAME address on every EVM
# chain, so one entry covers all chains. Names marked "(BscScan)" are the explorer's own public
# tag for that exact address, taken from a real approval list, not guessed.
KNOWN_SPENDERS = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2 (Uniswap)",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Router v5",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Router v6",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0xc92e8bdf79f0507f65a392b0ab4667716bfe0110": "CoW Protocol (GPv2VaultRelayer)",
    "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae": "LI.FI Diamond",
    "0x69460570c93f9de5e2edbc3052bf10125f0ca22d": "Rango",            # BscScan
    "0x663dc15d3c1ac63ff12e45ab68fea3f0a883c251": "deBridge",         # BscScan
    "0xb685760ebd368a891f27ae547391f4e2a289895b": "Bridgers",         # BscScan
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2 Router",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap Universal Router",
}
LEVELS = ("minimal", "low", "medium", "high", "critical")


_SPENDER_REG = None


def _spender_registry(chain):
    """Per-chain spender establishment index (distinct approvers), or {} if not mined."""
    global _SPENDER_REG
    if _SPENDER_REG is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spender_registry.json")
        try:
            with open(p) as f:
                _SPENDER_REG = json.load(f)
        except Exception:
            _SPENDER_REG = {}
    return _SPENDER_REG.get(chain) or {}


def _spender_breadth(chain, spender):
    """(distinct_approvers, is_established). A spender approved by a meaningful fraction of every
    wallet that approved anything is an established protocol. The bar is normalized to the chain's
    own sample — >= 1% of the distinct approvers seen, floor 300 — never a bare number, and high
    on purpose: a drainer with a few hundred victims must NOT be de-alarmed, so being conservative
    here fails safe. Establishment only lowers the alarm; a GoPlus-malicious flag always overrides."""
    reg = _spender_registry(chain)
    n = (reg.get("spenders") or {}).get((spender or "").lower(), 0)
    owners = (reg.get("meta") or {}).get("distinct_owners", 0)
    threshold = max(300, round(0.01 * owners))
    return n, (n >= threshold)


def _level(score):
    return (LEVELS[0] if score < 20 else LEVELS[1] if score < 40 else
            LEVELS[2] if score < 60 else LEVELS[3] if score < 80 else LEVELS[4])


def _goplus_malicious(chain_name, spender):
    """Best-effort: is the spender flagged malicious by GoPlus? Returns reason or None."""
    cfg = EVM_CFG.get(chain_name)
    if not cfg or not spender:
        return None
    try:
        d = _get(f"https://api.gopluslabs.io/api/v1/address_security/{spender}?chain_id={cfg['id']}")
    except Exception:
        return None
    r = d.get("result") or {}
    flags = ("cybercrime", "money_laundering", "financial_crime", "blacklist_doubt",
             "phishing_activities", "stealing_attack", "fake_kyc", "malicious_mining_activities",
             "darkweb_transactions", "sanctioned", "honeypot_related_address")
    hit = [k for k in flags if str(r.get(k)) == "1"]
    return ", ".join(hit) if hit else None


def _spender_trust(chain, spender, hints=None):
    """What do we know about this spender? The allowlist and GoPlus only speak EVM, so a
    non-EVM row used to come back 'unknown' by construction — not because nothing was known,
    but because nobody asked. Chains that carry their own identity/risk data (TRON) pass it
    in as hints, so every chain gets a real answer instead of a default one."""
    hints = hints or {}
    if hints.get("spender_flagged"):
        return "malicious", hints.get("spender_name") or "flagged by the chain's explorer"
    if hints.get("spender_known") and hints.get("spender_name"):
        return "legit", hints["spender_name"]
    s = (spender or "").lower()
    if s in KNOWN_SPENDERS:
        return "legit", KNOWN_SPENDERS[s]
    if chain in EVM_CFG:
        bad = _goplus_malicious(chain, spender)
        if bad:
            return "malicious", bad
        breadth, established = _spender_breadth(chain, s)
        if established:
            return "established", f"widely used · {breadth}+ approvers (sampled)"
    return "unknown", None


_REGISTRY = None
_REGSYM = {}


def _registry_symbol(chain, token):
    """address → ticker from the locally mined registry. Reverse of the impersonation lookup;
    costs zero network calls, so it works even when every RPC on the chain is refusing reads."""
    m = _REGSYM.get(chain)
    if m is None:
        m = {}
        for s, entries in _registry(chain).items():
            if s.startswith("__"):
                continue
            for e in entries:
                try:
                    m.setdefault(str(e[0]).lower(), s)
                except Exception:
                    pass
        _REGSYM[chain] = m
    return m.get(str(token).lower())


def _registry(chain):
    global _REGISTRY
    if _REGISTRY is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token_registry.json")
        try:
            with open(p) as f:
                _REGISTRY = json.load(f)
        except Exception:
            _REGISTRY = {}
    return _REGISTRY.get(chain) or {}


def _flag_impersonation(items):
    """A token's symbol is self-declared, so printing it unchallenged launders a disguise:
    four BSC contracts call themselves USDT and only one is the one anyone means. Where a
    symbol is contested, say which contract the market actually trades under that name."""
    for it in items:
        sym = (it.get("token_symbol") or "").strip()
        if not sym:
            continue
        entries = _registry(it["chain"]).get(sym.upper())
        if not entries:
            continue
        leader, leader_res = entries[0][0].lower(), int(entries[0][1])
        if leader == (it.get("token") or "").lower():
            it["symbol_verified"] = True
            continue
        mine = 0
        for a, r in entries:
            if a.lower() == (it.get("token") or "").lower():
                mine = int(r)
        it["symbol_claimants"] = len(entries)
        it["impersonates"] = leader
        # Same rule as tokencheck: dwarfed AND with no market of its own = wearing the name.
        # A contested ticker where this token has real liquidity is shared, not stolen.
        it["symbol_verified"] = False if (leader_res >= 100 * max(mine, 1)
                                          and mine < 10 ** 18) else None
        if it["symbol_verified"] is None:
            it["symbol_shared"] = True
    return items


def _score_items(items):
    """Attach a graded risk_level (0-100 + label) to each item: exposure + spender trust.
    The spender-trust lookups (GoPlus HTTP) run in parallel over the unique spenders."""
    # rows that already carry their own identity/risk data are resolved from it; only the rest
    # need a lookup, and only those are batched out.
    hinted = {}
    for it in items:
        if it.get("spender_known") or it.get("spender_flagged"):
            hinted[(it["chain"], (it.get("spender") or "").lower())] = {
                "spender_known": it.get("spender_known"),
                "spender_flagged": it.get("spender_flagged"),
                "spender_name": it.get("spender_name"),
            }
    keys = {(it["chain"], (it.get("spender") or "").lower()) for it in items}
    cache = {k: _spender_trust(k[0], k[1], hinted[k]) for k in keys if k in hinted}
    todo = [k for k in keys if k not in cache]
    if todo:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(todo))) as ex:
            for k, v in ex.map(lambda k: (k, _spender_trust(k[0], k[1])), todo):
                cache[k] = v
    for it in items:
        key = (it["chain"], (it.get("spender") or "").lower())
        trust, name = cache[key]
        kind = it.get("kind")
        if kind == "nft_operator":
            exposure = 45   # every NFT in the collection, including ones not yet bought
        elif kind == "permit2":
            exposure = 40 if it.get("unlimited") else 20
        elif kind == "delegate":
            exposure = 30
        else:
            exposure = 40 if it.get("unlimited") else 10
        score = exposure + {"legit": -20, "established": -10, "malicious": 60, "unknown": 25}[trust]
        if it.get("symbol_verified") is False:
            score += 40   # it wears a trusted ticker it has no claim to — treat as hostile
        score = max(0, min(100, score))
        it["risk_score"] = score
        it["risk_level"] = _level(score)
        it["spender_trust"] = trust
        it["spender_name"] = name
        it["risky"] = score >= 40   # back-compat; "attention" = medium+
    return items


def approvals(address, chain=None, cached_only=False):
    address = str(address).strip()
    kind = chain or detect_chain(address)
    if cached_only:
        # instant paint: return the last stored result with no network call (true ms),
        # marked stale so the caller can refresh live in the background.
        hit = _load_result(address)
        return hit if hit is not None else {"address": address, "address_type": kind,
                                            "stale": True, "cached_age_s": None,
                                            "chains_scanned": [], "count": 0, "risky_count": 0,
                                            "levels": {lv: 0 for lv in LEVELS}, "items": [],
                                            "note": "no cached result yet — run a live scan"}
    degraded, partial, probed = [], [], []
    if kind == "evm":
        items, scanned, degraded, partial, probed = _evm(address)
    elif kind == "tron":
        items, scanned = _tron(address)
    elif kind == "solana":
        items, scanned = _solana(address)
    else:
        return {"error": "unrecognized address (expected EVM 0x…, TRON T…, or Solana base58)"}
    _flag_impersonation(items)
    _score_items(items)
    levels = {lv: 0 for lv in LEVELS}
    for i in items:
        levels[i["risk_level"]] += 1
    attention = levels["medium"] + levels["high"] + levels["critical"]
    out = {
        "address": address, "address_type": kind, "chains_scanned": scanned,
        "count": len(items),
        "risky_count": attention,            # medium+ = worth a look
        "levels": levels,                    # full breakdown per level
        "items": sorted(items, key=lambda i: -i["risk_score"]),
        "engine": "guardbot-approvals/0.1",
    }
    if degraded:
        out["degraded_chains"] = degraded
        out["note"] = ("These chains have no readable log history on the free public RPCs and no "
                       "probe universe to fall back on, so they could not be scanned. Mine a probe "
                       "universe for them (tools/mine_probe_universe.py) or add an explorer key.")
    # Mined data is a SNAPSHOT: a scam deployed after the last mining run is not in the candidate
    # set, so a probe over stale data quietly narrows without saying so. The age is therefore
    # reported with the result, and called out once it is old enough to matter.
    if kind == "evm":
        ages, undated = {}, []
        for c in EVM_CFG:
            # a chain's candidate set is only as fresh as its OLDEST part, so take the minimum
            # across every grant kind rather than flattering the result with the newest one
            stamps = [m["mined_at"] for m in _probe_metas(c) if m.get("mined_at")]
            if stamps:
                ages[c] = int((time.time() - min(stamps)) / 86400)
            elif _probe_metas(c):
                undated.append(c)
        if ages:
            out["data_age_days"] = ages
        if undated:
            out["data_age_unknown"] = undated
        oldest = max(ages.values()) if ages else None
        if undated or (oldest is not None and oldest >= 30):
            when = (f"up to {oldest} days old" if oldest is not None and oldest >= 30
                    else "of unknown age")
            out["data_stale_note"] = (
                f"the mined candidate data is {when}, so tokens and spenders that appeared "
                "since are not in it — re-run `python3 tools/refresh.py`")
    if probed:
        cov = {c: (_probe_universe(c)[1] or {}).get("coverage_pct") for c in probed}
        out["probed_chains"] = probed
        out["probe_coverage_pct"] = cov
        out["probe_note"] = ("These chains have no readable log history on any free RPC, so they "
                             "were PROBED, not scanned: candidate (token,spender) pairs mined from "
                             "the chain's own activity are checked live via Multicall3, then "
                             "expanded outward from every hit — all tokens against a spender you "
                             "use, all spenders against a token you approved. This found all 5 "
                             "approvals BscScan lists for the test wallet. It can still miss a "
                             "grant whose token AND spender are both outside the mined set, so "
                             "treat an empty result here as 'nothing found', not 'nothing there'.")
        # The percentage below describes the MARKET the candidate set covers, not how much of
        # YOUR exposure was seen. Presenting it as a completeness figure is how a probe starts
        # sounding like a clean bill, so it is named for what it actually measures.
        out["probe_market_coverage_pct"] = out.pop("probe_coverage_pct", None)
    if partial:
        out["partial_chains"] = partial
        out["partial_note"] = ("Some block ranges on these chains could not be read from the free "
                               "RPC pool, so their approval list may be incomplete — not a clean "
                               "bill. Re-scan, or add a keyed provider, for full coverage.")
    _store_result(address, out)   # cache full result for instant paint on the next look-up
    return out


if __name__ == "__main__":
    import sys
    ad = sys.argv[1] if len(sys.argv) > 1 else "0x28C6c06298d514Db089934071355E5743bf21d60"
    print(json.dumps(approvals(ad), indent=2, ensure_ascii=False))
