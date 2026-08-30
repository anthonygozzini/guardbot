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

# ERC-20 Approval(owner,spender,value) event topic0
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
# Free Etherscan V2 key (one key, all chains) unlocks full-history getLogs on every chain.
# Without it we fall back to direct public RPC, which only allows full-range getLogs on a
# few chains (e.g. Arbitrum); the others are reported as 'degraded', never silently missed.
ETHERSCAN_KEY = os.environ.get("GUARDBOT_ETHERSCAN_KEY", "")
# Alchemy is the primary EVM logs source: its getLogs limits by RESULT COUNT (<=10k), not by
# block range, so an owner-filtered Approval query passes over full chain history. One free key
# covers all these chains. This is the approach revoke.cash-class tools actually use.
ALCHEMY_KEY = os.environ.get("GUARDBOT_ALCHEMY_KEY", "")
ALCHEMY_NET = {"ethereum": "eth-mainnet", "base": "base-mainnet", "arbitrum": "arb-mainnet",
               "optimism": "opt-mainnet", "polygon": "polygon-mainnet", "bsc": "bnb-mainnet"}
# per chain: id + public RPCs for eth_call (several, because free endpoints die without notice —
# polygon-rpc.com started returning 401 and a single hardcoded RPC turned that into a false clean).
EVM_CFG = {
    "ethereum": {"id": "1", "rpcs": ["https://eth.llamarpc.com",
                                     "https://ethereum-rpc.publicnode.com",
                                     "https://1.rpc.thirdweb.com"]},
    "bsc": {"id": "56", "rpcs": ["https://bsc-dataseed.binance.org",
                                 "https://bsc-rpc.publicnode.com",
                                 "https://56.rpc.thirdweb.com"]},
    "base": {"id": "8453", "rpcs": ["https://mainnet.base.org", "https://base.drpc.org"]},
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
    """Best RPC for eth_call (allowance/symbol): Alchemy if keyed, else the first public
    endpoint that actually answers (probed once per process, then remembered)."""
    if ALCHEMY_KEY and name in ALCHEMY_NET:
        return f"https://{ALCHEMY_NET[name]}.g.alchemy.com/v2/{ALCHEMY_KEY}"
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
SOL_RPC = "https://api.mainnet-beta.solana.com"
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


def _getlogs_try(url, owner_topic, lo, hi):
    """One owner-filtered getLogs. Returns ('ok', logs) | ('toobig', None) | ('err', None).
    'toobig' means the RANGE was too wide for the provider (split it), not a real failure."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
            "params": [{"fromBlock": hex(lo), "toBlock": hex(hi),
                        "topics": [APPROVAL_TOPIC, owner_topic]}]}
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


def _chunked_scan(pool, owner_topic, start, latest):
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
                st, got = _getlogs_try(next_url(), owner_topic, lo, hi)
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
            c.execute("CREATE TABLE IF NOT EXISTS pairs(chain TEXT, owner TEXT, token TEXT,"
                      " spender TEXT, PRIMARY KEY(chain, owner, token, spender))")
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
            pr = db.execute("SELECT token, spender FROM pairs WHERE chain=? AND owner=?",
                            (chain, owner)).fetchall()
            st = db.execute("SELECT last_block FROM state WHERE chain=? AND owner=?",
                            (chain, owner)).fetchone()
        except Exception:
            return set(), None
    return {(t, s) for t, s in pr}, (st[0] if st else None)


def _store(chain, owner, pairs, last_block):
    db = _db()
    if db is None:
        return
    owner = owner.lower()
    with _db_lock:
        try:
            db.executemany("INSERT OR IGNORE INTO pairs(chain, owner, token, spender)"
                           " VALUES(?,?,?,?)", [(chain, owner, t, s) for t, s in pairs])
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


def _approval_logs(name, cfg, owner_topic, owner, from_block=0, nonce_checked=False):
    """Return (logs, latest_block, ok, partial) for Approval events in [from_block, latest].
    from_block=0 = full history; >0 = incremental (only new blocks, driven by the local index).
    Fast pre-check skips fresh scans of chains the address never used (nonce==0). Source order:
    Etherscan free (Ethereum/Arbitrum/Polygon) → our own adaptive scanner over a free public-RPC
    pool. Alchemy is used only for eth_call (its free getLogs caps at 10 blocks).
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
               f"&fromBlock={from_block}&toBlock=latest&topic0={APPROVAL_TOPIC}&topic0_1_opr=and"
               f"&topic1={owner_topic}&apikey={ETHERSCAN_KEY}")
        for _ in range(4):
            try:
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
    # our own adaptive scanner over a free public-RPC pool (Base, Optimism, …).
    pool = RPC_POOL.get(name)
    if pool:
        start = from_block if from_block > 0 else _first_active_block(rpc, owner, latest)
        try:
            logs, gaps = _chunked_scan(pool, owner_topic, start, latest)
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


def _symbol(rpc, token):
    try:
        r = _rpc(rpc, "eth_call", [{"to": token, "data": "0x95d89b41"}, "latest"])  # symbol()
        if r and r != "0x":
            b = bytes.fromhex(r[2:])
            return b[64:].split(b"\x00")[0].decode("utf-8", "ignore").strip() or None
    except Exception:
        pass
    return None


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


def _probe_universe(chain):
    """Mined candidate (token,spender) pairs for a chain, or ([], meta) if none shipped."""
    global _PROBE
    if _PROBE is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe_universe.json")
        try:
            with open(p) as f:
                _PROBE = json.load(f)
        except Exception:
            _PROBE = {}
    entry = _PROBE.get(chain) or {}
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


def _resolve_pairs(rpc, name, owner, pairs):
    """Live allowance for every known (token,spender) pair, in parallel. cur==0 = revoked
    (skip); this is the current on-chain truth, re-checked every scan even when pairs are cached."""
    if not pairs:
        return []
    sym_cache, sym_lock = {}, threading.Lock()

    def symbol(token):
        with sym_lock:
            if token in sym_cache:
                return sym_cache[token]
        s = _symbol(rpc, token)
        with sym_lock:
            sym_cache[token] = s
        return s

    def resolve(pair):
        token, spender = pair
        cur = _allowance(rpc, owner, token, spender)
        if cur == 0:
            return None   # revoked / zero — nothing to clean
        unlimited = cur >= UNLIMITED
        return {
            "chain": name, "kind": "approval",
            "token": token, "token_symbol": symbol(token),
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_logs = ex.submit(_approval_logs, name, cfg, owner_topic, address, from_block, True)
        f_probe = ex.submit(_probe_allowances, rpc, address, universe) if universe else None
        try:
            logs, latest, ok, partial = f_logs.result()
        except Exception:
            logs, latest, ok, partial = [], 0, False, False
        probe_hits = set()
        if f_probe is not None:
            try:
                probe_hits = f_probe.result()
            except Exception:
                pass

    if ok:
        for lg in logs:
            topics = lg.get("topics") or []
            if len(topics) < 3:
                continue          # only indexed Approval(owner,spender); skip Permit-style
            pairs.add((lg["address"].lower(), "0x" + topics[2][-40:]))
        status = "partial" if partial else "scanned"
    elif probe_hits or universe:
        status = "probed"         # no readable history; the probe is the source
    elif pairs:
        status = "cached"         # nothing live worked; show last-known pairs
    else:
        return name, "degraded", []

    pairs |= probe_hits
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
        d = _get(f"https://apilist.tronscanapi.com/api/account/approve/list?address={address}&start=0&limit=50")
    except Exception:
        return [], ["tron?"]
    cinfo = d.get("contractInfo") or {}
    for row in (d.get("data") or []):
        unlimited = bool(row.get("unlimited"))
        token = row.get("contract_address")
        sym = (cinfo.get(token) or {}).get("tokenInfo", {}).get("tokenAbbr") if isinstance(cinfo.get(token), dict) else None
        items.append({
            "chain": "tron", "kind": "approval",
            "token": token, "token_symbol": sym,
            "spender": row.get("to_address"),
            "amount": str(row.get("amount", "")), "unlimited": unlimited,
            "risky": unlimited,   # on TRON an unlimited approval (often USDT) is the #1 risk
            "evidence": {"raw_amount": row.get("amount")},
        })
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
    return items, ["solana"]


# ---------------- leveled risk (exposure + spender trust) ----------------
# Common, legitimate spenders — a known interaction here is genuine, not a threat.
KNOWN_SPENDERS = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2 (Uniswap)",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Router",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Router v6",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
}
LEVELS = ("minimal", "low", "medium", "high", "critical")


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


def _spender_trust(chain, spender):
    s = (spender or "").lower()
    if s in KNOWN_SPENDERS:
        return "legit", KNOWN_SPENDERS[s]
    if chain in EVM_CFG:
        bad = _goplus_malicious(chain, spender)
        if bad:
            return "malicious", bad
    return "unknown", None


_REGISTRY = None


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
    keys = {(it["chain"], (it.get("spender") or "").lower()) for it in items}
    cache = {}
    if keys:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(keys))) as ex:
            for k, v in ex.map(lambda k: (k, _spender_trust(k[0], k[1])), list(keys)):
                cache[k] = v
    for it in items:
        key = (it["chain"], (it.get("spender") or "").lower())
        trust, name = cache[key]
        exposure = 40 if it.get("unlimited") else (30 if it.get("kind") == "delegate" else 10)
        score = exposure + {"legit": -20, "malicious": 60, "unknown": 25}[trust]
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
        out["note"] = ("These chains have no free full-history log source (Etherscan's free "
                       "tier covers only Ethereum/Arbitrum/Polygon; Alchemy's free tier caps "
                       "getLogs at 10 blocks). For them use a paid provider (Alchemy PAYG or "
                       "Etherscan) or a per-chain explorer key.")
    if probed:
        cov = {c: (_probe_universe(c)[1] or {}).get("coverage_pct") for c in probed}
        out["probed_chains"] = probed
        out["probe_coverage_pct"] = cov
        out["probe_note"] = ("These chains have no readable log history on any free RPC, so they "
                             "were PROBED instead of scanned: every candidate (token,spender) pair "
                             "mined from the chain's own Approval events was checked live via "
                             "Multicall3. Coverage is the share of observed approval activity the "
                             "candidate set represents — high, but not a guarantee of completeness.")
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
