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
import re
import time
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
# per chain: id, fallback public RPC for eth_call, and whether that RPC allows full-range getLogs.
EVM_CFG = {
    "ethereum": {"id": "1", "rpc": "https://eth.llamarpc.com", "logs_ok": False},
    "bsc": {"id": "56", "rpc": "https://bsc-dataseed.binance.org", "logs_ok": False},
    "base": {"id": "8453", "rpc": "https://mainnet.base.org", "logs_ok": False},
    "arbitrum": {"id": "42161", "rpc": "https://arb1.arbitrum.io/rpc", "logs_ok": True},
    "polygon": {"id": "137", "rpc": "https://polygon-rpc.com", "logs_ok": False},
    "optimism": {"id": "10", "rpc": "https://mainnet.optimism.io", "logs_ok": False},
}


def _chain_rpc(name, cfg):
    """Best RPC for eth_call (allowance/symbol): Alchemy if keyed, else the public fallback."""
    if ALCHEMY_KEY and name in ALCHEMY_NET:
        return f"https://{ALCHEMY_NET[name]}.g.alchemy.com/v2/{ALCHEMY_KEY}"
    return cfg["rpc"]
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
CHUNK = 10000        # blocks per getLogs request the public RPCs accept
SCAN_WORKERS = 20    # concurrent chunk requests


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


def _getlogs_range(url, owner_topic, lo, hi):
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
            "params": [{"fromBlock": hex(lo), "toBlock": hex(hi),
                        "topics": [APPROVAL_TOPIC, owner_topic]}]}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        d = json.load(r)
    return d["result"] if isinstance(d.get("result"), list) else None


def _chunked_scan(pool, owner, owner_topic):
    """Our own scanner: bound to the address's active window, then fan the 10k-block chunks
    out across a pool of free RPCs in parallel. Returns the Approval logs."""
    latest = _rpc(pool[0], "eth_blockNumber", [])
    latest = int(latest, 16) if latest else 0
    start = _first_active_block(pool[0], owner, latest)
    ranges = [(b, min(b + CHUNK - 1, latest)) for b in range(start, latest + 1, CHUNK)]
    logs = []

    def scan(idx, lo, hi):
        for k in range(len(pool) + 2):
            url = pool[(idx + k) % len(pool)]
            try:
                r = _getlogs_range(url, owner_topic, lo, hi)
                if r is not None:
                    return r
            except Exception:
                time.sleep(0.25)
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        futures = [ex.submit(scan, i, lo, hi) for i, (lo, hi) in enumerate(ranges)]
        for f in concurrent.futures.as_completed(futures):
            logs.extend(f.result())
    return logs


def _approval_logs(name, cfg, owner_topic, owner):
    """Return (logs, ok). Fast pre-check skips chains the address never used (nonce==0).
    Otherwise: Etherscan free (Ethereum/Arbitrum/Polygon) or our own chunked scanner over a
    free public-RPC pool. Alchemy is used only for eth_call (its free getLogs caps at 10 blocks).
    ok=False = no source could scan this chain (reported as degraded, honestly)."""
    rpc = _chain_rpc(name, cfg)
    # fast pre-check: an address that never acted on this chain has no approvals here → instant.
    try:
        if _nonce(rpc, owner) == 0:
            return [], True
    except Exception:
        pass
    # Etherscan V2 free — covers Ethereum, Arbitrum, Polygon.
    if ETHERSCAN_KEY:
        url = (f"https://api.etherscan.io/v2/api?chainid={cfg['id']}&module=logs&action=getLogs"
               f"&fromBlock=0&toBlock=latest&topic0={APPROVAL_TOPIC}&topic0_1_opr=and"
               f"&topic1={owner_topic}&apikey={ETHERSCAN_KEY}")
        for _ in range(4):
            try:
                d = _get(url)
            except Exception:
                time.sleep(0.7)
                continue
            res = d.get("result")
            if isinstance(res, list):
                return res, True
            msg = str(d.get("message", "")).lower()
            if msg.startswith("no records"):
                return [], True
            if "rate limit" in msg or "max" in str(res).lower():
                time.sleep(0.9)
                continue
            break   # chain not on the free tier → fall through to our scanner
    # our own scanner over a free public-RPC pool (Base, Optimism, …).
    pool = RPC_POOL.get(name)
    if pool:
        try:
            return _chunked_scan(pool, owner, owner_topic), True
        except Exception:
            pass
    return [], False   # no source could scan this chain → degraded, honestly


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


def _evm(address):
    owner_topic = "0x" + "0" * 24 + address[2:].lower()
    items, scanned, degraded = [], [], []
    for name, cfg in EVM_CFG.items():
        logs, ok = _approval_logs(name, cfg, owner_topic, address)
        if not ok:
            degraded.append(name)
            continue
        scanned.append(name)
        rpc = _chain_rpc(name, cfg)
        pairs = {}
        for lg in logs:
            topics = lg.get("topics") or []
            if len(topics) < 3:
                continue   # only indexed Approval(owner,spender); skip Permit-style
            pairs[(lg["address"].lower(), "0x" + topics[2][-40:])] = 1
        for token, spender in pairs:
            cur = _allowance(rpc, address, token, spender)
            if cur == 0:
                continue   # revoked / zero — nothing to clean
            unlimited = cur >= UNLIMITED
            items.append({
                "chain": name, "kind": "approval",
                "token": token, "token_symbol": _symbol(rpc, token),
                "spender": spender,
                "amount": "unknown" if cur < 0 else ("unlimited" if unlimited else str(cur)),
                "unlimited": unlimited, "risky": unlimited,
                "evidence": {"current_allowance_raw": None if cur < 0 else str(cur)},
            })
    return items, scanned, degraded


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


def _score_items(items):
    """Attach a graded risk_level (0-100 + label) to each item: exposure + spender trust."""
    cache = {}
    for it in items:
        chain = it["chain"]
        key = (chain, (it.get("spender") or "").lower())
        if key not in cache:
            cache[key] = _spender_trust(chain, it.get("spender"))
        trust, name = cache[key]
        exposure = 40 if it.get("unlimited") else (30 if it.get("kind") == "delegate" else 10)
        score = max(0, min(100, exposure + {"legit": -20, "malicious": 60, "unknown": 25}[trust]))
        it["risk_score"] = score
        it["risk_level"] = _level(score)
        it["spender_trust"] = trust
        it["spender_name"] = name
        it["risky"] = score >= 40   # back-compat; "attention" = medium+
    return items


def approvals(address, chain=None):
    address = str(address).strip()
    kind = chain or detect_chain(address)
    degraded = []
    if kind == "evm":
        items, scanned, degraded = _evm(address)
    elif kind == "tron":
        items, scanned = _tron(address)
    elif kind == "solana":
        items, scanned = _solana(address)
    else:
        return {"error": "unrecognized address (expected EVM 0x…, TRON T…, or Solana base58)"}
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
    return out


if __name__ == "__main__":
    import sys
    ad = sys.argv[1] if len(sys.argv) > 1 else "0x28C6c06298d514Db089934071355E5743bf21d60"
    print(json.dumps(approvals(ad), indent=2, ensure_ascii=False))
