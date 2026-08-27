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


def _approval_logs(name, cfg, owner_topic):
    """Return (logs, ok). ok=False means the chain could not be scanned (needs a key)."""
    if ALCHEMY_KEY and name in ALCHEMY_NET:
        url = f"https://{ALCHEMY_NET[name]}.g.alchemy.com/v2/{ALCHEMY_KEY}"
        for _ in range(3):
            try:
                logs = _rpc(url, "eth_getLogs",
                            [{"fromBlock": "0x0", "toBlock": "latest",
                              "topics": [APPROVAL_TOPIC, owner_topic]}])
                return (logs or []), True
            except Exception:
                time.sleep(0.5)
        return [], False
    if ETHERSCAN_KEY:
        url = (f"https://api.etherscan.io/v2/api?chainid={cfg['id']}&module=logs&action=getLogs"
               f"&fromBlock=0&toBlock=latest&topic0={APPROVAL_TOPIC}&topic0_1_opr=and"
               f"&topic1={owner_topic}&apikey={ETHERSCAN_KEY}")
        for attempt in range(4):
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
                return [], True   # valid empty answer
            # rate limit / busy on the free tier → back off and retry
            if "rate limit" in msg or "max" in str(res).lower() or str(d.get("status")) == "0":
                time.sleep(0.9)
                continue
            return [], False
        return [], False
    if cfg["logs_ok"]:
        try:
            logs = _rpc(cfg["rpc"], "eth_getLogs",
                        [{"fromBlock": "0x0", "toBlock": "latest",
                          "topics": [APPROVAL_TOPIC, owner_topic]}])
            return (logs or []), True
        except Exception:
            return [], False
    return [], False   # no key + RPC won't do full range → degraded, reported honestly


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
        if ALCHEMY_KEY or ETHERSCAN_KEY:
            time.sleep(0.2)    # stay under free-tier rate limits
        logs, ok = _approval_logs(name, cfg, owner_topic)
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
    risky = [i for i in items if i.get("risky")]
    out = {
        "address": address, "address_type": kind, "chains_scanned": scanned,
        "count": len(items), "risky_count": len(risky),
        "items": sorted(items, key=lambda i: (not i["risky"], not i["unlimited"])),
        "engine": "guardbot-approvals/0.1",
    }
    if degraded:
        out["degraded_chains"] = degraded
        out["note"] = ("For complete multi-chain coverage set a free Alchemy key "
                       "(GUARDBOT_ALCHEMY_KEY) — one key covers Ethereum, Base, Arbitrum, "
                       "Optimism, Polygon, BSC. These chains couldn't be scanned with the "
                       "current sources.")
    return out


if __name__ == "__main__":
    import sys
    ad = sys.argv[1] if len(sys.argv) > 1 else "0x28C6c06298d514Db089934071355E5743bf21d60"
    print(json.dumps(approvals(ad), indent=2, ensure_ascii=False))
