#!/usr/bin/env python3
"""GuardBot — pre-trade safety wrapper.

assess(chain, address) -> normalized verdict {verdict, score, checks[], sources}.
Aggregates RugCheck (Solana, the authority) + GoPlus (EVM). Every check carries its
evidence ("no verdict without proof"). If a source is down, it degrades gracefully
instead of failing.

No external dependencies (urllib stdlib). Does not route trades or touch funds:
it only reads public data and returns a verdict.
"""

import json
import re
import urllib.request
import urllib.error

UA = "guardbot/0.1 (+pre-trade safety; read-only)"
TIMEOUT = 12

EVM_CHAINS = {
    "ethereum": "1", "eth": "1", "1": "1",
    "bsc": "56", "bnb": "56", "56": "56",
    "base": "8453", "8453": "8453",
    "arbitrum": "42161", "arb": "42161", "42161": "42161",
    "polygon": "137", "matic": "137", "137": "137",
    "optimism": "10", "op": "10", "10": "10",
    "avalanche": "43114", "avax": "43114", "43114": "43114",
}
SOLANA = {"solana", "sol"}

RANK = {"safe": 0, "warn": 1, "block": 2}


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def _num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _check(name, status, detail, evidence=None):
    return {"name": name, "status": status, "detail": detail, "evidence": evidence}


# ---------------- Solana via RugCheck ----------------
def _assess_solana(mint):
    try:
        d = _get(f"https://api.rugcheck.xyz/v1/tokens/{mint}/report")
    except Exception as e:
        return None, f"rugcheck unavailable: {str(e)[:120]}"

    checks = []
    if d.get("rugged") is True:
        checks.append(_check("rugged", "block", "RugCheck flagged this token as RUGGED", {"rugged": True}))

    if d.get("mintAuthority"):
        checks.append(_check("mint_authority", "warn",
                             "Mint authority ACTIVE: supply can be inflated",
                             {"mintAuthority": d["mintAuthority"]}))
    if d.get("freezeAuthority"):
        checks.append(_check("freeze_authority", "warn",
                             "Freeze authority ACTIVE: transfers can be frozen",
                             {"freezeAuthority": d["freezeAuthority"]}))

    tf = d.get("transferFee")
    if isinstance(tf, dict):
        pct = _num(tf.get("pct"))
        if pct >= 10:
            checks.append(_check("transfer_fee", "block", f"Very high transfer fee: {pct}%", tf))
        elif pct > 0:
            checks.append(_check("transfer_fee", "warn", f"Transfer fee: {pct}%", tf))

    liq = _num(d.get("totalMarketLiquidity"))
    if liq and liq < 5000:
        checks.append(_check("liquidity", "warn", f"Low liquidity: ${int(liq):,}", {"totalMarketLiquidity": liq}))

    known = d.get("knownAccounts") or {}
    top = d.get("topHolders") or []
    for h in top[:5]:
        addr = h.get("address")
        pct = _num(h.get("pct"))
        if addr in known:
            continue
        if pct >= 50:
            checks.append(_check("holder_concentration", "block",
                                 f"A single holder owns {pct:.1f}%", {"address": addr, "pct": pct}))
        elif pct >= 25:
            checks.append(_check("holder_concentration", "warn",
                                 f"Concentrated holder: {pct:.1f}%", {"address": addr, "pct": pct}))
        break

    for risk in (d.get("risks") or []):
        lvl = str(risk.get("level", "")).lower()
        status = "block" if lvl in ("danger", "high") else "warn" if lvl in ("warn", "warning", "medium") else "info"
        if status == "info":
            continue
        checks.append(_check(f"rugcheck:{risk.get('name', 'risk')}", status,
                             risk.get("description") or risk.get("name") or "flagged risk",
                             {"level": lvl, "score": risk.get("score"), "value": risk.get("value")}))

    meta = {
        "rugcheck_score_normalised": d.get("score_normalised"),
        "total_holders": d.get("totalHolders"),
        "total_market_liquidity": d.get("totalMarketLiquidity"),
        "token_name": ((d.get("tokenMeta") or {}).get("name")),
        "launchpad": d.get("launchpad"),
    }
    return {"checks": checks, "meta": meta, "source": "rugcheck"}, None


# ---------------- EVM via GoPlus ----------------
def _assess_evm(chain_id, address):
    addr = address.lower()
    try:
        d = _get(f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={addr}")
    except Exception as e:
        return None, f"goplus unavailable: {str(e)[:120]}"
    res = (d.get("result") or {})
    t = res.get(addr) or (next(iter(res.values())) if res else None)
    if not t:
        return None, "goplus: no data for this token/chain"

    checks = []

    def yes(k):
        return str(t.get(k, "0")) == "1"

    if yes("is_honeypot"):
        checks.append(_check("honeypot", "block", "HONEYPOT: you cannot sell", {"is_honeypot": "1"}))
    if yes("cannot_sell_all"):
        checks.append(_check("cannot_sell_all", "block", "Cannot sell the full balance", {"cannot_sell_all": "1"}))
    if yes("cannot_buy"):
        checks.append(_check("cannot_buy", "warn", "Buying is blocked/limited", {"cannot_buy": "1"}))
    if yes("honeypot_with_same_creator"):
        checks.append(_check("creator_honeypots", "block", "Creator has shipped honeypots before", {"honeypot_with_same_creator": "1"}))

    for tax_field, label in [("sell_tax", "sell"), ("buy_tax", "buy"), ("transfer_tax", "transfer")]:
        tax = _num(t.get(tax_field))
        if tax >= 0.5:
            checks.append(_check(tax_field, "block", f"Very high {label} tax: {tax*100:.0f}%", {tax_field: t.get(tax_field)}))
        elif tax > 0.1:
            checks.append(_check(tax_field, "warn", f"{label.capitalize()} tax: {tax*100:.0f}%", {tax_field: t.get(tax_field)}))

    if str(t.get("is_open_source", "1")) == "0":
        checks.append(_check("open_source", "warn", "Contract is NOT verified (closed source)", {"is_open_source": "0"}))
    if yes("is_mintable"):
        checks.append(_check("mintable", "warn", "Mintable: supply can grow", {"is_mintable": "1"}))
    if yes("transfer_pausable"):
        checks.append(_check("pausable", "warn", "Transfers can be paused", {"transfer_pausable": "1"}))
    if yes("hidden_owner"):
        checks.append(_check("hidden_owner", "warn", "Hidden owner", {"hidden_owner": "1"}))
    if yes("selfdestruct"):
        checks.append(_check("selfdestruct", "block", "The contract can self-destruct", {"selfdestruct": "1"}))
    if yes("owner_change_balance"):
        checks.append(_check("owner_change_balance", "block", "The owner can change balances", {"owner_change_balance": "1"}))

    meta = {
        "token_name": t.get("token_name"), "token_symbol": t.get("token_symbol"),
        "holder_count": t.get("holder_count"), "is_in_dex": t.get("is_in_dex"),
        "buy_tax": t.get("buy_tax"), "sell_tax": t.get("sell_tax"),
    }
    return {"checks": checks, "meta": meta, "source": "goplus"}, None


# ---------------- public API ----------------
def assess(chain, address):
    chain = str(chain).strip().lower()
    address = str(address).strip()
    if not address:
        return {"error": "missing address"}

    if chain in SOLANA:
        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
            return {"error": "invalid Solana mint"}
        result, err = _assess_solana(address)
    elif chain in EVM_CHAINS:
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            return {"error": "invalid EVM address"}
        result, err = _assess_evm(EVM_CHAINS[chain], address)
    else:
        return {"error": f"unsupported chain: {chain}",
                "supported": ["solana"] + sorted(set(EVM_CHAINS))}

    if err:
        # source down: explicit 'warn' verdict, never a false 'safe'
        return {"chain": chain, "address": address, "verdict": "warn", "score": 50,
                "checks": [_check("source_unavailable", "warn", err)],
                "sources": [], "degraded": True}

    checks = result["checks"]
    worst = max([RANK[c["status"]] for c in checks if c["status"] in RANK], default=0)
    verdict = ["safe", "warn", "block"][worst]
    # score 0-100 (100 = safest): start at 100, penalize by severity
    penalty = sum({"warn": 12, "block": 45}.get(c["status"], 0) for c in checks)
    score = max(0, 100 - penalty)
    return {
        "chain": chain, "address": address,
        "verdict": verdict, "score": score,
        "checks": checks, "sources": [result["source"]],
        "meta": result.get("meta", {}),
        "engine": "guardbot/0.1",
    }


if __name__ == "__main__":
    import sys
    ch = sys.argv[1] if len(sys.argv) > 2 else "solana"
    ad = sys.argv[2] if len(sys.argv) > 2 else "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    print(json.dumps(assess(ch, ad), indent=2, ensure_ascii=False))
