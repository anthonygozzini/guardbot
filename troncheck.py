#!/usr/bin/env python3
"""TRON TRC-20 token safety, read first-hand from the chain. No TronScan verdict, no vendor API.

TRON runs an EVM, so a TRC-20 is ERC-20 bytecode with the same function selectors, and the same
first-hand technique applies: read the deployed bytecode and see which privileged functions are
actually in it (mint, blacklist, pause, fee setters), and read the owner. This is done through
TronGrid's node endpoints (`getcontract`, `triggerconstantcontract`) — the TRON equivalent of an
RPC, i.e. reading chain state, not asking an explorer for its opinion.

Honest limit, stated up front: the EVM buy-and-sell honeypot SIMULATION does not port to TRON.
TRON's public endpoints don't offer the state override that lets us hand a throwaway address a
balance and try to sell, so "can you sell it back?" can't be proven here the way it is on EVM.
What CAN be established first-hand — dangerous functions in the bytecode, mint/blacklist/pause
authority, the owner — catches the most common TRC-20 traps (USDT-TRON's own blacklist included).

  check_token(token) -> {verdict, score, checks[], evidence}
"""

import json
import urllib.request

import solmeta
from keccak import selector

TRONGRID = ["https://api.trongrid.io"]
UA = "Mozilla/5.0 (guardbot/0.1; tron token safety; read-only)"

# Same selectors as EVM (TRON is EVM-compatible), computed with our own keccak, never copied.
DANGEROUS_SIGS = {
    "mint(address,uint256)": "can mint new supply",
    "mint(uint256)": "can mint new supply",
    "addBlackList(address)": "can blacklist holders (freeze their tokens)",
    "removeBlackList(address)": "maintains a blacklist",
    "blacklist(address)": "can blacklist holders",
    "isBlackListed(address)": "maintains a blacklist",
    "pause()": "can pause all transfers",
    "setFees(uint256,uint256)": "can change fees",
    "setBasisPointsRate(uint256)": "can set a transfer fee rate (USDT-style)",
    "setParams(uint256,uint256)": "can change fee params",
    "issue(uint256)": "can issue new supply",
    "redeem(uint256)": "supply can be redeemed by the owner",
    "destroyBlackFunds(address)": "can DESTROY a blacklisted holder's balance",
}


def b58_to_hex(addr):
    """TRON base58check address -> 21-byte hex (0x41 prefix + 20). Returns None if not TRON-shaped."""
    try:
        raw = solmeta.b58decode(addr)
        if len(raw) < 21 or raw[0] != 0x41:
            return None
        return raw[:21].hex()
    except Exception:
        return None


def _post(path, body, timeout=25):
    last = None
    for base in TRONGRID:
        req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                     headers={"User-Agent": UA, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:
            last = e
    return {"error": str(last)[:120]}


def _const(token_hex, sig):
    """triggerconstantcontract: read a constant method. Returns the raw hex result or None."""
    r = _post("/wallet/triggerconstantcontract",
              {"owner_address": token_hex, "contract_address": token_hex,
               "function_selector": sig, "visible": False})
    cr = r.get("constant_result") or []
    return cr[0] if cr else None


def _string(token_hex, sig):
    raw = _const(token_hex, sig)
    if not raw or len(raw) < 128:
        return None
    try:
        b = bytes.fromhex(raw)
        return b[64:].split(b"\x00")[0].decode("utf-8", "ignore").strip() or None
    except Exception:
        return None


def check_token(token):
    """First-hand safety verdict for a TRC-20 token."""
    token = (token or "").strip()
    thex = b58_to_hex(token)
    if not thex:
        return {"error": "expected a TRON address (T…)"}

    got = _post("/wallet/getcontract", {"value": thex, "visible": False})
    if got.get("error"):
        return {"error": f"could not reach TRON node: {got['error']}"}
    bytecode = (got.get("bytecode") or "").lower()
    if not bytecode:
        return {"chain": "tron", "token": token, "verdict": "block", "score": 0,
                "checks": [{"name": "contract", "status": "fail",
                            "detail": "no contract code at this address — not a TRC-20 token"}]}

    checks, score = [], 100

    def add(name, status, detail, penalty=0, evidence=None):
        nonlocal score
        score -= penalty
        c = {"name": name, "status": status, "detail": detail}
        if evidence:
            c["evidence"] = evidence
        checks.append(c)

    # dangerous functions actually present in the deployed bytecode
    found = []
    for sig, why in DANGEROUS_SIGS.items():
        if selector(sig)[2:] in bytecode:
            found.append({"function": sig, "meaning": why})
    # destroyBlackFunds is the outright-seizure vector (the classic TRON scam) → hard fail
    seize = [f for f in found if "DESTROY" in f["meaning"]]
    blacklist = [f for f in found if "blacklist" in f["meaning"].lower()]
    if seize:
        # A seizure capability is real and worth shouting about, but on its own it does not tell
        # Tether (USDT-TRON genuinely has destroyBlackFunds, and discloses it) from a scam. So it
        # is a heavy WARN, not an automatic block — the same lesson as EVM freeze / Solana freeze.
        add("seize_funds", "warn",
            "the code can DESTROY a blacklisted holder's balance — a blacklisted wallet loses its "
            "tokens outright. Real and disclosed for USDT-TRON; on an unknown token, a strong "
            "red flag — see who holds the owner key", 45, {"functions": seize})
    elif blacklist:
        add("blacklist", "warn",
            "holders can be blacklisted (their tokens frozen). Disclosed and normal for a "
            "regulated stablecoin like USDT-TRON, a red flag on an unknown token", 25,
            {"functions": blacklist})
    other = [f for f in found if f not in seize and f not in blacklist]
    if other:
        names = ", ".join(f["meaning"] for f in other[:4])
        add("privileged_functions", "warn",
            f"the deployed code contains {len(other)} more privileged function(s): {names}",
            min(25, 6 * len(other)), {"functions": other})
    if not found:
        add("privileged_functions", "pass", "no known privileged functions in the bytecode", 0)

    # owner: renounced (zero) or still in control
    for sig in ("owner()", "getOwner()"):
        raw = _const(thex, sig)
        if raw and len(raw) >= 64:
            owner_hex = raw[-40:]
            renounced = int(owner_hex, 16) == 0
            add("ownership", "pass" if renounced else "warn",
                "ownership renounced" if renounced
                else "an owner is still in control of the privileged functions above",
                0 if renounced else 10, {"owner": "41" + owner_hex})
            break

    add("sell_simulation", "unknown",
        "TRON's public endpoints don't allow the buy-and-sell honeypot simulation GuardBot runs "
        "on EVM, so 'can you sell it?' is not proven here — judge from the functions above", 0)

    symbol = _string(thex, "symbol()")
    name = _string(thex, "name()")
    score = max(0, min(100, score))
    fails = [c for c in checks if c["status"] == "fail"]
    verdict = "block" if fails else ("warn" if score < 75 else "safe")
    return {"chain": "tron", "token": token, "verdict": verdict, "score": score,
            "checks": checks, "token_symbol": symbol, "token_name": name,
            "engine": "guardbot-troncheck/0.1 (bytecode + authorities read first-hand, no vendor API)"}


if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    print(json.dumps(check_token(t), indent=2, ensure_ascii=False))
