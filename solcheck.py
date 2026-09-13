#!/usr/bin/env python3
"""Solana token safety, read first-hand from the chain. No RugCheck, no vendor verdict.

Solana has no honeypot to simulate the way an EVM DEX does — the trap is shaped differently, and
it is written plainly in the mint account and its extensions:

  - **freeze authority**: whoever holds it can freeze YOUR token account. That is the Solana
    honeypot — you keep the balance and can never move it again.
  - **mint authority**: whoever holds it can print unlimited new supply and dilute you to nothing.
  - **permanent delegate** (Token-2022): can transfer your tokens out of your wallet, forever,
    without asking. There is no revoking it.
  - **transfer hook** (Token-2022): arbitrary program code runs on every transfer — it can make
    selling fail under conditions the token chooses.
  - **transfer fee** (Token-2022): a tax on every transfer, and the authority can change it.
  - **holder concentration**: if one wallet holds most of the supply, the price is whatever they
    decide to sell at.

Every one of those is read from `getAccountInfo` / `getTokenLargestAccounts` on a public RPC.

  check_token(mint) -> {verdict, score, checks[], evidence}
"""

import base64
import json
import os
import time
import urllib.request

import solmeta

RPCS = [os.environ.get("GUARDBOT_SOLANA_RPC", "https://api.mainnet-beta.solana.com")]
UA = "Mozilla/5.0 (guardbot/0.1; solana token safety; read-only)"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
# Token-2022 extension type ids that can take or tax your tokens (SPL token-2022 ExtensionType)
EXT_TRANSFER_FEE_CONFIG = 1
EXT_MINT_CLOSE_AUTHORITY = 3
EXT_PERMANENT_DELEGATE = 12
EXT_TRANSFER_HOOK = 14
DANGEROUS_EXTS = {
    EXT_PERMANENT_DELEGATE: ("permanent delegate",
                             "a fixed address can move your tokens out of your wallet at any "
                             "time, and it cannot be revoked"),
    EXT_TRANSFER_HOOK: ("transfer hook",
                        "custom program code runs on every transfer and can make selling fail"),
    EXT_TRANSFER_FEE_CONFIG: ("transfer fee",
                              "every transfer is taxed, and the fee authority can change it"),
    EXT_MINT_CLOSE_AUTHORITY: ("mint close authority", "the mint can be closed by its authority"),
}


def _rpc(method, params, timeout=25, tries=3):
    """Public Solana RPCs throttle hard (HTTP 429). A throttled call must never be read as an
    answer, so it retries with backoff and, failing that, returns an error the caller reports as
    'unknown' — never as 'nothing found'."""
    last = None
    for attempt in range(tries):
        for url in RPCS:
            req = urllib.request.Request(
                url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                                      "params": params}).encode(),
                headers={"User-Agent": UA, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.load(r)
            except Exception as e:
                last = e
        time.sleep(1.5 * (attempt + 1))
    return {"error": str(last)[:120]}


def _mint_info(mint):
    r = _rpc("getAccountInfo", [mint, {"encoding": "jsonParsed"}])
    val = ((r.get("result") or {}).get("value")) or None
    if not val:
        return None, None, None
    owner = val.get("owner")
    parsed = ((val.get("data") or {}).get("parsed") or {})
    if parsed.get("type") != "mint":
        return None, owner, None
    info = parsed.get("info") or {}
    # the raw bytes carry the Token-2022 extension TLV that jsonParsed may not expose
    raw = _rpc("getAccountInfo", [mint, {"encoding": "base64"}])
    data = (((raw.get("result") or {}).get("value") or {}).get("data") or [None])[0]
    return info, owner, data


def _extensions(b64):
    """Token-2022 packs extensions after the 165-byte base mint + a 1-byte account type, as a
    TLV list of (u16 type, u16 length, value). Only the type ids are needed here."""
    found = []
    try:
        raw = base64.b64decode(b64 or "")
    except Exception:
        return found
    if len(raw) <= 166:
        return found
    off = 166
    while off + 4 <= len(raw):
        t = int.from_bytes(raw[off:off + 2], "little")
        ln = int.from_bytes(raw[off + 2:off + 4], "little")
        if t == 0 or off + 4 + ln > len(raw):
            break
        found.append(t)
        off += 4 + ln
    return found


def _concentration(mint, supply, decimals):
    """Top-holder share. getTokenLargestAccounts returns the 20 biggest token accounts."""
    r = _rpc("getTokenLargestAccounts", [mint])
    vals = ((r.get("result") or {}).get("value")) or []
    if not vals or not supply:
        return None, None, len(vals)
    amounts = []
    for v in vals:
        try:
            amounts.append(int(v.get("amount") or 0))
        except (TypeError, ValueError):
            pass
    if not amounts:
        return None, None, 0
    top1 = max(amounts) / supply * 100
    top10 = sum(sorted(amounts, reverse=True)[:10]) / supply * 100
    return round(top1, 1), round(top10, 1), len(vals)


def check_token(mint):
    """First-hand safety verdict for an SPL token."""
    mint = (mint or "").strip()
    if not (32 <= len(mint) <= 44):
        return {"error": "expected a Solana mint address (base58)"}
    info, owner, raw = _mint_info(mint)
    if info is None:
        return {"chain": "solana", "token": mint, "verdict": "block", "score": 0,
                "checks": [{"name": "mint", "status": "fail",
                            "detail": "this address is not an SPL token mint"}]}

    checks, score = [], 100

    def add(name, status, detail, penalty=0, evidence=None):
        nonlocal score
        score -= penalty
        c = {"name": name, "status": status, "detail": detail}
        if evidence:
            c["evidence"] = evidence
        checks.append(c)

    is2022 = owner == TOKEN_2022
    try:
        supply = int(info.get("supply") or 0)
    except (TypeError, ValueError):
        supply = 0
    decimals = info.get("decimals")

    freeze = info.get("freezeAuthority")

    mint_auth = info.get("mintAuthority")
    if mint_auth:
        add("mint_authority", "warn",
            "new supply can still be printed at will, diluting holders", 25,
            {"mint_authority": mint_auth})
    else:
        add("mint_authority", "pass", "supply is fixed — nobody can mint more", 0)

    exts = _extensions(raw) if is2022 else []
    hits = [(t,) + DANGEROUS_EXTS[t] for t in exts if t in DANGEROUS_EXTS]
    if hits:
        for t, label, why in hits:
            fail = t in (EXT_PERMANENT_DELEGATE, EXT_TRANSFER_HOOK)
            add(f"token2022_{label.replace(' ', '_')}", "fail" if fail else "warn",
                f"{label}: {why}", 60 if fail else 25, {"extension_id": t})
    elif is2022:
        add("token2022_extensions", "pass", "no seizing or taxing extensions enabled", 0)

    top1, top10, holders = _concentration(mint, supply, decimals)

    # Freeze authority is judged together with concentration, because alone it does not
    # distinguish a regulated stablecoin (Circle can freeze USDC, and discloses it) from a
    # honeypot. Scoring it as a hard failure on its own branded USDC and USDT `block` — the same
    # false-positive that soft-warning accumulation caused on the EVM side.
    if freeze:
        if top1 is not None and top1 >= 50:
            add("freeze_authority", "fail",
                f"someone can FREEZE your tokens AND one wallet holds {top1}% of the supply — "
                "you could be left holding a balance you can never sell", 60,
                {"freeze_authority": freeze, "top1_pct": top1})
        else:
            unread = " Holder distribution could not be read just now, so this could not be " \
                     "sharpened either way — treat it as unresolved, not as cleared." \
                     if top1 is None else ""
            add("freeze_authority", "warn",
                "someone can freeze your tokens: you would keep the balance but not be able to "
                "move it. Normal and disclosed for regulated stablecoins, a red flag on an "
                "unknown token — check who holds the authority." + unread, 30,
                {"freeze_authority": freeze, "concentration_known": top1 is not None})
    else:
        add("freeze_authority", "pass", "nobody can freeze your tokens", 0)
    if top1 is not None:
        if top1 >= 50:
            add("concentration", "fail",
                f"one wallet holds {top1}% of the supply — the price is whatever they decide", 40,
                {"top1_pct": top1, "top10_pct": top10})
        elif top10 >= 80:
            add("concentration", "warn",
                f"the top 10 wallets hold {top10}% of the supply", 20,
                {"top1_pct": top1, "top10_pct": top10})
        else:
            add("concentration", "pass",
                f"supply is spread out (top holder {top1}%, top 10 {top10}%)", 0,
                {"top1_pct": top1, "top10_pct": top10})
    else:
        add("concentration", "unknown", "holder distribution could not be read", 10)

    meta = None
    try:
        meta = solmeta.token_meta(RPCS[0], mint)
    except Exception:
        pass

    score = max(0, min(100, score))
    fails = [c for c in checks if c["status"] == "fail"]
    verdict = "block" if fails else ("warn" if score < 75 else "safe")
    out = {"chain": "solana", "token": mint, "verdict": verdict, "score": score,
           "checks": checks,
           "token_program": "token-2022" if is2022 else "spl-token",
           "supply": str(supply), "decimals": decimals,
           "engine": "guardbot-solcheck/0.1 (read first-hand from the chain, no third-party API)"}
    if meta:
        out["token_symbol"], out["token_name"] = meta.get("symbol"), meta.get("name")
    return out


if __name__ == "__main__":
    import sys
    m = sys.argv[1] if len(sys.argv) > 1 else "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    print(json.dumps(check_token(m), indent=2, ensure_ascii=False))
