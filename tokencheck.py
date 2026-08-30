#!/usr/bin/env python3
"""GuardBot — our own token-safety engine. No GoPlus, no RugCheck, no honeypot.is.

Everything here is derived from the chain itself, through plain `eth_call` against public
RPCs. The core trick is that `eth_call` accepts a **state override**: we can hand a throwaway
address some native coin and then execute a real buy-and-sell against live liquidity, without
signing anything, spending anything, or asking a third party what they think of the token.

  check_token(chain, token) -> {verdict, score, checks[], evidence}

What it establishes, first-hand:
  - can you BUY it, and what does the buy really cost you (fee-on-transfer buy tax);
  - can you SELL it back — the honeypot question — and what the sell really returns;
  - how deep the liquidity is, and how much of the LP is burned (rug distance);
  - whether ownership is renounced, whether it's an upgradeable proxy;
  - which dangerous functions actually exist in the deployed bytecode (mint, blacklist,
    pause, fee setters), read from the code, not from a label someone else assigned.

A failed simulation is never taken at face value: a sell that fails is retried, on another
RPC, before it is allowed to become a verdict. A transient node error must not brand a token
a honeypot — that is how a safety tool loses the right to be trusted.
"""

import concurrent.futures
import json
import os
import urllib.error
import urllib.request

from keccak import keccak256, selector

UA = "Mozilla/5.0 (guardbot/0.1; token safety; read-only)"
TIMEOUT = 30
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
BURN = ["0x000000000000000000000000000000000000dead",
        "0x0000000000000000000000000000000000000000"]
PROBE_EOA = "0x00000000000000000000000000000000deadbe02"
START_BAL = 10 ** 19          # native coin handed to the throwaway address in the override
DEADLINE = 9999999999
MAX_UINT = (1 << 256) - 1
SIM_GAS = 8_000_000
# We deliberately sell slightly less than we bought, to absorb rounding. Every figure derived
# from the round trip must divide by this, or a clean token appears to charge a ~1.6% tax that
# is really just our own margin — a measurement artefact reported as the token's behaviour.
SELL_FRACTION = 0.99

# Only the ROUTER is configured. Its WETH() and factory() are read from the chain, so a wrong
# guess here fails loudly instead of silently analysing the wrong venue.
ROUTERS = {
    "bsc":      ["0x10ED43C718714eb63d5aA57B78B54704E256024E"],   # PancakeSwap V2
    "ethereum": ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"],   # Uniswap V2
    "base":     ["0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"],   # Uniswap V2 (Base)
    "arbitrum": ["0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"],   # SushiSwap V2
    "polygon":  ["0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff"],   # QuickSwap V2
}
RPCS = {
    "bsc": ["https://bsc-dataseed.binance.org", "https://bsc-rpc.publicnode.com",
            "https://56.rpc.thirdweb.com"],
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com",
                 "https://1.rpc.thirdweb.com"],
    "base": ["https://mainnet.base.org", "https://base.drpc.org"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"],
    # Optimism has no Uniswap-V2 venue (liquidity is on Velodrome, whose router takes a
    # different route struct), so it is covered through the V3 path only.
    "optimism": ["https://mainnet.optimism.io", "https://optimism-rpc.publicnode.com"],
}
BUY_AMOUNT = {"bsc": 10 ** 16, "ethereum": 10 ** 16, "base": 10 ** 15,
              "arbitrum": 10 ** 15, "polygon": 10 ** 18, "optimism": 10 ** 15}

# Functions whose mere presence in the deployed bytecode is worth knowing about. Selectors are
# computed from the signatures with our own keccak — nothing is copied from a vendor list.
DANGEROUS_SIGS = {
    "mint(address,uint256)": "can mint new supply",
    "mint(uint256)": "can mint new supply",
    "blacklist(address,bool)": "can blacklist holders",
    "addBlackList(address)": "can blacklist holders",
    "setBlacklist(address,bool)": "can blacklist holders",
    "pause()": "can pause transfers",
    "setTradingEnabled(bool)": "can switch trading off",
    "enableTrading()": "trading is gated by the owner",
    "setMaxTxAmount(uint256)": "can cap your transaction size",
    "setMaxWalletAmount(uint256)": "can cap your wallet size",
    "setFees(uint256,uint256)": "can change fees",
    "setTaxes(uint256,uint256)": "can change taxes",
    "setFeePercent(uint256)": "can change fees",
    "excludeFromFee(address)": "fee exemptions exist",
    "setSwapEnabled(bool)": "can switch swapping off",
}
# EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
PROXY_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def _w(x):
    return f"{int(x):064x}"


def _a32(a):
    return a.lower().replace("0x", "").rjust(64, "0")


def _rpc(url, method, params, timeout=TIMEOUT):
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                              "params": params}).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return {"error": {"message": e.read().decode()[:200]}}
        except Exception:
            return {"error": {"message": f"http {e.code}"}}
    except Exception as e:
        return {"error": {"message": str(e)[:120]}}


def _call(url, to, data, overrides=None, frm=None, value=None, block="latest"):
    tx = {"to": to, "data": data}
    if frm:
        tx["from"] = frm
    if value is not None:
        tx["value"] = hex(value)
        tx["gas"] = hex(SIM_GAS)
    params = [tx, block] + ([overrides] if overrides else [])
    r = _rpc(url, "eth_call", params)
    return r.get("result"), (r.get("error") or {}).get("message")


# ---------- ABI encoding for the few calls we make ----------
def _enc_call3value(calls):
    """aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[])"""
    head = [selector("aggregate3Value((address,bool,uint256,bytes)[])")[2:], _w(0x20), _w(len(calls))]
    bodies = []
    for tgt, allow, val, cd in calls:
        cd = cd[2:] if cd.startswith("0x") else cd
        nb = len(cd) // 2
        pad = "0" * (((32 - (nb % 32)) % 32) * 2)
        bodies.append(_a32(tgt) + _w(1 if allow else 0) + _w(val) + _w(0x80) + _w(nb) + cd + pad)
    off = 32 * len(calls)
    for b in bodies:
        head.append(_w(off))
        off += len(b) // 2
    return "0x" + "".join(head) + "".join(bodies)


def _dec_results(hexstr):
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


def _dec_uint_array(hexstr):
    d = hexstr[2:] if hexstr.startswith("0x") else hexstr

    def word(i):
        return int(d[i * 64:(i + 1) * 64], 16)

    base = word(0) // 32
    return [word(base + 1 + i) for i in range(word(base))]


def _enc_buy(min_out, path, to):
    return (selector("swapExactETHForTokens(uint256,address[],address,uint256)")
            + _w(min_out) + _w(0x80) + _a32(to) + _w(DEADLINE)
            + _w(len(path)) + "".join(_a32(p) for p in path))


def _enc_sell(amt_in, min_out, path, to):
    return (selector("swapExactTokensForETHSupportingFeeOnTransferTokens"
                     "(uint256,uint256,address[],address,uint256)")
            + _w(amt_in) + _w(min_out) + _w(0xa0) + _a32(to) + _w(DEADLINE)
            + _w(len(path)) + "".join(_a32(p) for p in path))


def _enc_amounts_out(amt_in, path):
    return (selector("getAmountsOut(uint256,address[])") + _w(amt_in) + _w(0x40)
            + _w(len(path)) + "".join(_a32(p) for p in path))


def _uint(res):
    try:
        return int(res, 16) if res and res != "0x" else 0
    except ValueError:
        return 0


def _venue(url, chain):
    """Resolve router -> (weth, factory) from the chain. Never assumed."""
    for router in ROUTERS.get(chain, []):
        weth, _ = _call(url, router, selector("WETH()"))
        fact, _ = _call(url, router, selector("factory()"))
        if weth and fact and _uint(weth) and _uint(fact):
            return router, "0x" + weth[-40:], "0x" + fact[-40:]
    return None, None, None


def _simulate(url, chain, token, router, weth, factory, block="latest"):
    """Buy the token with native coin, then sell it all back — atomically, in one eth_call,
    using Multicall3 as the throwaway holder. Returns the measured facts.

    Every call is pinned to ONE block. The buy is simulated twice (once to learn the amount,
    once inside the sell), and on a busy pool the reserves move between blocks — the second
    buy then yields slightly less than the first, the sell asks for more than is held, and it
    reverts. That is drift, not a honeypot, and it briefly branded USDT one. Pinning the block
    removes it; the margin below absorbs the remaining rounding."""
    out = {}
    amt = BUY_AMOUNT.get(chain, 10 ** 16)
    pair_res, _ = _call(url, factory, selector("getPair(address,address)") + _a32(token) + _a32(weth), block=block)
    pair = "0x" + pair_res[-40:] if pair_res else ""
    if not pair or _uint(pair_res) == 0:
        out["error"] = "no liquidity pair against the chain's wrapped native token"
        return out
    out["pair"] = pair
    res, _ = _call(url, router, _enc_amounts_out(amt, [weth, token]), block=block)
    if not res:
        out["error"] = "pair exists but quotes nothing (no liquidity)"
        return out
    expected = _dec_uint_array(res)[-1]
    out["expected_tokens"] = expected
    if expected == 0:
        out["error"] = "no liquidity"
        return out

    ov = {PROBE_EOA: {"balance": hex(START_BAL)}}
    buy = [(router, True, amt, _enc_buy(0, [weth, token], MULTICALL3)),
           (token, True, 0, selector("balanceOf(address)") + _a32(MULTICALL3))]
    res, err = _call(url, MULTICALL3, _enc_call3value(buy), ov, PROBE_EOA, amt, block)
    if not res:
        out["error"] = f"buy simulation unavailable: {err}"
        return out
    r = _dec_results(res)
    out["buy_ok"] = r[0][0]
    got = _uint(r[1][1]) if r[1][0] else 0
    out["tokens_received"] = got
    if not out["buy_ok"] or got == 0:
        out["sellable"] = False
        out["reason"] = "cannot_buy"
        return out
    out["buy_tax_pct"] = round(max(0.0, 1 - got / expected) * 100, 2)

    res, _ = _call(url, router, _enc_amounts_out(got, [token, weth]), block=block)
    exp_back = _dec_uint_array(res)[-1] if res else 0
    sell = [(router, True, amt, _enc_buy(0, [weth, token], MULTICALL3)),
            (token, True, 0, selector("approve(address,uint256)") + _a32(router) + _w(MAX_UINT)),
            (router, True, 0, _enc_sell(int(got * SELL_FRACTION), 0, [token, weth], PROBE_EOA)),
            (MULTICALL3, True, 0, selector("getEthBalance(address)") + _a32(PROBE_EOA))]
    res, err = _call(url, MULTICALL3, _enc_call3value(sell), ov, PROBE_EOA, amt, block)
    if not res:
        out["error"] = f"sell simulation unavailable: {err}"
        return out
    r = _dec_results(res)
    out["approve_ok"] = r[1][0]
    out["sellable"] = r[2][0]
    if not out["sellable"]:
        out["reason"] = "sell_reverted"
        return out
    back = _uint(r[3][1]) - (START_BAL - amt) if r[3][0] else 0
    out["native_back"] = back
    out["round_trip_pct"] = round(back / (amt * SELL_FRACTION) * 100, 2) if amt else 0
    if exp_back > 0:
        out["sell_tax_pct"] = round(max(0.0, 1 - back / (exp_back * SELL_FRACTION)) * 100, 2)
    return out


# A token that is beyond doubt sellable on each chain, used as the experiment's CONTROL.
CONTROL_TOKEN = {
    "bsc": "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",       # CAKE
    "ethereum": "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",      # USDC
    "arbitrum": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",  # USDC
    "polygon": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",   # USDC
    "optimism": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",  # USDC
}


WRAPPED_NATIVE = {
    "ethereum": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "bsc": "0xbb4CdB9CbD36B01bD1cBaEBF2De08d9173bc095c",
    "base": "0x4200000000000000000000000000000000000006",
    "arbitrum": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    "polygon": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    "optimism": "0x4200000000000000000000000000000000000006",
}
# Uniswap V3 SwapRouter02, verified at runtime via WETH9() rather than trusted from a list.
ROUTER_V3 = {
    "ethereum": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    "arbitrum": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    "optimism": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    "polygon": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    "base": "0x2626664c2603336E57B271c5C0b26F421741e481",
    "bsc": "0xB971eF87ede563556b2ED4b1C0b0019111Dd85d2",
}
SEL_EXACT_IN = selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))")


def _enc_exact_in(token_in, token_out, fee, recipient, amount_in):
    """exactInputSingle — all members static, so the struct encodes inline."""
    return (SEL_EXACT_IN + _a32(token_in) + _a32(token_out) + _w(fee) + _a32(recipient)
            + _w(amount_in) + _w(0) + _w(0))


def _best_v3_tier(url, chain, token, weth, block="latest"):
    """The fee tier whose pool actually holds the most wrapped-native — i.e. where you would
    really trade. Returns (fee, pool, depth) or (None, None, 0)."""
    f3 = FACTORY_V3.get(chain)
    if not f3:
        return None, None, 0
    best = (None, None, 0)
    for fee in FEE_TIERS:
        pool, _ = _call(url, f3, selector("getPool(address,address,uint24)")
                        + _a32(token) + _a32(weth) + f"{fee:064x}", block=block)
        if not pool or _uint(pool) == 0:
            continue
        p = "0x" + pool[-40:]
        bal, _ = _call(url, weth, selector("balanceOf(address)") + _a32(p), block=block)
        d = _uint(bal)
        if d > best[2]:
            best = (fee, p, d)
    return best


def _simulate_v3(url, chain, token, weth, block="latest"):
    """Same buy-then-sell-back proof, executed on Uniswap V3 for tokens that do not live on a
    V2 pair. Native coin is wrapped inside the same call (WETH.deposit), so nothing is held or
    spent; Multicall3 is still the throwaway holder."""
    out = {}
    v3router = ROUTER_V3.get(chain)
    if not v3router:
        out["error"] = "no V3 router known for this chain"
        return out
    fee, pool, depth = _best_v3_tier(url, chain, token, weth, block)
    if not fee:
        out["error"] = "no V2 pair and no V3 pool against the wrapped native token"
        return out
    out["pair"], out["v3_fee"], out["venue"] = pool, fee, "uniswap_v3"
    amt = BUY_AMOUNT.get(chain, 10 ** 16)
    ov = {PROBE_EOA: {"balance": hex(START_BAL)}}
    buy = [(weth, True, amt, selector("deposit()")),
           (weth, True, 0, selector("approve(address,uint256)") + _a32(v3router) + _w(MAX_UINT)),
           (v3router, True, 0, _enc_exact_in(weth, token, fee, MULTICALL3, amt)),
           (token, True, 0, selector("balanceOf(address)") + _a32(MULTICALL3))]
    res, err = _call(url, MULTICALL3, _enc_call3value(buy), ov, PROBE_EOA, amt, block)
    if not res:
        out["error"] = f"V3 buy simulation unavailable: {err}"
        return out
    r = _dec_results(res)
    out["buy_ok"] = r[2][0]
    got = _uint(r[3][1]) if r[3][0] else 0
    out["tokens_received"] = got
    if not out["buy_ok"] or got == 0:
        out["sellable"] = False
        out["reason"] = "cannot_buy"
        return out
    sell = buy + [
        (token, True, 0, selector("approve(address,uint256)") + _a32(v3router) + _w(MAX_UINT)),
        (v3router, True, 0, _enc_exact_in(token, weth, fee, MULTICALL3, int(got * SELL_FRACTION))),
        (weth, True, 0, selector("balanceOf(address)") + _a32(MULTICALL3))]
    res, err = _call(url, MULTICALL3, _enc_call3value(sell), ov, PROBE_EOA, amt, block)
    if not res:
        out["error"] = f"V3 sell simulation unavailable: {err}"
        return out
    r = _dec_results(res)
    out["sellable"] = r[5][0]
    if not out["sellable"]:
        out["reason"] = "sell_reverted"
        return out
    back = _uint(r[6][1]) if r[6][0] else 0
    out["native_back"] = back
    out["round_trip_pct"] = round(back / (amt * SELL_FRACTION) * 100, 2) if amt else 0
    fee_factor = (1 - fee / 1_000_000) ** 2
    expected = amt * SELL_FRACTION * fee_factor
    out["buy_tax_pct"] = 0.0
    out["sell_tax_pct"] = round(max(0.0, 1 - back / expected) * 100, 2) if expected else 0.0
    return out


def _confirm(chain, token, router, weth, factory, urls, block="latest"):
    """Simulate, and treat a FAILURE as a claim that must be proven before it becomes a verdict.

    A failed sell has two possible causes: the token blocks you, or the node hiccuped. They
    look identical in the response, and node hiccups do repeat across providers under load —
    we watched a plain retry brand USDT a honeypot twice in a row. So every failure is paired
    with a CONTROL: a token that is certainly sellable, simulated through the same node in the
    same moment. Control fails too -> it was the infrastructure, and the result is discarded.
    Control passes while the target fails -> the token really did it. Two such matched
    observations, on different providers, are required to call something a honeypot."""
    attempts, proven = [], 0
    control_token = CONTROL_TOKEN.get(chain)
    first_fail = None
    for url in urls:
        s = _simulate(url, chain, token, router, weth, factory, block)
        if s.get("error") and ("no liquidity" in s["error"] or "no liquidity pair" in s["error"]
                               or "quotes nothing" in s["error"]):
            # nothing to trade against on V2 — the token may simply live on V3, which is where
            # most non-BSC liquidity is. Prove it there instead of reporting it as unknown.
            v3 = _simulate_v3(url, chain, token, weth, block)
            if not v3.get("error"):
                s = v3
        attempts.append(s)
        if s.get("error"):
            continue                       # infrastructure problem, try elsewhere
        if s.get("sellable"):
            return s, attempts             # a success needs no second opinion
        if control_token and control_token.lower() != token.lower():
            c = _simulate(url, chain, control_token, router, weth, factory, block)
            if c.get("error") or not c.get("sellable"):
                s["control_failed_here"] = True
                continue                   # the node, not the token — this observation is void
        first_fail = first_fail or s
        proven += 1
        if proven >= 2:
            s["confirmations"] = proven
            return s, attempts
    if first_fail is not None:
        first_fail["unconfirmed"] = True    # failed against a healthy control, but only once
        return first_fail, attempts
    clean = [a for a in attempts if not a.get("error")]
    if clean:
        c = clean[0]
        c["unconfirmed"] = True
        return c, attempts
    return (attempts[-1] if attempts else {"error": "no RPC could simulate"}), attempts


def _bytecode_facts(url, token):
    """Read the deployed bytecode and report which dangerous functions are actually in it."""
    r = _rpc(url, "eth_getCode", [token, "latest"])
    code = r.get("result") or "0x"
    facts = {"is_contract": len(code) > 2, "code_size": (len(code) - 2) // 2}
    if not facts["is_contract"]:
        return facts
    body = code[2:]
    found = []
    for sig, why in DANGEROUS_SIGS.items():
        if selector(sig)[2:] in body:
            found.append({"function": sig, "meaning": why})
    facts["dangerous_functions"] = found
    return facts


_REGISTRY = None


def _registry(chain):
    """symbol -> contracts claiming it, mined from the chain (tools/mine_token_registry.py)."""
    global _REGISTRY
    if _REGISTRY is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token_registry.json")
        try:
            with open(p) as f:
                _REGISTRY = json.load(f)
        except Exception:
            _REGISTRY = {}
    return _REGISTRY.get(chain) or {}


IMPERSONATION_RATIO = 100   # leader's pool must dwarf this one by this multiple to call it out
OWN_MARKET_FLOOR = 10 ** 18  # one unit of native coin: below this there is no market to speak of


def _identity(chain, token, symbol, own_reserve):
    """Is this contract the one the market means when it says that symbol?

    A scam token can call itself USDT for free — four BSC contracts do. What it cannot fake
    cheaply is depth: the real one trades against tens of thousands of BNB. So the test is a
    RATIO against the leading claimant of the same symbol, never an absolute size, which is
    what lets it work for obscure tickers too.

    But a big ratio alone does not make an impostor. Plenty of tickers are shared by tokens
    that are all real — a chain's native stablecoin and its bridged twin both answer "USDC",
    and 29 contested symbols here have more than one genuine market behind them. So the
    accusation also requires that this contract have no market of its own: an impostor lives
    off the borrowed name because it has nothing else. One with real liquidity gets the
    honest answer instead — the ticker is shared, look at the address.

    Note this only ever compares contracts claiming the SAME symbol string, so distinct real
    stablecoins (USDe, FDUSD, PYUSD, USDT0 …) never collide with each other by construction;
    no list of "approved" tokens is needed, and none is kept."""
    if not symbol:
        return None
    entries = _registry(chain).get(symbol.upper())
    if not entries or len(entries) < 2:
        return None
    top_addr, top_res = entries[0][0], int(entries[0][1])
    if top_addr.lower() == token.lower():
        return {"canonical": True, "symbol": symbol, "claimants": len(entries)}
    mine = max(int(own_reserve or 0), 1)
    base = {"canonical": False, "symbol": symbol, "claimants": len(entries),
            "leader": top_addr, "leader_reserve": str(top_res), "this_reserve": str(mine),
            "ratio": int(top_res / mine)}
    if top_res >= IMPERSONATION_RATIO * mine:
        base["impostor"] = mine < OWN_MARKET_FLOOR      # dwarfed AND no market of its own
        return base
    base["ambiguous"] = True
    return base


def _symbol_of(url, token):
    res, _ = _call(url, token, selector("symbol()"))
    if not res or len(res) < 130:
        return None
    try:
        off = int(res[2:66], 16) * 2 + 2
        ln = int(res[off:off + 64], 16) * 2
        s = bytes.fromhex(res[off + 64:off + 64 + ln]).decode("utf-8", "ignore").strip()
        return s or None
    except Exception:
        return None


def _ownership(url, token):
    out = {}
    for sig in ("owner()", "getOwner()"):
        res, _ = _call(url, token, selector(sig))
        if res and res != "0x":
            owner = "0x" + res[-40:]
            out["owner"] = owner
            out["renounced"] = _uint(res) == 0 or owner in BURN
            break
    res = _rpc(url, "eth_getStorageAt", [token, PROXY_SLOT, "latest"]).get("result")
    out["proxy"] = bool(res and _uint(res) != 0)
    return out


# The V2 pair is not the whole market. Native USDC on Arbitrum keeps 0.3 ETH in the Sushi V2
# pair and hundreds of millions in Uniswap V3 — measuring V2 alone called it illiquid and
# blocked it. Depth is therefore summed over V2 and every V3 fee tier, as the registry does.
FACTORY_V3 = {
    "ethereum": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "arbitrum": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "polygon": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "optimism": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
    "base": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
    "bsc": "0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865",
}
FEE_TIERS = [100, 500, 3000, 10000]


def _v3_depth(url, chain, token, weth):
    """Wrapped-native sitting in this token's Uniswap-V3 pools, summed across fee tiers."""
    f3 = FACTORY_V3.get(chain)
    if not f3:
        return 0
    total = 0
    for fee in FEE_TIERS:
        pool, _ = _call(url, f3, selector("getPool(address,address,uint24)")
                        + _a32(token) + _a32(weth) + f"{fee:064x}")
        if not pool or _uint(pool) == 0:
            continue
        bal, _ = _call(url, weth, selector("balanceOf(address)") + _a32("0x" + pool[-40:]))
        total += _uint(bal)
    return total


def _liquidity(url, pair, weth, chain=None, token=None):
    """Tradeable depth in wrapped-native terms (V2 pair + V3 pools) + share of LP burned."""
    out = {}
    res, _ = _call(url, pair, selector("getReserves()"))
    t0, _ = _call(url, pair, selector("token0()"))
    if res and len(res) >= 130 and t0:
        r0 = int(res[2:66], 16)
        r1 = int(res[66:130], 16)
        native_is_0 = ("0x" + t0[-40:]).lower() == weth.lower()
        out["v2_reserve"] = r0 if native_is_0 else r1
        out["native_reserve"] = out["v2_reserve"]
    if chain and token:
        v3 = _v3_depth(url, chain, token, weth)
        if v3:
            out["v3_reserve"] = v3
            out["native_reserve"] = out.get("v2_reserve", 0) + v3
    supply, _ = _call(url, pair, selector("totalSupply()"))
    total = _uint(supply)
    if total:
        burned = 0
        for b in BURN:
            bal, _ = _call(url, pair, selector("balanceOf(address)") + _a32(b))
            burned += _uint(bal)
        out["lp_burned_pct"] = round(burned / total * 100, 1)
    return out


def check_token(chain, token, rpcs=None):
    """First-hand safety verdict for a token: simulate trading it, read its code, weigh both."""
    chain = (chain or "").lower()
    token = (token or "").strip()
    urls = rpcs or RPCS.get(chain) or []
    if not urls:
        return {"error": f"unsupported chain '{chain}'", "supported": sorted(RPCS)}
    if not token.startswith("0x") or len(token) != 42:
        return {"error": "expected a 0x… contract address"}
    url = urls[0]

    code = _bytecode_facts(url, token)
    if not code.get("is_contract"):
        return {"chain": chain, "token": token, "verdict": "block", "score": 0,
                "checks": [{"name": "contract", "status": "fail",
                            "detail": "no code at this address — it is not a token contract"}]}

    router, weth, factory = _venue(url, chain)
    if not router:
        # no V2 venue here (e.g. Optimism): fall back to the chain's wrapped native + V3 path
        weth = WRAPPED_NATIVE.get(chain)
        if not weth:
            return {"error": f"no DEX venue resolved on {chain}"}
        factory = None
    # Pin the whole analysis to one block, so every call sees identical reserves.
    bn = _rpc(url, "eth_blockNumber", []).get("result")
    block = hex(int(bn, 16) - 1) if bn else "latest"   # -1: the head may not have propagated

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_own = ex.submit(_ownership, url, token)
        f_sim = ex.submit(_confirm, chain, token, router, weth, factory, urls, block)
        own = f_own.result()
        sim, attempts = f_sim.result()
    liq = _liquidity(url, sim["pair"], weth, chain, token) if sim.get("pair") else {}

    checks, score = [], 100

    def add(name, status, detail, penalty=0, evidence=None):
        nonlocal score
        score -= penalty
        c = {"name": name, "status": status, "detail": detail}
        if evidence:
            c["evidence"] = evidence
        checks.append(c)

    if sim.get("error"):
        add("tradeable", "unknown", sim["error"], 25)
    elif sim.get("reason") == "cannot_buy":
        add("buy", "fail", "the buy itself fails — the token cannot be acquired on this venue", 60)
    elif not sim.get("sellable"):
        if sim.get("unconfirmed"):
            add("honeypot", "unknown",
                "the sell failed once but could not be reproduced on a second RPC — treat as "
                "unproven, not as a clean bill", 30)
        else:
            add("honeypot", "fail",
                "bought fine, but selling back REVERTS on more than one node — you would not "
                "get your money out", 100,
                {"buy_ok": True, "sell_reverted": True, "confirmations": len(attempts)})
    else:
        rt = sim.get("round_trip_pct", 0)
        bt = sim.get("buy_tax_pct", 0)
        st = sim.get("sell_tax_pct", 0)
        add("honeypot", "pass",
            f"simulated buy and sell both succeed; {rt:.1f}% of the money comes back",
            0, {"round_trip_pct": rt})
        worst = max(bt, st)
        if worst >= 50:
            add("tax", "fail", f"punitive fees: {bt:.1f}% on buy, {st:.1f}% on sell", 60,
                {"buy_tax_pct": bt, "sell_tax_pct": st})
        elif worst >= 15:
            add("tax", "warn", f"heavy fees: {bt:.1f}% on buy, {st:.1f}% on sell", 30,
                {"buy_tax_pct": bt, "sell_tax_pct": st})
        else:
            add("tax", "pass", f"normal fees: {bt:.1f}% buy / {st:.1f}% sell", 0,
                {"buy_tax_pct": bt, "sell_tax_pct": st})

    nat = liq.get("native_reserve")
    sym = _symbol_of(url, token)
    ident = _identity(chain, token, sym, nat)
    if ident and not ident.get("canonical"):
        if ident.get("ambiguous"):
            add("identity", "warn",
                f"{ident['claimants']} different contracts on this chain call themselves "
                f"'{sym}' — the name tells you nothing; check the address", 15,
                {"symbol": sym, "claimants": ident["claimants"]})
        elif not ident.get("impostor"):
            add("identity", "warn",
                f"'{sym}' is also the ticker of a far bigger market at {ident['leader'][:10]}… "
                f"({ident['ratio']}x this one) — this token has its own liquidity, so it is not "
                "a pure impostor, but you may not be buying the one you have in mind", 20,
                {"symbol": sym, "bigger_market": ident["leader"],
                 "liquidity_ratio": ident["ratio"], "claimants": ident["claimants"]})
        else:
            add("identity", "fail",
                f"this calls itself '{sym}', but the '{sym}' the market actually trades sits at "
                f"{ident['leader'][:10]}… with {ident['ratio']}x the liquidity — this is an "
                "impostor wearing a trusted name", 80,
                {"symbol": sym, "impersonates": ident["leader"],
                 "liquidity_ratio": ident["ratio"], "claimants": ident["claimants"]})
    elif ident and ident.get("canonical"):
        add("identity", "pass",
            f"this IS the '{sym}' the market trades, despite {ident['claimants']} contracts "
            "claiming the name", 0, {"symbol": sym, "claimants": ident["claimants"]})
    # How established the market is decides how much the governance facts should weigh. A pool
    # with thousands of coins in it is supplied by many independent LPs, so "the LP isn't burned"
    # is the normal state of a real market, not a rug signal — while on a 2-coin pool it is the
    # whole story. Same fact, different meaning; the threshold is the market's own depth.
    deep = (nat or 0) / 1e18 >= 100
    if nat is not None:
        human = nat / 1e18
        if human < 1:
            add("liquidity", "fail",
                f"almost nothing to trade against ({human:.3f} in the pool) — the price is "
                "whatever the owner decides", 40, {"native_reserve": str(nat)})
        elif human < 10:
            add("liquidity", "warn", f"thin liquidity ({human:.2f} in the pool)", 20,
                {"native_reserve": str(nat)})
        else:
            add("liquidity", "pass", f"{human:.1f} of the native coin in the pool", 0,
                {"native_reserve": str(nat)})
    lp = liq.get("lp_burned_pct")
    if lp is not None:
        if lp >= 90:
            add("lp_burned", "pass", f"{lp}% of the LP is burned — liquidity can't just leave", 0)
        elif deep or (liq.get("v3_reserve", 0) > liq.get("v2_reserve", 0)):
            add("lp_burned", "info",
                f"{lp}% of the V2 LP is burned — not meaningful for a market of this shape", 0,
                {"lp_burned_pct": lp})
        elif lp >= 50:
            add("lp_burned", "warn", f"only {lp}% of the LP is burned", 10)
        else:
            add("lp_burned", "warn",
                f"just {lp}% of the LP is burned — whoever holds the rest can pull it", 20,
                {"lp_burned_pct": lp})

    if own.get("proxy"):
        add("proxy", "warn", "upgradeable proxy — today's code is not a promise about tomorrow's",
            8 if deep else 15)
    if "renounced" in own:
        if own["renounced"]:
            add("ownership", "pass", "ownership renounced", 0)
        else:
            add("ownership", "warn", f"an owner is still in control ({own['owner'][:10]}…)",
                5 if deep else 10, {"owner": own["owner"]})

    danger = code.get("dangerous_functions") or []
    if danger:
        names = ", ".join(d["meaning"] for d in danger[:4])
        cap = 10 if deep else 25
        add("privileged_functions", "warn",
            f"the deployed code contains {len(danger)} privileged function(s): {names}",
            min(cap, 5 * len(danger)), {"functions": danger})
    else:
        add("privileged_functions", "pass", "no known privileged functions in the bytecode", 0)

    score = max(0, min(100, score))
    fails = [c for c in checks if c["status"] == "fail"]
    # "block" means you would lose money here, so only a demonstrated hard failure earns it:
    # a honeypot, an unbuyable token, an impostor, punitive fees, an empty pool. Soft warnings
    # must never add up into one — a legitimate bridged USDC that buys and sells perfectly was
    # being blocked purely for having a proxy, an owner and unburned LP.
    verdict = "block" if fails else ("warn" if score < 75 else "safe")
    return {"chain": chain, "token": token, "verdict": verdict, "score": score,
            "checks": checks,
            "simulation": {k: (str(v) if isinstance(v, int) and abs(v) > 2**53 else v)
                           for k, v in sim.items() if k != "error"},
            "engine": "guardbot-tokencheck/0.1 (first-hand simulation, no third-party API)"}


if __name__ == "__main__":
    import sys
    ch = sys.argv[1] if len(sys.argv) > 1 else "bsc"
    tk = sys.argv[2] if len(sys.argv) > 2 else "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"
    print(json.dumps(check_token(ch, tk), indent=2, ensure_ascii=False))
