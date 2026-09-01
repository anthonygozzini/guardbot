#!/usr/bin/env python3
"""Build the exact transaction that revokes an approval — and nothing else.

GuardBot has been read-only: it shows you the danger without letting you remove it. Removing it
means signing a transaction, which is the one gesture drainers exploit, so the rules here are
deliberately narrow:

  - Only these three calls can ever be produced, each with the revoking argument hard-coded:
      ERC-20        approve(spender, 0)
      NFT operator  setApprovalForAll(operator, false)
      Permit2       approve(token, spender, 0, 0)   -- amount 0, expiration 0
    There is no path that emits a transfer, an increase, or an arbitrary call. The amount is a
    literal in the encoder, not a parameter a caller could set.
  - Nothing is signed or sent here. This returns calldata for the wallet to sign, so the same
    payload also works for a hardware wallet or an offline signer.
  - Every field the wallet will see is returned in plain form too (`human`), so the page can show
    what is about to be signed instead of asking for blind trust.

  revoke_tx(chain, kind, token, spender) -> {to, data, value, chain_id, human, ...}
"""

from keccak import selector

# The three revoking calls. Nothing else is encodable by this module.
SEL_APPROVE = selector("approve(address,uint256)")                    # ERC-20
SEL_SET_APPROVAL_FOR_ALL = selector("setApprovalForAll(address,bool)")  # ERC-721/1155
SEL_PERMIT2_APPROVE = selector("approve(address,address,uint160,uint48)")
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

CHAIN_IDS = {"ethereum": 1, "bsc": 56, "polygon": 137, "base": 8453,
             "arbitrum": 42161, "optimism": 10}
CHAIN_NAMES = {v: k for k, v in CHAIN_IDS.items()}


def _a32(a):
    return a.lower().replace("0x", "").rjust(64, "0")


def _w(x):
    return f"{int(x):064x}"


def _is_addr(a):
    a = (a or "").strip()
    if not a.startswith("0x") or len(a) != 42:
        return False
    try:
        int(a, 16)
    except ValueError:
        return False
    return True


def revoke_tx(chain, kind, token, spender):
    """The transaction that takes a specific permission away. Returns an error dict rather than
    guessing whenever the inputs don't describe exactly one revocable grant."""
    chain = (chain or "").lower()
    if chain not in CHAIN_IDS:
        return {"error": f"revoking is not supported on '{chain}' yet (EVM chains only)"}
    if not _is_addr(token) or not _is_addr(spender):
        return {"error": "token and spender must both be 0x addresses"}
    token, spender = token.lower(), spender.lower()

    if kind in ("approval", "erc20"):
        tx = {"to": token, "data": SEL_APPROVE + _a32(spender) + _w(0)}
        human = {"call": f"approve({spender}, 0)", "contract": token,
                 "effect": "sets this spender's allowance on this token to zero"}
    elif kind in ("nft_operator", "nft"):
        tx = {"to": token, "data": SEL_SET_APPROVAL_FOR_ALL + _a32(spender) + _w(0)}
        human = {"call": f"setApprovalForAll({spender}, false)", "contract": token,
                 "effect": "revokes this operator's access to every NFT in this collection"}
    elif kind == "permit2":
        # Permit2 keeps its own books: zeroing the ERC-20 approval to Permit2 shuts the door for
        # the future but leaves grants already inside it alive until they expire. They must be
        # zeroed in Permit2 itself — the blind spot this tool found in reading, closed in writing.
        tx = {"to": PERMIT2.lower(),
              "data": SEL_PERMIT2_APPROVE + _a32(token) + _a32(spender) + _w(0) + _w(0)}
        human = {"call": f"Permit2.approve({token}, {spender}, 0, 0)", "contract": PERMIT2,
                 "effect": "zeroes the amount and expiry this spender holds inside Permit2 — "
                           "the ERC-20 approval to Permit2 alone would NOT do this"}
    else:
        return {"error": f"nothing revocable for kind '{kind}'"}

    tx["value"] = "0x0"
    tx["chainId"] = hex(CHAIN_IDS[chain])
    return {"chain": chain, "chain_id": CHAIN_IDS[chain], "kind": kind,
            "token": token, "spender": spender, "tx": tx, "human": human,
            "note": "Nothing is signed or sent here. Sign it in your wallet, or take this "
                    "calldata to a hardware/offline signer."}


def simulate_revoke(chain, kind, owner, token, spender):
    """Prove the revoke's EFFECT without spending gas: eth_simulateV1 runs the revoke and, in the
    SAME simulated block, re-reads the grant. works=True only when the read comes back zero — so
    this checks that the transaction actually removes the permission, not merely that it encodes.

    Where the public RPC doesn't support eth_simulateV1, `simulated` is False and no verdict is
    invented — the calldata is still correct, it just couldn't be proven on that node."""
    import approvals as A   # imported here so revoke_tx stays dependency-free for encoding-only use
    built = revoke_tx(chain, kind, token, spender)
    if built.get("error"):
        return built
    if not _is_addr(owner):
        return {"error": "owner must be a 0x address to simulate the effect"}
    tx = built["tx"]
    o = owner.lower()

    if kind in ("approval", "erc20"):
        read_to = token.lower()
        read_data = "0xdd62ed3e" + _a32(o) + _a32(spender)   # allowance(owner, spender)
        decode = lambda h: int(h, 16)
    elif kind in ("nft_operator", "nft"):
        read_to = token.lower()
        read_data = "0xe985e9c5" + _a32(o) + _a32(spender)   # isApprovedForAll(owner, operator)
        decode = lambda h: int(h, 16)
    else:  # permit2
        read_to = PERMIT2.lower()
        read_data = "0x927da105" + _a32(o) + _a32(token) + _a32(spender)  # Permit2.allowance
        decode = lambda h: int(h[:66], 16)   # amount is the first word

    rpc = A._chain_rpc(chain, A.EVM_CFG.get(chain, {}))
    bundle = {"blockStateCalls": [{"calls": [
        {"from": o, "to": tx["to"], "data": tx["data"]},
        {"from": o, "to": read_to, "data": read_data},
    ]}]}
    try:
        res = A._rpc(rpc, "eth_simulateV1", [bundle, "latest"])
    except Exception as e:
        res = {"__err": str(e)[:80]}
    calls = (res or [None])[0].get("calls") if isinstance(res, list) and res else None
    if not calls or len(calls) < 2:
        built["simulation"] = {"simulated": False,
                               "note": "this RPC does not support eth_simulateV1 — calldata is "
                                       "correct but its effect could not be proven here"}
        return built
    ok_exec = str(calls[0].get("status")) in ("0x1", "1")
    rd = calls[1].get("returnData") or "0x"
    after = decode(rd) if rd != "0x" else None
    built["simulation"] = {"simulated": True, "executes": ok_exec,
                           "grant_after": None if after is None else str(after),
                           "works": bool(ok_exec and after == 0)}
    return built


# ---------------- Solana / TRON: the same proof, zero gas, no wallet ----------------
# The EVM path proves a revoke with eth_simulateV1. Solana and TRON have the same primitive
# (simulateTransaction / triggerconstantcontract), so a SOL delegate or TRC-20 approval can be
# proven revocable against a LIVE grant without spending anything or holding a key. What this
# proves: the instruction is correct for this owner/account. What it does NOT prove: that a
# given wallet app accepts and signs our transaction object — that stays unverified until a
# real signature goes through, and is reported as such.

SOL_FEE_PAYER_FALLBACK = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9"


def _cu16(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def simulate_revoke_solana(owner, token_account):
    """SPL Token `Revoke` (instruction 5) on the token ACCOUNT holding the delegate, simulated
    with sigVerify=false. Builds the legacy message in pure Python: no SDK, no key."""
    import base64
    import solcheck
    import solmeta
    try:
        okey, akey = solmeta.b58decode(owner), solmeta.b58decode(token_account)
        if len(okey) != 32 or len(akey) != 32:
            raise ValueError
    except Exception:
        return {"error": "owner and token account must be base58 Solana public keys"}
    out = {"chain": "solana", "kind": "delegate", "owner": owner, "token_account": token_account,
           "human": {"call": f"revoke({token_account})", "contract": "SPL Token program",
                     "effect": "removes the delegate from this token account; no other change"}}
    info = solcheck._rpc("getAccountInfo", [token_account, {"encoding": "jsonParsed"}])
    val = (info.get("result") or {}).get("value") if isinstance(info, dict) else None
    if not val:
        out["simulation"] = {"simulated": False, "note": "could not read the token account"
                             + (": " + info["error"] if isinstance(info, dict) and info.get("error") else "")}
        return out
    program = val.get("owner")
    parsed = ((val.get("data") or {}).get("parsed") or {}).get("info") or {}
    if parsed.get("owner") != owner:
        out["simulation"] = {"simulated": False, "note": "this token account is not owned by that wallet"}
        return out
    delegate = parsed.get("delegate")
    if not delegate:
        out["simulation"] = {"simulated": True, "executes": False, "works": False,
                             "note": "no delegate on this account — nothing to revoke"}
        return out
    bh = solcheck._rpc("getLatestBlockhash", [{"commitment": "finalized"}])
    blockhash = ((bh.get("result") or {}).get("value") or {}).get("blockhash") if isinstance(bh, dict) else None
    if not blockhash:
        out["simulation"] = {"simulated": False, "note": "could not fetch a recent blockhash"}
        return out
    pkey = solmeta.b58decode(program)
    bhash = solmeta.b58decode(blockhash)

    def build(payer_key):
        # legacy message. Signers first: [payer?, owner]; then the writable token account; then
        # the program (read-only). The Revoke instruction takes [token_account, owner].
        if payer_key is None:
            keys, ix_acc, prog_ix, nsig = [okey, akey, pkey], [1, 0], 2, 1
        else:
            keys, ix_acc, prog_ix, nsig = [payer_key, okey, akey, pkey], [2, 1], 3, 2
        msg = bytes([nsig, 0, 1]) + _cu16(len(keys)) + b"".join(keys) + bhash
        msg += _cu16(1) + bytes([prog_ix]) + _cu16(len(ix_acc)) + bytes(ix_acc) + _cu16(1) + bytes([5])
        return _cu16(nsig) + bytes(64 * nsig) + msg      # unverified signature slots

    def run(tx):
        sim = solcheck._rpc("simulateTransaction",
                            [base64.b64encode(tx).decode(),
                             {"encoding": "base64", "sigVerify": False, "commitment": "processed"}])
        return (sim.get("result") or {}).get("value") if isinstance(sim, dict) else None, sim

    res, sim = run(build(None))
    fee_note = None
    if res is not None and res.get("err") == "AccountNotFound":
        # the owner holds no SOL, so the fee payer "does not exist" for the runtime. Pay the
        # SIMULATED fee from a large, permanently funded account instead — it signs nothing and
        # is not part of the real transaction; the instruction itself is unchanged.
        bal = solcheck._rpc("getBalance", [owner])
        if ((bal.get("result") or {}).get("value") or 0) == 0:
            res, sim = run(build(solmeta.b58decode(SOL_FEE_PAYER_FALLBACK)))
            fee_note = ("owner holds no SOL: the fee was paid by a substitute account in the "
                        "simulation only — the real transaction needs a little SOL for its fee")
    if res is None:
        out["simulation"] = {"simulated": False, "note": "simulateTransaction unavailable"
                             + (": " + str(sim.get("error"))[:100] if isinstance(sim, dict) and sim.get("error") else "")}
        return out
    err = res.get("err")
    out["program"] = program
    out["simulation"] = {"simulated": True, "executes": err is None, "works": err is None,
                         "delegate_before": delegate,
                         "error": None if err is None else str(err)[:160],
                         "logs": (res.get("logs") or [])[-4:]}
    if fee_note:
        out["simulation"]["note"] = fee_note
    return out
    err = res.get("err")
    out["program"] = program
    out["simulation"] = {"simulated": True, "executes": err is None, "works": err is None,
                         "delegate_before": delegate,
                         "error": None if err is None else str(err)[:160],
                         "logs": (res.get("logs") or [])[-4:]}
    return out


def _tron_param(addr_hex):
    return addr_hex[2:].rjust(64, "0")    # drop the 0x41 prefix, left-pad the 20 bytes


def simulate_revoke_tron(owner, token, spender):
    """TRC-20 approve(spender, 0) run as a constant call from the owner — executed by the node,
    never broadcast. works=True when the call does not revert for THIS owner/token/spender and a
    live allowance exists to revoke (the constant call cannot change state, so the proof is 'the
    revoking call executes cleanly against a real grant')."""
    import troncheck
    oh, th, sh = troncheck.b58_to_hex(owner), troncheck.b58_to_hex(token), troncheck.b58_to_hex(spender)
    if not (oh and th and sh):
        return {"error": "owner, token and spender must be TRON base58 (T…) addresses"}
    out = {"chain": "tron", "kind": "approval", "owner": owner, "token": token, "spender": spender,
           "human": {"call": f"approve({spender}, 0)", "contract": token,
                     "effect": "sets this spender's TRC-20 allowance on this token to zero"}}
    before = troncheck._post("/wallet/triggerconstantcontract",
                             {"owner_address": oh, "contract_address": th,
                              "function_selector": "allowance(address,address)",
                              "parameter": _tron_param(oh) + _tron_param(sh), "visible": False})
    cr = before.get("constant_result") if isinstance(before, dict) else None
    allowance = int(cr[0], 16) if cr and cr[0] else None
    sim = troncheck._post("/wallet/triggerconstantcontract",
                          {"owner_address": oh, "contract_address": th,
                           "function_selector": "approve(address,uint256)",
                           "parameter": _tron_param(sh) + "0" * 64, "visible": False})
    if not isinstance(sim, dict) or sim.get("error") or "result" not in sim:
        out["simulation"] = {"simulated": False, "note": "TronGrid constant call unavailable"
                             + (": " + str(sim.get("error"))[:100] if isinstance(sim, dict) and sim.get("error") else "")}
        return out
    r = sim.get("result") or {}
    executes = bool(r.get("result")) and not r.get("message")
    rev = r.get("message")
    try:
        rev = bytes.fromhex(rev).decode("utf-8", "ignore").strip("\x00 ") if rev else None
    except Exception:
        pass
    out["simulation"] = {"simulated": True, "executes": executes,
                         "works": executes and (allowance is None or allowance > 0),
                         "allowance_before": None if allowance is None else str(allowance),
                         "energy_used": sim.get("energy_used"),
                         "error": None if executes else (rev or str(r.get("code") or "reverted"))[:160]}
    if executes and allowance == 0:
        out["simulation"]["note"] = "the call executes, but the allowance is already zero"
    return out


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 5:
        print("usage: revoke.py <chain> <kind> <token> <spender> [owner]")
        raise SystemExit(2)
    if len(sys.argv) >= 6:
        print(json.dumps(simulate_revoke(sys.argv[1], sys.argv[2], sys.argv[5],
                                         sys.argv[3], sys.argv[4]), indent=2))
    else:
        print(json.dumps(revoke_tx(*sys.argv[1:5]), indent=2))
