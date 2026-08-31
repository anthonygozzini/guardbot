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
