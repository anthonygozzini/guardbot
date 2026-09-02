#!/usr/bin/env python3
"""End-to-end signing proof for the Solana and TRON revokes — no wallet, no third party, no value.

Trust problem this solves: proving that the revoke transactions GuardBot builds are ACCEPTED and
EFFECTIVE on chain requires a signature, and every earlier route required trusting something —
mainnet gas (money) or third-party wallet software. This script trusts nothing: it generates a
THROWAWAY key locally, signs with our own stdlib-only ed25519/secp256k1 (self-tested against the
RFC 8032 and secp256k1 reference vectors on every run), and runs the full lifecycle on a TESTNET:

  solana (devnet):  airdrop -> create token account + approve(1) -> verify delegate ON (first-hand
                    account read) -> sign & send the REVOKE -> verify delegate GONE.
  tron   (nile):    fund the printed address at https://nileex.io/join/getJoinPage once, re-run ->
                    approve(spender, 1) -> verify allowance=1 -> approve(spender, 0) (the revoke)
                    -> verify allowance=0.

Keys live in ~/.guardbot/ (outside the repo, worthless by construction: testnet only).
Usage:  python3 tools/testnet_e2e.py solana | tron
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import solmeta
from keccak import keccak256

SOL_RPC = os.environ.get("GUARDBOT_SOLANA_RPC", "https://api.devnet.solana.com")
TRONGRID = {"nile": "https://nile.trongrid.io", "shasta": "https://api.shasta.trongrid.io",
            "mainnet-DONT": ""}[os.environ.get("GUARDBOT_TRON_NETWORK", "nile")]
KEYDIR = os.path.join(os.path.expanduser("~"), ".guardbot")

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
DEVNET_USDC = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
NILE_USDT = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"
TRON_SPENDER = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"   # the TRON black hole — obviously not a real spender


# ---------------- ed25519 (RFC 8032), pure stdlib ----------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrec(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if x % 2:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_B = (_xrec(_BY), _BY)


def _padd(p, q):
    (x1, y1), (x2, y2) = p, q
    den = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + den) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - den) % _P
    return x3, y3


def _pmul(pt, e):
    q = (0, 1)
    while e:
        if e & 1:
            q = _padd(q, pt)
        pt = _padd(pt, pt)
        e >>= 1
    return q


def _penc(pt):
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed_keys(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(bytes([h[0] & 248]) + h[1:31] + bytes([(h[31] & 63) | 64]), "little")
    return _penc(_pmul(_B, a)), a, h[32:]


def ed_sign(seed, msg):
    pub, a, prefix = ed_keys(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    R = _penc(_pmul(_B, r))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % _L
    return R + ((r + k * a) % _L).to_bytes(32, "little")


def _selftest_ed25519():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub, _, _ = ed_keys(seed)
    assert pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed_sign(seed, b"").hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249"
                                        "01555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe2465514143"
                                        "8e7a100b")


# ---------------- secp256k1 (ECDSA + recovery id), pure stdlib ----------------
_SP = 2 ** 256 - 2 ** 32 - 977
_SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _sinv(x, m):
    return pow(x, m - 2, m)


def _sadd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % _SP == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * _sinv(2 * y1, _SP) % _SP
    else:
        lam = (y2 - y1) * _sinv((x2 - x1) % _SP, _SP) % _SP
    x3 = (lam * lam - x1 - x2) % _SP
    return x3, (lam * (x1 - x3) - y1) % _SP


def _smul(pt, e):
    q = None
    while e:
        if e & 1:
            q = _sadd(q, pt)
        pt = _sadd(pt, pt)
        e >>= 1
    return q


def _rfc6979_k(priv, z):
    x = priv.to_bytes(32, "big")
    h1 = z.to_bytes(32, "big")
    V, K = b"\x01" * 32, b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < _SN:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def ecdsa_sign_recoverable(priv, digest32):
    z = int.from_bytes(digest32, "big")
    k = _rfc6979_k(priv, z)
    R = _smul(_SG, k)
    r = R[0] % _SN
    s = _sinv(k, _SN) * (z + r * priv) % _SN
    rec = (R[1] & 1) | (2 if R[0] >= _SN else 0)
    if s > _SN // 2:
        s = _SN - s
        rec ^= 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([rec])


def _selftest_secp256k1():
    two_g = _smul(_SG, 2)
    assert two_g[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    # sign/verify round trip
    priv = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    d = hashlib.sha256(b"guardbot").digest()
    sig = ecdsa_sign_recoverable(priv, d)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    z = int.from_bytes(d, "big")
    pub = _smul(_SG, priv)
    w = _sinv(s, _SN)
    u1, u2 = z * w % _SN, r * w % _SN
    X = _sadd(_smul(_SG, u1), _smul(pub, u2))
    assert X[0] % _SN == r


# ---------------- helpers ----------------
def _post_json(url, body, timeout=25):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "guardbot-e2e/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def sol_rpc(method, params):
    return _post_json(SOL_RPC, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


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


def _keyfile(name, nbytes):
    os.makedirs(KEYDIR, exist_ok=True)
    p = os.path.join(KEYDIR, name)
    if os.path.exists(p):
        return bytes.fromhex(open(p).read().strip())
    k = os.urandom(nbytes)
    open(p, "w").write(k.hex())
    os.chmod(p, 0o600)
    return k


def _confirm_sol(sig, tries=30):
    for _ in range(tries):
        st = sol_rpc("getSignatureStatuses", [[sig]])
        v = ((st.get("result") or {}).get("value") or [None])[0]
        if v and v.get("confirmationStatus") in ("confirmed", "finalized"):
            return v.get("err")
        time.sleep(2)
    return "timeout"


# ---------------- Solana devnet leg ----------------
def solana_leg():
    assert "devnet" in SOL_RPC or "testnet" in SOL_RPC, "refusing: GUARDBOT_SOLANA_RPC is not a testnet"
    cluster = "devnet" if "devnet" in SOL_RPC else "testnet"
    seed = _keyfile("e2e_solana.seed", 32)
    pub, _, _ = ed_keys(seed)
    owner = solmeta.b58encode(pub)
    print(f"throwaway owner: {owner}")
    bal = (sol_rpc("getBalance", [owner]).get("result") or {}).get("value") or 0
    if bal < 5_000_000:
        print("balance low — requesting devnet airdrop…")
        try:
            sol_rpc("requestAirdrop", [owner, 1_000_000_000])
        except Exception as e:
            print("  airdrop call failed:", e)
        for _ in range(15):
            time.sleep(2)
            bal = (sol_rpc("getBalance", [owner]).get("result") or {}).get("value") or 0
            if bal >= 5_000_000:
                break
        if bal < 5_000_000:
            print(f"AIRDROP REFUSED (rate limit). Paste this address at https://faucet.solana.com "
                  f"(no wallet needed) and re-run:\n  {owner}")
            return 1
    print(f"balance: {bal/1e9:.4f} SOL (devnet — no value)")

    token_b = solmeta.b58decode(TOKEN_PROGRAM)
    # the well-known USDC test mint lives on devnet only; on any cluster where it is absent the
    # proof gets MORE first-hand, not less: we create a throwaway mint of our own (second signer)
    usdc_info = ((sol_rpc("getAccountInfo", [DEVNET_USDC, {"encoding": "base64"}])
                  .get("result") or {}).get("value")) or {}
    have_usdc = usdc_info.get("owner") == TOKEN_PROGRAM   # must BE a mint, not merely exist
    if have_usdc:
        mint, mint_seed = DEVNET_USDC, None
    else:
        mint_seed = _keyfile("e2e_solana_mint.seed", 32)
        mint = solmeta.b58encode(ed_keys(mint_seed)[0])
        print(f"USDC test mint absent on {cluster} — using our own throwaway mint {mint}")
    mint_b = solmeta.b58decode(mint)
    system_b = solmeta.b58decode(SYSTEM_PROGRAM)
    ata_prog_b = solmeta.b58decode(ATA_PROGRAM)
    ata, _bump = solmeta.find_program_address([pub, token_b, mint_b], ATA_PROGRAM)
    ata_b = solmeta.b58decode(ata)
    print(f"token account (derived): {ata}")

    def build(keys, header, instrs, blockhash):
        msg = bytes(header) + _cu16(len(keys)) + b"".join(keys) + solmeta.b58decode(blockhash)
        msg += _cu16(len(instrs))
        for prog_ix, accs, data in instrs:
            msg += bytes([prog_ix]) + _cu16(len(accs)) + bytes(accs) + _cu16(len(data)) + data
        return msg

    def send(msg, signers):
        tx = _cu16(len(signers)) + b"".join(ed_sign(sd, msg) for sd in signers) + msg
        r = sol_rpc("sendTransaction", [base64.b64encode(tx).decode(),
                                        {"encoding": "base64", "preflightCommitment": "confirmed"}])
        # default preflight is "finalized": an account created one tx earlier (only "confirmed")
        # does not exist in that view yet, and the ATA create failed with IncorrectProgramId
        if "error" in r:
            print("  send error:", json.dumps(r["error"])[:300])
            return None
        sig = r.get("result")
        err = _confirm_sol(sig)
        print(f"  tx {sig}\n  https://explorer.solana.com/tx/{sig}?cluster={cluster}\n  confirmed, err={err}")
        return None if err else sig

    def delegate_state():
        info = sol_rpc("getAccountInfo", [ata, {"encoding": "jsonParsed", "commitment": "confirmed"}])
        v = ((info.get("result") or {}).get("value") or {})
        pi = (((v.get("data") or {}).get("parsed") or {}).get("info") or {})
        return pi.get("delegate"), (pi.get("delegatedAmount") or {}).get("amount")

    def blockhash():
        return ((sol_rpc("getLatestBlockhash", [{"commitment": "finalized"}]).get("result") or {})
                .get("value") or {}).get("blockhash")

    if mint_seed is not None and not ((sol_rpc("getAccountInfo", [mint, {"encoding": "base64"}])
                                       .get("result") or {}).get("value")):
        rent = (sol_rpc("getMinimumBalanceForRentExemption", [82]).get("result")) or 1461600
        print("\n[0/2] creating the throwaway mint (two signatures: owner pays, mint account signs)…")
        # keys: 0 owner(s,w) 1 mint(s,w) | ro: 2 system 3 token
        mkeys = [pub, ed_keys(mint_seed)[0], solmeta.b58decode(SYSTEM_PROGRAM), token_b]
        create = (0).to_bytes(4, "little") + int(rent).to_bytes(8, "little") + (82).to_bytes(8, "little") + token_b
        init2 = bytes([20, 0]) + pub + bytes([0])       # InitializeMint2, decimals 0, no freeze
        msg = build(mkeys, [2, 0, 2], [(2, [0, 1], create), (3, [1], init2)], blockhash())
        if send(msg, [seed, mint_seed]) is None:
            return 1

    # keys: 0 owner(s,w) 1 ata(w) | ro: 2 mint 3 system 4 token 5 ata_prog
    keys = [pub, ata_b, mint_b, system_b, token_b, ata_prog_b]
    print("\n[1/2] create token account (idempotent) + approve 1 unit to the test delegate…")
    msg = build(keys, [1, 0, 4],
                [(5, [0, 1, 0, 2, 3, 4], bytes([1])),                       # create ATA (idempotent)
                 (4, [1, 3, 0], bytes([4]) + (1).to_bytes(8, "little"))],   # approve(delegate=system, 1)
                blockhash())
    if send(msg, [seed]) is None:
        return 1
    d, amt = delegate_state()
    print(f"  first-hand read: delegate={d} amount={amt}")
    assert d == SYSTEM_PROGRAM and amt == "1", "delegate not set as expected"

    print("\n[2/2] REVOKE — the exact instruction GuardBot builds…")
    msg = build([pub, ata_b, token_b], [1, 0, 1], [(2, [1, 0], bytes([5]))], blockhash())
    if send(msg, [seed]) is None:
        return 1
    d, amt = delegate_state()
    print(f"  first-hand read: delegate={d}")
    assert d is None, "delegate still present after revoke"
    print("\nPROVEN: the Solana revoke transaction signs, lands, and removes the delegate. ✓")
    return 0


# ---------------- TRON Nile leg ----------------
def tron_addr(priv):
    x, y = _smul(_SG, priv)
    payload = b"\x41" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:]
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return solmeta.b58encode(payload + chk), payload.hex()


def tron_leg():
    assert "nile" in TRONGRID or "shasta" in TRONGRID, "refusing: not a TRON testnet"
    priv = int.from_bytes(_keyfile("e2e_tron.seed", 32), "big") % _SN
    addr, addr_hex = tron_addr(priv)
    print(f"throwaway owner: {addr}   (network: {TRONGRID})")
    acct = _post_json(f"{TRONGRID}/wallet/getaccount", {"address": addr_hex, "visible": False})
    if not acct or "balance" not in acct:
        print(f"NOT FUNDED yet. Get free test TRX at https://nileex.io/join/getJoinPage for:\n  {addr}\nthen re-run.")
        return 1
    print(f"balance: {acct['balance']/1e6:.2f} TRX (Nile — no value)")

    tok_hex = solmeta.b58decode(NILE_USDT)[:21].hex()
    spd_hex = solmeta.b58decode(TRON_SPENDER)[:21].hex()

    def call(amount):
        b = _post_json(f"{TRONGRID}/wallet/triggersmartcontract",
                       {"owner_address": addr_hex, "contract_address": tok_hex,
                        "function_selector": "approve(address,uint256)",
                        "parameter": spd_hex[2:].rjust(64, "0") + f"{amount:064x}",
                        "fee_limit": 100_000_000, "call_value": 0, "visible": False})
        tx = b.get("transaction")
        if not tx:
            print("  build failed:", json.dumps(b)[:200])
            return None
        sig = ecdsa_sign_recoverable(priv, bytes.fromhex(tx["txID"]))
        tx["signature"] = [sig.hex()]
        r = _post_json(f"{TRONGRID}/wallet/broadcasttransaction", tx)
        if not r.get("result"):
            print("  broadcast failed:", json.dumps(r)[:200])
            return None
        print(f"  tx {tx['txID']}\n  https://nile.tronscan.org/#/transaction/{tx['txID']}")
        for _ in range(20):
            time.sleep(3)
            info = _post_json(f"{TRONGRID}/wallet/gettransactionbyid", {"value": tx["txID"], "visible": False})
            ret = ((info.get("ret") or [{}])[0]).get("contractRet")
            if ret:
                print(f"  confirmed: {ret}")
                return tx["txID"] if ret == "SUCCESS" else None
        print("  not confirmed in time")
        return None

    def allowance():
        r = _post_json(f"{TRONGRID}/wallet/triggerconstantcontract",
                       {"owner_address": addr_hex, "contract_address": tok_hex,
                        "function_selector": "allowance(address,address)",
                        "parameter": addr_hex[2:].rjust(64, "0") + spd_hex[2:].rjust(64, "0"),
                        "visible": False})
        cr = r.get("constant_result") or []
        return int(cr[0], 16) if cr else None

    print("\n[1/2] approve(spender, 1) — creating the grant to revoke…")
    if call(1) is None:
        return 1
    a = allowance()
    print(f"  first-hand read: allowance={a}")
    assert a == 1, "allowance not set"
    print("\n[2/2] REVOKE — approve(spender, 0), the exact call GuardBot builds…")
    if call(0) is None:
        return 1
    a = allowance()
    print(f"  first-hand read: allowance={a}")
    assert a == 0, "allowance not zero after revoke"
    print("\nPROVEN: the TRON revoke transaction signs, lands, and zeroes the allowance. ✓")
    return 0


if __name__ == "__main__":
    _selftest_ed25519()
    _selftest_secp256k1()
    print("crypto self-tests: RFC 8032 vector ✓  secp256k1 vector ✓\n")
    leg = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
    if leg == "solana":
        raise SystemExit(solana_leg())
    if leg == "tron":
        raise SystemExit(tron_leg())
    print("usage: python3 tools/testnet_e2e.py solana|tron")
    raise SystemExit(2)
