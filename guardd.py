#!/usr/bin/env python3
"""GuardBot daemon — HTTP API for the pre-trade safety verdict, with x402 payments.

Endpoints:
  GET  /llms.txt      agent onboarding (free)
  GET  /v1/status     service status (free)
  GET  /v1/check?chain=<c>&address=<a>   verdict (paid if PRICE>0)
  POST /v1/check      body {chain,address}

Payment = real x402 (HTTP 402 + facilitator /verify + /settle), "exact" scheme.
Modes:
  - PRICE_USDC=0 (default): free, usable/demoable right away.
  - PRICE_USDC>0 + GUARDBOT_FACILITATOR + GUARDBOT_PAY_TO: real on-chain enforcement.
    If PRICE>0 but the facilitator is missing, paid requests are REJECTED (never a
    false 'paid'): enforcement is real or absent, never faked.
Inherits the verdict-with-evidence contract and per-call paywall from Referee.
"""

import base64
import json
import os
import re
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import guard
import approvals as approvals_mod
import revoke as revoke_mod
import solcheck
import tokencheck
import troncheck

BASE = os.path.dirname(os.path.abspath(__file__))


def _code_version():
    """Which commit this process actually loaded. A long-lived daemon keeps running the code
    it started with, so a fix can look like it did nothing — say the version out loud."""
    try:
        import subprocess
        out = subprocess.run(["git", "-C", BASE, "log", "-1", "--format=%h %cd",
                              "--date=format:%Y-%m-%d %H:%M"],
                             capture_output=True, text=True, timeout=5)
        return (out.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


CODE_VERSION = _code_version()
PORT = int(os.environ.get("GUARDBOT_PORT", "8403"))
# Loopback by default: the tool is local-first and private. GUARDBOT_HOST=0.0.0.0 opts into the
# local network, which is what lets a phone on the same Wi-Fi open the viewer (and connect its
# wallet's own in-app browser, where the Solana/TRON providers are injected).
HOST = os.environ.get("GUARDBOT_HOST", "127.0.0.1")
TESTNET = ("devnet" in approvals_mod.SOL_RPC or "testnet" in approvals_mod.SOL_RPC
           or approvals_mod.TRON_NETWORK != "mainnet")
DEV_SEED = os.environ.get("GUARDBOT_DEV_SEED", "") in ("1", "true", "yes")


def _lan_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None
PRICE_USDC = float(os.environ.get("GUARDBOT_PRICE_USDC", "0"))
PAY_TO = os.environ.get("GUARDBOT_PAY_TO", "")
FACILITATOR = os.environ.get("GUARDBOT_FACILITATOR", "").rstrip("/")
NETWORK = os.environ.get("GUARDBOT_NETWORK", "base-sepolia")
CACHE_TTL = 120
FAC_TIMEOUT = 20

# USDC per network (6 decimals). Override with GUARDBOT_ASSET if needed.
USDC = {
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}
ASSET = os.environ.get("GUARDBOT_ASSET", USDC.get(NETWORK, ""))
ATOMIC = str(int(round(PRICE_USDC * 1_000_000)))  # USDC has 6 decimals

START = time.time()
STATS = {"checks": 0, "blocked": 0, "warned": 0, "paid": 0, "challenges": 0}
LOCK = threading.Lock()
CACHE = {}
SETTLED = set()   # replay-guard on already-settled payments


def payment_requirements(resource_url):
    """x402 'exact' scheme PaymentRequirements. Validate the fields against the chosen
    facilitator's /supported endpoint before mainnet."""
    return {
        "scheme": "exact",
        "network": NETWORK,
        "maxAmountRequired": ATOMIC,
        "resource": resource_url,
        "description": "GuardBot pre-trade token safety check",
        "mimeType": "application/json",
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 120,
        "asset": ASSET,
        "extra": {"name": "USDC", "version": "2"},
    }


def _b64json(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _facilitator(path, payload):
    req = urllib.request.Request(
        f"{FACILITATOR}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "guardbot/0.1"},
    )
    with urllib.request.urlopen(req, timeout=FAC_TIMEOUT) as r:
        return json.load(r)


def read_payment_header(headers):
    """Accept the ecosystem's divergent header names (Coinbase X-PAYMENT /
    foundation PAYMENT-SIGNATURE). Returns the decoded PaymentPayload or None."""
    raw = headers.get("X-PAYMENT") or headers.get("PAYMENT-SIGNATURE") or headers.get("X-Payment")
    if not raw:
        return None
    try:
        return json.loads(base64.b64decode(raw))
    except Exception:
        return None


def verify_and_settle(payload, requirements):
    """Real x402 enforcement via facilitator: /verify then /settle.
    Returns (ok: bool, settle_response|reason)."""
    if not (FACILITATOR and PAY_TO and ASSET):
        return False, "facilitator/pay_to not configured (enforcement inactive)"
    body = {"x402Version": 1, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        v = _facilitator("/verify", body)
    except Exception as e:
        return False, f"facilitator /verify unreachable: {str(e)[:120]}"
    if not v.get("isValid", v.get("valid", False)):
        return False, f"invalid payment: {v.get('invalidReason') or v.get('reason') or 'rejected'}"
    # anti-replay: key = tx/nonce from the payload
    key = json.dumps(payload.get("payload", payload), sort_keys=True)[:512]
    with LOCK:
        if key in SETTLED:
            return False, "payment already used"
    try:
        s = _facilitator("/settle", body)
    except Exception as e:
        return False, f"facilitator /settle unreachable: {str(e)[:120]}"
    if not s.get("success", False):
        return False, f"settle failed: {s.get('errorReason') or s.get('error') or 'unknown'}"
    with LOCK:
        SETTLED.add(key)
        STATS["paid"] += 1
    return True, s


def cached_assess(chain, address):
    key = (chain.lower(), address)
    now = time.time()
    with LOCK:
        hit = CACHE.get(key)
        if hit and now - hit[0] < CACHE_TTL:
            return hit[1]
    # the paid endpoint must serve the BEST engine — the same first-hand dispatch as
    # /v1/tokencheck; the legacy third-party wrapper only covers chains our engines don't
    c = chain.lower()
    if c == "solana":
        verdict = solcheck.check_token(address)
    elif c == "tron":
        verdict = troncheck.check_token(address)
    elif c in tokencheck.RPCS:
        verdict = tokencheck.check_token(c, address)
    else:
        verdict = guard.assess(chain, address)
    with LOCK:
        CACHE[key] = (now, verdict)
        STATS["checks"] += 1
        if verdict.get("verdict") == "block":
            STATS["blocked"] += 1
        elif verdict.get("verdict") == "warn":
            STATS["warned"] += 1
    return verdict


LLMS = f"""# GuardBot — pre-trade safety for agents & bots

Ask before you buy: is this token a rug / honeypot / trap? GuardBot answers first-hand —
on EVM it simulates buying the token and selling it back against live liquidity; on Solana
it reads the mint's authorities, Token-2022 extensions and holder concentration; on TRON it
reads the deployed bytecode for seize/blacklist/mint powers. No third-party safety API.

## Endpoints
GET /v1/tokencheck?chain=<chain>&address=<token>   is this token a trap?
GET /v1/approvals?address=<wallet>                 what has this wallet handed out?
GET /v1/revoke?chain=&kind=&token=&spender=&owner= calldata that takes a permission back (+ sim)
chain: ethereum | bsc | base | arbitrum | polygon | optimism | solana | tron

## Response
{{"verdict":"safe|warn|block","score":0-100,"checks":[{{"name","status","detail","evidence"}}],"sources":[...]}}
verdict=block → do not trade. Every check carries its proof.

## Payment (x402)
{"FREE (demo mode)." if PRICE_USDC <= 0 else f"{PRICE_USDC} USDC/call on {NETWORK} via x402."}
First call → HTTP 402 with `accepts` (PaymentRequirements). Pay with an x402 client,
retry with the X-PAYMENT header. Free endpoints: GET /llms.txt, GET /v1/status.

## MCP
Run `python3 mcp_server.py` to expose `check_token(chain, address)` as an MCP tool.
"""


class H(BaseHTTPRequestHandler):
    server_version = "guardbot/0.1"

    def log_message(self, *a):
        print(f"[{time.strftime('%H:%M:%S')}] " + (a[0] % a[1:]), flush=True)

    def _json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass   # client disconnected (e.g. refreshed / navigated) — ignore

    def _resource_url(self):
        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        return f"http://{host}/v1/check"

    def _require_payment(self):
        """(ok, settle_response|None). In free mode, always ok."""
        if PRICE_USDC <= 0:
            return True, None
        reqs = payment_requirements(self._resource_url())
        payload = read_payment_header(self.headers)
        if payload is None:
            with LOCK:
                STATS["challenges"] += 1
            self._json(402,
                       {"x402Version": 1, "accepts": [reqs], "error": "payment required"},
                       {"PAYMENT-REQUIRED": _b64json({"x402Version": 1, "accepts": [reqs]})})
            return False, None
        ok, res = verify_and_settle(payload, reqs)
        if not ok:
            self._json(402, {"x402Version": 1, "accepts": [reqs], "error": res})
            return False, None
        return True, res

    def _check(self, chain, address):
        if not chain or not address:
            return self._json(400, {"error": "chain and address are required"})
        ok, settle = self._require_payment()
        if not ok:
            return  # 402 response already sent
        try:
            verdict = cached_assess(chain, address)
        except Exception as e:
            return self._json(500, {"error": f"check failed: {e}"})
        extra = {"X-PAYMENT-RESPONSE": _b64json(settle), "PAYMENT-RESPONSE": _b64json(settle)} if settle else {}
        return self._json(200, verdict, extra)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/view"):
            try:
                with open(os.path.join(BASE, "view.html"), "rb") as fh:
                    body = fh.read()
            except OSError:
                body = b"<h1>viewer not found</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            # the viewer is edited often; never let a browser serve a stale copy of it
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/dev/seed" and DEV_SEED:
            # test-only page that asks a TEST wallet to create a tiny grant on a TESTNET, so the
            # revoke signing can be exercised for free. Off unless GUARDBOT_DEV_SEED=1.
            try:
                with open(os.path.join(BASE, "tools", "seed_grants.html"), "rb") as fh:
                    body = fh.read()
            except OSError:
                body = b"<h1>seed page not found</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/llms.txt":
            body = LLMS.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/v1/status":
            with LOCK:
                s = dict(STATS)
            self._json(200, {"service": "guardbot",
                             "mode": "free" if PRICE_USDC <= 0 else ("x402" if (FACILITATOR and PAY_TO) else "x402-unconfigured"),
                             "price_usdc": PRICE_USDC, "network": NETWORK,
                             "uptime_s": int(time.time() - START),
                             "code_version": CODE_VERSION, **s})
        elif u.path == "/v1/check":
            q = parse_qs(u.query)
            self._check((q.get("chain") or [""])[0], (q.get("address") or [""])[0])
        elif u.path == "/v1/tokencheck":
            # first-hand verdict: we simulate buying and selling the token ourselves.
            q = parse_qs(u.query)
            chain = (q.get("chain") or ["bsc"])[0].strip()
            token = (q.get("address") or q.get("token") or [""])[0].strip()
            if not token:
                return self._json(400, {"error": "address is required"})
            try:
                if chain == "solana":
                    self._json(200, solcheck.check_token(token))
                elif chain == "tron":
                    self._json(200, troncheck.check_token(token))
                else:
                    self._json(200, tokencheck.check_token(chain, token))
            except Exception as e:
                self._json(500, {"error": f"token check failed: {e}"})
        elif u.path == "/v1/config":
            # Frontend config. The WalletConnect projectId is a PUBLIC frontend identifier (safe
            # to expose); it's read from env so no account detail is baked into the code. Empty =
            # WalletConnect stays off and the viewer uses injected wallets only.
            self._json(200, {"wc_project_id": os.environ.get("GUARDBOT_WC_PROJECT_ID", ""),
                             "sol_rpc": approvals_mod.SOL_RPC,
                             "tron_network": approvals_mod.TRON_NETWORK,
                             "testnet": TESTNET,
                             "dev_seed": DEV_SEED})
        elif u.path == "/v1/revoke":
            # Builds the revoking calldata only. Nothing is signed or broadcast server-side:
            # the wallet does that, so this endpoint can never move anyone's funds.
            q = parse_qs(u.query)
            g = lambda k: (q.get(k) or [""])[0].strip()
            try:
                chain = g("chain").lower()
                if chain == "solana":
                    # no calldata here — the browser builds the instruction; the server PROVES it
                    self._json(200, revoke_mod.simulate_revoke_solana(g("owner"), g("account") or g("token")))
                elif chain == "tron":
                    self._json(200, revoke_mod.simulate_revoke_tron(g("owner"), g("token"), g("spender")))
                elif g("owner"):
                    # prove the effect before the user signs — simulate the revoke and re-read
                    self._json(200, revoke_mod.simulate_revoke(g("chain"), g("kind"), g("owner"),
                                                               g("token"), g("spender")))
                else:
                    self._json(200, revoke_mod.revoke_tx(g("chain"), g("kind"),
                                                         g("token"), g("spender")))
            except Exception as e:
                self._json(500, {"error": f"could not build the revoke tx: {e}"})
        elif u.path == "/v1/detect":
            # wallet or token? lets one paste field route itself in the viewer
            q = parse_qs(u.query)
            a = (q.get("address") or [""])[0].strip()
            if not a:
                return self._json(400, {"error": "address is required"})
            try:
                self._json(200, approvals_mod.detect_kind(a))
            except Exception as e:
                self._json(500, {"error": f"detect failed: {e}"})
        elif u.path == "/v1/approvals":
            # local-first & private: nothing is stored server-side or published. cached=1 returns
            # the local index's last result instantly (µs); otherwise a live scan (~seconds).
            q = parse_qs(u.query)
            addr = (q.get("address") or [""])[0].strip()
            cached = (q.get("cached") or ["0"])[0] in ("1", "true", "yes")
            if not addr:
                return self._json(400, {"error": "address is required"})
            try:
                res = approvals_mod.approvals(addr, cached_only=cached)
                # BSC has no free log history, so the live scan PROBES a mined candidate list —
                # which can miss an unmined spender. The certainty pass (nonce-walk over the
                # wallet's own transactions, ~5 min) is too slow for a click, so it launches
                # itself in the background ONCE per wallet; the next scan includes its finds.
                if (not cached and "bsc" in (res.get("probed_chains") or [])
                        and approvals_mod._cached("bsc#deepscan", addr)[1] is None):
                    try:
                        import subprocess
                        logp = os.path.join(os.path.expanduser("~"), ".guardbot", "deepscan.log")
                        subprocess.Popen(["python3", os.path.join(BASE, "tools", "deepscan_bsc.py"), addr],
                                         stdout=open(logp, "ab"), stderr=subprocess.STDOUT)
                        approvals_mod._store("bsc#deepscan", addr, set(), 1)
                        res["deepscan_started"] = ["bsc"]
                    except Exception:
                        pass
                self._json(200, res)
            except Exception as e:
                self._json(500, {"error": f"approvals lookup failed: {e}"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/v1/check":
            return self._json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            p = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            return self._json(400, {"error": f"invalid body: {e}"})
        self._check(str(p.get("chain", "")), str(p.get("address", "")))


if __name__ == "__main__":
    if PRICE_USDC <= 0:
        mode = "FREE (demo)"
    elif FACILITATOR and PAY_TO and ASSET:
        mode = f"{PRICE_USDC} USDC/call · REAL x402 on {NETWORK}"
    else:
        mode = f"{PRICE_USDC} USDC/call · WARNING x402 NOT configured (missing facilitator/pay_to/asset) -> paid requests rejected"
    print(f"\n  GuardBot running  ·  code {CODE_VERSION}  ·  payment: {mode}", flush=True)
    print("  (restart me after a git pull — a running daemon keeps the code it started with)",
          flush=True)
    print(f"  ➜  Approvals viewer:  http://127.0.0.1:{PORT}/view", flush=True)
    print(f"  ➜  API / agents:      http://127.0.0.1:{PORT}/llms.txt", flush=True)
    if TESTNET:
        print(f"  ⚠  TESTNET MODE: solana={approvals_mod.SOL_RPC}  tron={approvals_mod.TRON_NETWORK}"
              "  — EVM chains are still mainnet", flush=True)
    if DEV_SEED:
        print(f"  ➜  Test grants page:  http://127.0.0.1:{PORT}/dev/seed   (test wallets only)", flush=True)
    if HOST not in ("127.0.0.1", "localhost"):
        lan = _lan_ip()
        print(f"  ➜  On this network:   http://{lan or HOST}:{PORT}/view   "
              f"(phone on the same Wi-Fi; open it in your wallet's browser)", flush=True)
        print("     (a firewall must allow the port: e.g. "
              f"sudo ufw allow from 192.168.0.0/16 to any port {PORT} proto tcp)", flush=True)
    print("  (Ctrl+C to stop)\n", flush=True)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
