#!/usr/bin/env python3
"""GuardBot daemon — HTTP API per il verdetto di sicurezza pre-trade, con pagamento x402.

Endpoint:
  GET  /llms.txt      onboarding per agenti (gratis)
  GET  /v1/status     stato servizio (gratis)
  GET  /v1/check?chain=<c>&address=<a>   verdetto (a pagamento se PRICE>0)
  POST /v1/check      body {chain,address}

Pagamento = x402 vero (HTTP 402 + facilitator /verify + /settle), scheme "exact".
Modalità:
  - PRICE_USDC=0 (default): gratis, usabile/demo subito.
  - PRICE_USDC>0 + GUARDBOT_FACILITATOR + GUARDBOT_PAY_TO: enforcement on-chain reale.
    Se PRICE>0 ma manca il facilitator, la richiesta a pagamento viene RIFIUTATA (nessun
    falso 'pagato'): l'enforcement è reale o assente, mai finto.
Riusa da Referee lo spirito del contratto (verdetto+prove) e il paywall per-chiamata.
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

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("GUARDBOT_PORT", "8403"))
PRICE_USDC = float(os.environ.get("GUARDBOT_PRICE_USDC", "0"))
PAY_TO = os.environ.get("GUARDBOT_PAY_TO", "")
FACILITATOR = os.environ.get("GUARDBOT_FACILITATOR", "").rstrip("/")
NETWORK = os.environ.get("GUARDBOT_NETWORK", "base-sepolia")
CACHE_TTL = 120
FAC_TIMEOUT = 20

# USDC per network (6 decimali). Override con GUARDBOT_ASSET se serve.
USDC = {
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}
ASSET = os.environ.get("GUARDBOT_ASSET", USDC.get(NETWORK, ""))
ATOMIC = str(int(round(PRICE_USDC * 1_000_000)))  # USDC 6 decimali

START = time.time()
STATS = {"checks": 0, "blocked": 0, "warned": 0, "paid": 0, "challenges": 0}
LOCK = threading.Lock()
CACHE = {}
SETTLED = set()   # replay-guard sui tx già regolati


def payment_requirements(resource_url):
    """x402 'exact' scheme PaymentRequirements. Validare i campi contro il /supported
    del facilitator scelto prima del mainnet."""
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
    """Accetta i nomi header divergenti dell'ecosistema (Coinbase X-PAYMENT /
    foundation PAYMENT-SIGNATURE). Ritorna il PaymentPayload decodificato o None."""
    raw = headers.get("X-PAYMENT") or headers.get("PAYMENT-SIGNATURE") or headers.get("X-Payment")
    if not raw:
        return None
    try:
        return json.loads(base64.b64decode(raw))
    except Exception:
        return None


def verify_and_settle(payload, requirements):
    """Enforcement x402 reale via facilitator: /verify poi /settle.
    Ritorna (ok: bool, settle_response|reason)."""
    if not (FACILITATOR and PAY_TO and ASSET):
        return False, "facilitator/pay_to non configurati (enforcement non attivo)"
    body = {"x402Version": 1, "paymentPayload": payload, "paymentRequirements": requirements}
    try:
        v = _facilitator("/verify", body)
    except Exception as e:
        return False, f"facilitator /verify irraggiungibile: {str(e)[:120]}"
    if not v.get("isValid", v.get("valid", False)):
        return False, f"pagamento non valido: {v.get('invalidReason') or v.get('reason') or 'rifiutato'}"
    # anti-replay: chiave = tx/nonce del payload
    key = json.dumps(payload.get("payload", payload), sort_keys=True)[:512]
    with LOCK:
        if key in SETTLED:
            return False, "pagamento già usato"
    try:
        s = _facilitator("/settle", body)
    except Exception as e:
        return False, f"facilitator /settle irraggiungibile: {str(e)[:120]}"
    if not s.get("success", False):
        return False, f"settle fallito: {s.get('errorReason') or s.get('error') or 'sconosciuto'}"
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

Ask before you buy: is this token a rug / honeypot / trap? GuardBot aggregates
RugCheck (Solana) and GoPlus (EVM) into ONE verdict with the evidence.

## Endpoint
GET /v1/check?chain=<chain>&address=<token>
POST /v1/check  {{"chain":"solana","address":"<mint>"}}
chain: solana | ethereum | bsc | base | arbitrum | polygon | optimism | avalanche

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
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _resource_url(self):
        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        return f"http://{host}/v1/check"

    def _require_payment(self):
        """(ok, settle_response|None). In modalità gratis sempre ok."""
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
            return self._json(400, {"error": "servono chain e address"})
        ok, settle = self._require_payment()
        if not ok:
            return  # risposta 402 già inviata
        try:
            verdict = cached_assess(chain, address)
        except Exception as e:
            return self._json(500, {"error": f"check fallito: {e}"})
        extra = {"X-PAYMENT-RESPONSE": _b64json(settle), "PAYMENT-RESPONSE": _b64json(settle)} if settle else {}
        return self._json(200, verdict, extra)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/llms.txt"):
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
                             "uptime_s": int(time.time() - START), **s})
        elif u.path == "/v1/check":
            q = parse_qs(u.query)
            self._check((q.get("chain") or [""])[0], (q.get("address") or [""])[0])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/v1/check":
            return self._json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            p = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            return self._json(400, {"error": f"body non valido: {e}"})
        self._check(str(p.get("chain", "")), str(p.get("address", "")))


if __name__ == "__main__":
    if PRICE_USDC <= 0:
        mode = "GRATIS (demo)"
    elif FACILITATOR and PAY_TO and ASSET:
        mode = f"{PRICE_USDC} USDC/call · x402 REALE su {NETWORK}"
    else:
        mode = f"{PRICE_USDC} USDC/call · ⚠ x402 NON configurato (mancano facilitator/pay_to/asset) → richieste a pagamento rifiutate"
    print(f"guardbot su :{PORT}  ·  pagamento: {mode}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
