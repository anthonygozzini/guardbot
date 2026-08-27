# GuardBot ⚡ — pre-trade safety for agents & bots

Before you buy a token: **is it a rug / honeypot / trap?** GuardBot aggregates
RugCheck (Solana) and GoPlus (EVM) into **one verdict** — `safe | warn | block` — **with
the evidence**. It never routes trades or touches funds: it only reads public data.

Designed as a typed **MCP tool** an agent calls *before* it buys, plus a plain HTTP API,
with per-call **x402** payments.

## What it does (tested on live tokens)
- **safe** (score 100): clean tokens.
- **warn** (e.g. 88 — mutable metadata; USDC-Solana: active mint/freeze authority).
- **block** (e.g. 0 — low liquidity + concentrated holder).

Every check carries its proof (honeypot, mint/freeze authority, taxes, liquidity, holder
concentration, LP, and more).

GuardBot does both sides of safety:
- **Prevent** — `check_token`: is a token a trap *before* you buy?
- **Fix / view** — `approvals`: paste any address, see standing token approvals across
  **EVM + TRON + Solana** in one place (what single-chain revoke tools don't unify). Read-only.

## Components
- `guard.py` — token-safety engine: `assess(chain, address)` → normalized verdict. Stdlib only.
- `approvals.py` — approval viewer: `approvals(address)` across EVM (Approval events + live
  allowance, the revoke.cash method), TRON (TronScan), Solana (SPL delegates via RPC).
- `guardd.py` — HTTP daemon: `/v1/check`, `/v1/approvals`, `/view` (browser UI), x402 payments.
- `mcp_server.py` — MCP server (stdio): exposes `check_token(chain, address)` as a tool.

### Approvals viewer — local-first & private
```bash
python3 guardd.py            # then open http://127.0.0.1:8403/view
python3 approvals.py 0x…     # or TRON T… / Solana base58
```
**Runs entirely on your machine. Queries are live and ephemeral — nothing is stored, cached,
or published.** No server sees which address you look up (unlike a hosted checker).

For complete EVM coverage, bring your own free **Alchemy key** (one key covers Ethereum, Base,
Arbitrum, Optimism, Polygon, BSC) — Alchemy's `getLogs` limits by result count, not block range,
so an owner-filtered Approval query passes over full history:
```bash
echo 'GUARDBOT_ALCHEMY_KEY=<your key>' >> .env   # .env is gitignored, never shipped
python3 guardd.py
```
The key lives only in your local `.env`, never in the code or the repo — **bring-your-own-key**.
Without it, only chains whose public RPC allows full-history `getLogs` are scanned (e.g. Arbitrum);
the rest are reported as `degraded`, never silently missed. (This is why free-tier token-security
APIs miss approvals: reading Approval events across full history needs an indexed provider or
your own node — that's the data source you plug in, under your control.)

## Run
```bash
# engine from the CLI
python3 guard.py solana EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v

# HTTP daemon (free, for demo/testing)
python3 guardd.py                       # :8403
curl "http://127.0.0.1:8403/v1/check?chain=solana&address=<mint>"
curl -X POST http://127.0.0.1:8403/v1/check -d '{"chain":"base","address":"0x…"}'

# paid mode (real x402): returns 402 with `accepts`, verifies + settles via a facilitator
GUARDBOT_PRICE_USDC=0.01 \
GUARDBOT_NETWORK=base-sepolia \
GUARDBOT_FACILITATOR=<x402 facilitator url> \
GUARDBOT_PAY_TO=0x<your address> \
python3 guardd.py

# MCP tool for an agent (Claude / VibeKit)
python3 mcp_server.py                    # speaks JSON-RPC over stdio
```
Free endpoints: `GET /llms.txt` (agent onboarding), `GET /v1/status`.
Chains: `solana | ethereum | bsc | base | arbitrum | polygon | optimism | avalanche`.

## Payment model
- **Free** (default): usable right away, for demos.
- **Per-call x402-USDC**: micro-fee per check, like GoPlus's agent pay-as-you-go. Real
  enforcement (facilitator `/verify` + `/settle`); if the facilitator isn't configured,
  paid requests are rejected — never a false "paid".

## Status
- [x] `assess()` engine on Solana (RugCheck) + EVM (GoPlus), verdict + evidence, tested on live tokens.
- [x] HTTP daemon (`/v1/check`, `/llms.txt`, `/v1/status`) + cache.
- [x] MCP stdio server with the `check_token` tool.
- [x] Real x402 payments (402 `accepts` → verify + settle → verdict + `X-PAYMENT-RESPONSE`),
      tested end-to-end.
- [ ] VibeKit plug-in packaging + example agent.
- [ ] Multi-chain expansion + latency SLA.

## References
- GoPlus Security API — https://docs.gopluslabs.io/reference/api-overview
- RugCheck REST — https://api.rugcheck.xyz/swagger/index.html
- x402 — https://github.com/x402-foundation/x402
- VibeKit — https://vibekit.ai/

Note: GoPlus's Solana endpoint is unreliable (timeouts/null) → Solana relies on RugCheck.
This is a safety signal on public data, not financial advice.
