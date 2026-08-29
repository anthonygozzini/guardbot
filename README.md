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

### Approvals viewer — local-first, private, and fast
```bash
python3 guardd.py            # then open http://127.0.0.1:8403/view
python3 approvals.py 0x…     # or TRON T… / Solana base58
```
**Runs entirely on your machine.** The browser paints the last result from your local index
**instantly** (microseconds), then refreshes it with a live scan. No hosted server ever sees
which address you look up.

**Speed — minutes → seconds → microseconds.** Listing every approval means reading historical
`Approval` events, which base-layer RPCs don't index. A naïve full-history sweep is minutes/chain.
GuardBot's own scanner instead:
- **skips dead chains instantly** — `eth_getTransactionCount == 0` means the address never acted
  there, so no approval is possible (a binary search on the nonce also bounds the active window);
- **adaptive parallel scan** — seeds wide block ranges across a pool of free public RPCs and only
  splits a range when a provider rejects it as too large, trying *every* pool RPC before giving up.
  A range no free RPC will serve is reported as a **partial** scan, never silently dropped;
- **local incremental index** (`~/.guardbot`, private, outside the repo, never uploaded) — the
  first scan is seconds; every re-scan reads cached `(token,spender)` pairs and only the blocks
  added since, and an instant cached paint is ~microseconds. Disable with `GUARDBOT_NO_CACHE=1`.

Result on a normal wallet: full multi-chain live scan in ~2s, cached re-open in <1ms.

**Coverage & honesty.** Ethereum / Arbitrum / Polygon use the free **Etherscan V2** key
(`GUARDBOT_ETHERSCAN_KEY`); Base / Optimism / Polygon use the built-in free-RPC scanner. **BSC has
no free `getLogs`** (every public BSC RPC returns `limit exceeded`), so it is reported as
`degraded` until you add a keyed provider — never counted as clean. Keys live only in your local
`.env` (gitignored, never shipped):
```bash
echo 'GUARDBOT_ETHERSCAN_KEY=<your key>' >> .env   # free, covers eth/arbitrum/polygon
echo 'GUARDBOT_ALCHEMY_KEY=<your key>'   >> .env   # used for eth_call (allowance/symbol)
```

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
- [x] Local-first approvals viewer (`/v1/approvals`, `/view`) across EVM + TRON + Solana —
      live, private, bring-your-own-key; the "fix" side of the "prevent" side.
- [x] Own multi-chain scanner: nonce-skip + adaptive parallel `getLogs` + local incremental
      index (µs cached paint → ~2s live), partial ranges surfaced, never silently dropped.
- [ ] BSC full-history source (no free `getLogs`; needs a keyed provider).
- [ ] Revoke action (signed tx via WalletConnect).
- [ ] VibeKit plug-in packaging + example agent.
- [ ] Multi-chain expansion + latency SLA.

## References
- GoPlus Security API — https://docs.gopluslabs.io/reference/api-overview
- RugCheck REST — https://api.rugcheck.xyz/swagger/index.html
- x402 — https://github.com/x402-foundation/x402
- VibeKit — https://vibekit.ai/

Note: GoPlus's Solana endpoint is unreliable (timeouts/null) → Solana relies on RugCheck.
This is a safety signal on public data, not financial advice.
