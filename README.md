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
- **Prevent** — is a token a trap *before* you buy? Answered **first-hand**: we simulate
  buying and selling it ourselves (see below), rather than asking a vendor's API.
- **Fix / view** — `approvals`: paste any address, see standing token approvals across
  **EVM + TRON + Solana** in one place (what single-chain revoke tools don't unify). Read-only.

## Honeypot detection, done first-hand (`tokencheck.py`)

Nobody's API is asked whether a token is a scam. `eth_call` accepts a **state override**, so a
throwaway address can be handed some native coin and then **actually buy the token and sell it
back** — atomically, in one call, against live liquidity, using Multicall3 as the temporary
holder. Nothing is signed, nothing is spent. If the sell reverts, it's a honeypot; if less money
comes back than the quote promised, that difference *is* the tax.

Also read straight from the chain: liquidity depth, share of LP burned, whether ownership is
renounced, whether it's an upgradeable proxy, and which privileged functions (mint, blacklist,
pause, fee setters) genuinely exist in the deployed bytecode — matched by selectors computed
with our own `keccak.py`, since Python ships SHA3-256, which is not keccak256.

**A failure has to prove itself.** A reverted sell can mean "honeypot" or "the node hiccuped",
and the two are indistinguishable in the response. So every failure is paired with a *control*
token that is certainly sellable, run through the same node at the same moment: if the control
fails too, the observation is thrown away. The whole analysis is also pinned to **one block** —
without that, reserves shift between calls on a busy pool, the second buy returns slightly less
than the first, the sell overdraws, and the tool brands **USDT** a honeypot. It did, twice,
until this was fixed.

Measured on BSC (real tokens people had approved): **5/5 honeypots blocked** across repeat runs,
**0 false positives in 20 consecutive runs** on CAKE / USDT / BUSD / WBNB. Chains: BSC,
Ethereum, Base, Arbitrum, Polygon.

```bash
python3 tokencheck.py bsc 0x<token>
curl "http://127.0.0.1:8403/v1/tokencheck?chain=bsc&address=0x<token>"
```

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

**Probing the present when the past is unreadable.** BSC refuses `eth_getLogs` on every free RPC
(`limit exceeded`, or a 50-block ceiling — useless across 118M blocks), so approval *history* there
cannot be read for free. GuardBot doesn't buy an indexer for it: it changes mechanism.
`eth_call` is never range-limited, and **Multicall3** — same address on every EVM chain — batches
thousands of `allowance()` calls into **one** request (measured: 4000 calls / 2.6s on BSC). So the
present is probed instead of the past being read:

1. `tools/mine_probe_universe.py` samples real `Approval` events from the chain itself and keeps
   the `(token, spender)` pairs that actually occur — the universe is mined from the chain, not
   hardcoded and not bought. On BSC: 7.7k unique pairs exist, the top 4000 cover **96.6%** of all
   observed approval activity (`probe_universe.json`).
2. Every candidate pair is checked live via Multicall3 in ~8 batched requests.

Verified against ground truth: **3/3 real BSC approvals recovered, ~0.8s each, zero `getLogs`,
zero API keys, zero third-party services** — including two unlimited USDT approvals that the
log-scanning path could never see. Results are labelled `probed` with their coverage %: high, but
reported as a probe, never implied to be exhaustive.

The probe runs on **every** chain, not just BSC, alongside the log scan — the two sources are
unioned, so history is exhaustive where it's readable and the probe is the floor everywhere else.
Universes are mined per chain (`ethereum` 12k pairs / 92.2%, `base` 4k / 97.6%, `bsc` 4k / 96.6%,
`polygon`, `optimism`, `arbitrum` 100% of their sampled activity).

**Don't trust the token contracts.** The probe queries contracts nobody vetted, and scam tokens
exist whose `allowance()` returns "unlimited" for the scammer's spender *no matter who the owner
is* — 8 such contracts sit in Ethereum's top-12k pairs alone. Every hit is therefore re-asked for
a **canary owner** that cannot have approved anything: a truthful ERC-20 answers 0, a fabricator
doesn't, and its hits are dropped. Measured: 8 lies in → 0 out, genuine approvals untouched.

**Are keys still required? No.** Same address, same result:

| mode | time | chains | approvals found |
|---|---|---|---|
| with Etherscan + Alchemy keys | 2.4s | 6/6, none degraded | 4 |
| **no keys at all** (public RPCs only) | 10.0s | 6/6, none degraded | **4** |
| cached re-open | 0.1ms | — | 4 |

Keys buy **speed and exhaustive history**, not coverage. Without them nothing is skipped: each
chain is reported as `scanned`, `probed`, `partial`, or `degraded`. Keys are optional and live
only in your local `.env` (gitignored, never shipped):
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
- [x] BSC covered with **no** log history and **no** paid provider: Multicall3 present-probing over
      a chain-mined candidate universe (96.6% coverage, 3/3 ground-truth approvals recovered).
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
