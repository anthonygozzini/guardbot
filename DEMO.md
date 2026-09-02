# The 30-second demo

Three beats, one paste field. Record the browser at `http://127.0.0.1:8403/view` (dark theme,
~1280px window). Everything shown is real and reproducible; nothing is mocked.

## Pre-warm (run < 2 minutes before recording — makes every paint instant)

```bash
python3 guardd.py   # mainnet mode, no TESTNET chip
# in another shell:
curl -s "http://127.0.0.1:8403/v1/tokencheck?chain=bsc&address=0xbEC0209f3fe563f6726F7BEE38d72d57fd758888" > /dev/null
curl -s "http://127.0.0.1:8403/v1/tokencheck?chain=bsc&address=0x55d398326f99059fF775485246999027B3197955" > /dev/null
curl -s "http://127.0.0.1:8403/v1/approvals?address=0x01B84E832265C81a5dCb4c326326fe49dC424810" > /dev/null
```

## Beat 1 — the catch nobody else makes (0–10s)

Paste `0xbEC0209f3fe563f6726F7BEE38d72d57fd758888` → Scan.

The panel returns **BLOCK**: *"the ticker only LOOKS like 'USDT' — it is written with lookalike
characters (ՍՏⅮꓔ)"*, pointing at the real USDT the market trades.

**Caption:** "BscScan flags this token. honeypot.is shows it as PASSED. GuardBot returns a block
verdict — with the evidence: the ticker is a typographic disguise."

## Beat 2 — the honest positive (10–18s)

Paste `0x55d398326f99059fF775485246999027B3197955` (real Binance-Peg USDT) → Scan.

**SAFE**, with the stat row: round trip ~99.5% back, 0% taxes, ~70k BNB pool.

**Caption:** "Verdicts come from actually simulating a buy and a sell against live liquidity —
no vendor API. A real token reads safe, with the numbers."

## Beat 3 — the other half: what did you already sign away? (18–30s)

Paste `0x01B84E832265C81a5dCb4c326326fe49dC424810` (public example wallet) → Scan.

The unified approvals table appears — the same rows revoke.cash shows, to the decimal, plus the
chains a single revoke tool doesn't unify (EVM + Solana + TRON). Click **Revoke** on a row: the
sign box shows the exact call and *"✓ simulated on-chain: this sets the permission to 0 (no gas
spent)"*. Don't sign — it's not your wallet.

**Caption:** "One field, three chains: see every standing approval, prove the revoke on-chain
before signing, take permissions back. Local-first, zero dependencies, zero keys."

## Close (2s)

**Caption:** "GuardBot — first-hand pre-trade safety. github.com/anthonygozzini/guardbot"

## Notes
- Wording discipline: GuardBot is read-only — it *returns verdicts with evidence*; it never
  blocks, routes, or touches funds. Keep captions to what the tool provably does.
- The revoke simulation in beat 3 runs live (~2–5s): keep the cursor still, let it land.
- Agent variant (alternative beat 3): `python3 mcp_server.py` in a terminal + one
  `check_token` call from an MCP client, for a developer-facing cut.
