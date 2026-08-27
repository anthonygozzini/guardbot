# GuardBot ⚡ — pre-trade safety per agenti & bot (v0)

Prima di comprare un token: **è un rug / honeypot / trappola?** GuardBot aggrega
RugCheck (Solana) e GoPlus (EVM) in **un solo verdetto** `safe | warn | block` **con
le prove**. Non instrada trade, non tocca fondi: legge solo dati pubblici.

È il v0 del **Piano Breve** della roadmap (ponte di cassa: grant Arbitrum Trailblazer +
per-chiamata x402 + ricompense builder). Riusa il contratto "verdetto con prove" e il
paywall 402 di Referee (`~/vibe/referee/`).

## Cosa fa (provato su token reali)
- **safe** (score 100): token puliti.
- **warn** (es. 88 — "CyberLeek": metadata mutabile; USDC-Solana: mint/freeze authority attive).
- **block** (es. 0 — "モナー": liquidità bassa + holder concentrato).

Ogni check porta la sua prova (honeypot, mint/freeze authority, tax, liquidità,
concentrazione holder, LP, ecc.).

## Componenti
- `guard.py` — il motore: `assess(chain, address)` → verdetto normalizzato. Stdlib, con
  timeout/fallback (se una fonte è giù → `warn` esplicito, mai un falso `safe`).
- `guardd.py` — daemon HTTP.
- `mcp_server.py` — server MCP (stdio): espone `check_token(chain, address)` come tool.

## Avvio
```bash
cd ~/vibe/guardbot

# motore da CLI
python3 guard.py solana EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v

# daemon HTTP (gratis, per demo/test/ricompense builder)
python3 guardd.py                       # :8403
curl "http://127.0.0.1:8403/v1/check?chain=solana&address=<mint>"
curl -X POST http://127.0.0.1:8403/v1/check -d '{"chain":"base","address":"0x…"}'

# modalità a pagamento (scaffold x402): ritorna 402 con challenge
GUARDBOT_PRICE_USDC=0.01 GUARDBOT_PAY_TO=0x<tuo> python3 guardd.py

# tool MCP per un agente (Claude / VibeKit)
python3 mcp_server.py                    # parla JSON-RPC su stdio
```
Endpoint gratis: `GET /llms.txt` (onboarding agenti), `GET /v1/status`.
Chain: `solana | ethereum | bsc | base | arbitrum | polygon | optimism | avalanche`.

## Modello di guadagno
- **Gratis** (default v0): usabile subito, per demo e ricompense builder Base/Farcaster.
- **Per-chiamata x402-USDC** (scaffold pronto): micro-fee per verifica, come GoPlus pay-as-you-go.
- **Grant** Arbitrum Trailblazer ($10k): impacchettare come tool MCP per agenti VibeKit.

## Stato — cosa è vero e cosa manca (onesto)
- [x] Motore `assess()` funzionante su Solana (RugCheck) + EVM (GoPlus), verdetto+prove, provato su token reali.
- [x] Daemon HTTP (`/v1/check`, `/llms.txt`, `/v1/status`) + cache.
- [x] Server MCP stdio con tool `check_token` (initialize/tools.list/tools.call verificati).
- [x] **Pagamento x402 REALE** (non più stub): 402 con `accepts` → verify+settle via facilitator
      → verdetto + header `X-PAYMENT-RESPONSE`. Provato end-to-end (facilitator finto); se il
      facilitator non è configurato, le richieste a pagamento vengono rifiutate (mai un falso 'pagato').
- [ ] **Azioni fisicamente di Anthony** (vedi `HANDOFF.md`): pubblicare il repo, inviare la
      submission Trailblazer ($10k), attivare un canale di ricompense builder, e accendere x402
      con un facilitator + wallet reali. Tutto preparato al copia-incolla.

## Riferimenti
- GoPlus Security API — https://docs.gopluslabs.io/reference/api-overview
- RugCheck REST — https://api.rugcheck.xyz/swagger/index.html
- Arbitrum Trailblazer 2.0 — https://blog.arbitrum.foundation/trailblazer-2-0-1m-in-grants-to-power-agentic-defi-on-arbitrum/
- VibeKit — https://vibekit.ai/
- Riuso da Referee — `~/vibe/referee/refereed.py` (paywall 402, token HMAC, verdetto+prove)
- Piano completo — Piano Breve (artifact) + `~/.claude/plans/all-artefatto-…dazzling-codd.md`

⚠️ Note: GoPlus-Solana è inaffidabile (timeout/null) → per Solana ci si affida a RugCheck.
Non è consulenza finanziaria; è un segnale di sicurezza su dati pubblici.
