# GuardBot — handoff: le 3 azioni che restano (fisicamente tue)

Il prodotto è **costruito e provato**: motore + server HTTP + tool MCP + **pagamento x402
reale** (verify+settle via facilitator, provato end-to-end con un facilitator finto).
Quello che resta del Piano Breve richiede **il tuo wallet / GitHub / Google** — io non posso
essere te. Qui è tutto ridotto a copia-incolla.

---

## 1. Pubblica il repo (serve al grant) — ~2 min
```bash
cd ~/vibe/guardbot
git remote add origin https://github.com/anthonygozzini/guardbot.git   # crea prima il repo vuoto su GitHub
git push -u origin main
```
(Ho già fatto `git init` + primo commit in locale; il secret è escluso via `.gitignore`.)

## 2. Invia la submission al grant Arbitrum Trailblazer 2.0 ($10k) — ~5 min
Form: https://docs.google.com/forms/d/e/1FAIpQLSe-GF7UcUOuyEMsgnVpLFrG_W83RAchaPPqOCD83pZaZXskgw/viewform

Risposte pronte da incollare:
- **Project name:** GuardBot
- **One-liner:** Pre-trade safety as a typed MCP tool for agents — one `check_token` call
  returns safe/warn/block with the evidence, aggregating RugCheck (Solana) + GoPlus (EVM).
- **Why it fits (agentic DeFi / VibeKit):** VibeKit trading agents can lose funds to rugs and
  honeypots. GuardBot is a drop-in MCP safety tool an agent calls *before* it buys — a
  capability integration that makes every VibeKit agent safer. MCP-native, matches the
  Trailblazer requirement.
- **What's built:** working `check_token` MCP tool + HTTP API, x402 per-call payments
  (verify+settle), verdict-with-evidence contract. Demo + repo below.
- **Repo:** <link dal punto 1>
- **Amount requested:** $10,000
- **Milestones:** (1) VibeKit plug-in packaging + example agent; (2) multi-chain coverage
  (Arbitrum via GoPlus chain 42161 — già supportato dal motore); (3) latency SLA + caching;
  (4) mainnet x402 billing live.
- **Team:** Anthony Gozzini (solo builder) — vedi CV/GitHub.
- **Contact:** (tua email/telegram)

> Nota: Trailblazer chiede di costruire con/per **VibeKit** (framework MCP di Ember). Il
> milestone 1 è proprio impacchettare GuardBot come plug-in VibeKit — coerente col requisito.

## 3. Attiva un canale di ricompensa builder (cassa immediata) — ~10 min
Il trickle più rapido, ma serve il tuo wallet/identità:
- **Base builder rewards** (builderscore.xyz): serve un **Basename** + **Builder Score ≥40** +
  checkmark umano. Registra il Basename, collega il wallet, e lo scoring premia attività
  on-chain/open-source settimanale.
- In parallelo: lista GuardBot sulle **directory L402/x402** e su un board bounty allineato.

---

## Per accendere x402 REALE (primo incasso vero) — quando vuoi
Il codice è pronto; serve un facilitator + il tuo indirizzo + testnet finanziato:
```bash
GUARDBOT_PRICE_USDC=0.01 \
GUARDBOT_NETWORK=base-sepolia \
GUARDBOT_FACILITATOR=<url facilitator x402> \
GUARDBOT_PAY_TO=0x<tuo indirizzo> \
python3 guardd.py
```
Un client x402 paga in USDC e ottiene il verdetto; il server fa verify+settle sul facilitator.
Testato end-to-end con facilitator finto → identico contro uno reale. (Conferma i campi di
`payment_requirements()` contro il `/supported` del facilitator scelto prima del mainnet.)
