#!/usr/bin/env python3
"""GuardBot MCP server (stdio) — espone check_token come tool MCP tipizzato.

Un agente (Claude, VibeKit, ecc.) monta questo server e chiama check_token(chain, address)
prima di comprare. Nessuna dipendenza: JSON-RPC 2.0 newline-delimited su stdin/stdout,
come da transport stdio di MCP. La logica di sicurezza è guard.assess().
"""

import json
import sys

import guard

PROTOCOL = "2024-11-05"
TOOL = {
    "name": "check_token",
    "description": ("Pre-trade safety check: dato un token (chain + address), ritorna un "
                    "verdetto safe/warn/block con le prove. Aggrega RugCheck (Solana) e "
                    "GoPlus (EVM). Usalo PRIMA di comprare un token."),
    "inputSchema": {
        "type": "object",
        "properties": {
            "chain": {"type": "string",
                      "description": "solana | ethereum | bsc | base | arbitrum | polygon | optimism | avalanche"},
            "address": {"type": "string", "description": "mint Solana o address EVM (0x…) del token"},
        },
        "required": ["chain", "address"],
    },
}


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def result(id_, res):
    send({"jsonrpc": "2.0", "id": id_, "result": res})


def error(id_, code, message):
    send({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


def handle(msg):
    method = msg.get("method")
    id_ = msg.get("id")
    if id_ is None:  # notifica: nessuna risposta
        return
    if method == "initialize":
        result(id_, {"protocolVersion": PROTOCOL,
                     "capabilities": {"tools": {}},
                     "serverInfo": {"name": "guardbot", "version": "0.1"}})
    elif method == "ping":
        result(id_, {})
    elif method == "tools/list":
        result(id_, {"tools": [TOOL]})
    elif method == "tools/call":
        params = msg.get("params") or {}
        if params.get("name") != "check_token":
            return error(id_, -32602, f"tool sconosciuto: {params.get('name')}")
        args = params.get("arguments") or {}
        try:
            verdict = guard.assess(args.get("chain", ""), args.get("address", ""))
        except Exception as e:
            return result(id_, {"content": [{"type": "text", "text": f"errore: {e}"}], "isError": True})
        is_err = "error" in verdict
        result(id_, {"content": [{"type": "text", "text": json.dumps(verdict, ensure_ascii=False)}],
                     "isError": is_err})
    else:
        error(id_, -32601, f"metodo non gestito: {method}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            handle(msg)
        except Exception as e:
            if msg.get("id") is not None:
                error(msg["id"], -32603, f"internal: {e}")


if __name__ == "__main__":
    main()
