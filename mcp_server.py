#!/usr/bin/env python3
"""GuardBot MCP server (stdio) — the tools an agent should call before it acts.

An agent (Claude, VibeKit, …) mounts this server and asks two things: is this token a trap
(check_token), and what has this wallet already handed out (check_approvals). No dependencies:
newline-delimited JSON-RPC 2.0 over stdin/stdout, per the MCP stdio transport.

check_token runs OUR engine (tokencheck): it simulates buying and selling the token against
live liquidity rather than asking a vendor's API what it thinks. On chains that engine does
not cover it falls back to guard.assess() (RugCheck/GoPlus) and says so, instead of pretending.
"""

import json
import sys

import guard
import tokencheck
import approvals as approvals_mod

PROTOCOL = "2024-11-05"
TOOLS = [
    {
        "name": "check_token",
        "description": ("Pre-trade safety check. Simulates actually BUYING the token and "
                        "SELLING it back against live liquidity, so a honeypot, a punitive "
                        "tax or an empty pool is demonstrated rather than guessed. Also "
                        "checks whether the contract is impersonating a bigger token's "
                        "ticker. Returns safe/warn/block with the evidence. Call BEFORE "
                        "buying."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string",
                          "description": "bsc | ethereum | base | arbitrum | polygon "
                                         "(simulated); solana falls back to RugCheck"},
                "address": {"type": "string", "description": "token contract address (0x…) "
                                                             "or Solana mint"},
            },
            "required": ["chain", "address"],
        },
    },
    {
        "name": "check_approvals",
        "description": ("What has this wallet already handed out? Lists standing approvals "
                        "across EVM chains, TRON and Solana — ERC-20 allowances, NFT operator "
                        "approvals (ApprovalForAll) and grants held inside Permit2 — each with "
                        "a graded risk level. Read-only."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",
                            "description": "wallet address: EVM 0x…, TRON T…, or Solana base58"},
            },
            "required": ["address"],
        },
    },
]


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
    if id_ is None:  # notification: no response
        return
    if method == "initialize":
        result(id_, {"protocolVersion": PROTOCOL,
                     "capabilities": {"tools": {}},
                     "serverInfo": {"name": "guardbot", "version": "0.1"}})
    elif method == "ping":
        result(id_, {})
    elif method == "tools/list":
        result(id_, {"tools": TOOLS})
    elif method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in {t["name"] for t in TOOLS}:
            return error(id_, -32602, f"unknown tool: {name}")
        try:
            if name == "check_approvals":
                verdict = approvals_mod.approvals(args.get("address", ""))
            else:
                chain = (args.get("chain") or "").lower()
                if chain in tokencheck.RPCS:
                    verdict = tokencheck.check_token(chain, args.get("address", ""))
                else:
                    # our simulator has no venue on this chain — say which engine answered
                    verdict = guard.assess(chain, args.get("address", ""))
                    verdict["engine"] = "guard/third-party (chain not simulated by tokencheck)"
        except Exception as e:
            return result(id_, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
        is_err = "error" in verdict
        result(id_, {"content": [{"type": "text", "text": json.dumps(verdict, ensure_ascii=False)}],
                     "isError": is_err})
    else:
        error(id_, -32601, f"unhandled method: {method}")


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
