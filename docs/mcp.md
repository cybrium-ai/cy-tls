# Using cy-tls as a Model Context Protocol server

`cy-tls mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server over stdio. AI agents that speak MCP (Claude Desktop, Cline,
Continue, Cursor, and others) can invoke cy-tls as a tool — a user can
ask the agent "scan cybrium.ai and example.com for SSL issues" and the
agent will run the scan, parse the findings, and synthesise a response.

## Quick smoke

```sh
# Manually drive the server — paste these JSON-RPC lines into stdin
(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
 echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
 sleep 1) | cy-tls mcp
```

You should see two responses on stdout — the initialize payload and
the tools list. If you get JSON back, your environment is MCP-ready.

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cy-tls": {
      "command": "/opt/homebrew/bin/cy-tls",
      "args": ["mcp"]
    }
  }
}
```

Adjust the `command` path for your install:

| Install method | Path |
|----------------|------|
| Homebrew on Apple Silicon | `/opt/homebrew/bin/cy-tls` |
| Homebrew on Intel macOS  | `/usr/local/bin/cy-tls` |
| Linux                    | `/usr/local/bin/cy-tls` or `~/.local/bin/cy-tls` |
| Scoop on Windows         | `%LOCALAPPDATA%\scoop\shims\cy-tls.exe` |
| `cargo install`          | `~/.cargo/bin/cy-tls` |

Restart Claude Desktop. The `cy_tls_scan` tool will appear in the tool
picker.

## Cline / Continue / Cursor

These IDEs read MCP config from their own settings. The shape is
identical to the Claude Desktop JSON — the server spec is just:

```json
{
  "command": "cy-tls",
  "args": ["mcp"]
}
```

## What the agent can do

The MCP server advertises one tool:

| Tool | Input | Returns |
|------|-------|---------|
| `cy_tls_scan` | `targets: string[]`, optional `timeout_seconds: int`, optional `no_cipher_enum: bool` | Pretty-printed JSON array of scan reports as a `text` content block |

Example prompts that work well:

> "Use cy-tls to scan cybrium.ai, then summarise the critical and
> high-severity findings."

> "Run cy-tls against example.com and chase.com. Compare their TLS
> posture and tell me which one is more locked down."

> "Scan my entire blog's domain list (one per line below) with
> cy-tls and produce a report of every cert that expires in the
> next 60 days."

The agent receives the full JSON output and decides how to render it
to you — no parsing required on your end.

## Wire protocol

JSON-RPC 2.0, line-delimited, on stdin / stdout. Supported methods:

| Method | Notes |
|--------|-------|
| `initialize` | Handshake; returns `protocolVersion`, `capabilities.tools`, `serverInfo` |
| `notifications/initialized` | Notification (no response); MCP convention |
| `ping` | Health check; returns `{}` |
| `tools/list` | Advertises `cy_tls_scan` and its JSON schema |
| `tools/call` | Invokes `cy_tls_scan`; returns content array with the scan JSON as text |

The protocol version is `2024-11-05`. Logging goes to stderr so it
doesn't poison the JSON-RPC channel.

## Security

cy-tls is a network scanner. When run as an MCP tool, an AI agent
could theoretically scan any internet-reachable host. **Don't add
cy-tls to MCP configs you wouldn't trust to make arbitrary outbound
TLS connections from your machine.**

cy-tls never performs intrusive probes — no exploitation, no
ROBOT/DROWN aggressive probes in v0.2.x — but it does open TLS
connections to whatever targets you (or the agent) names. The standard
rule applies: only enable MCP tools you understand and trust.

## What's next

- SSE transport (`cy-tls mcp --transport sse --port N`) — v0.2.5+
- Stream tool results progressively while a long scan is running
- Expose `cy_tls_verify_preload` and `cy_tls_bulk` as separate tools
- Auth via bearer token for shared / multi-tenant deployments
