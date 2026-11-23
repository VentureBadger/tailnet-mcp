# tailnet-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI assistant inspect a Tailscale tailnet: list and audit devices, read the access policy, and answer "who can reach this?" questions with Tailscale's own policy engine. It is read-only by default; changing devices is opt-in.

Written in Go with no dependencies outside the standard library.

## Tools

| Tool | What it does | Access |
|---|---|---|
| `list_devices` | Devices with addresses, owner, tags, OS, and connection state. Filters by name, tag, OS, connected, authorized. | read |
| `get_device` | Full detail for one device, including subnet routes and connectivity. | read |
| `audit_devices` | Unauthorized devices, node keys expiring or expired, devices not seen recently, clients with updates. | read |
| `get_policy` | The policy file as HuJSON, with its ETag. | read |
| `validate_policy` | Validates a proposed policy file and runs its tests without saving it. | read |
| `preview_access` | Which rules apply to a user or an IP:port, against the current policy or a proposed one. | read |
| `set_device_authorized` | Authorize or deauthorize a device. | write, opt-in |
| `set_device_tags` | Replace a device's tags. | write, opt-in |

`preview_access` with a proposed policy lets the assistant show the effect of an ACL change before anyone applies it. The server never writes the policy file.

## Install

```sh
go install github.com/VentureBadger/tailnet-mcp/cmd/tailnet-mcp@latest
```

## Configure

Credentials come from the environment only, so they never appear in process listings or client config arguments.

| Variable | |
|---|---|
| `TAILSCALE_OAUTH_CLIENT_ID`, `TAILSCALE_OAUTH_CLIENT_SECRET` | An OAuth client (recommended). Tokens are fetched, cached, refreshed a minute before expiry, and refreshed again if the API rejects one. |
| `TAILSCALE_OAUTH_SCOPES` | Optional, space separated. Requests a narrower token than the client allows. |
| `TAILSCALE_API_KEY` | An API access token, as an alternative to OAuth. |
| `TAILSCALE_TAILNET` | Tailnet ID. Defaults to `-`, the credential's own tailnet. |
| `TAILNET_MCP_ALLOW_WRITES` | `true` to expose the write tools. Same as `-allow-writes`. |
| `TAILNET_MCP_LOG_LEVEL` | `debug`, `info` (default), `warn`, `error`. Logs are JSON on stderr. |

Scopes needed:

| Use | OAuth scopes |
|---|---|
| Read-only tools | `devices:core:read`, `policy_file:read` |
| With `-allow-writes` | `devices:core`, `policy_file:read` (Tailscale requires tags on a `devices:core` client) |

### Claude Code

```sh
claude mcp add tailnet \
  -e TAILSCALE_OAUTH_CLIENT_ID=... \
  -e TAILSCALE_OAUTH_CLIENT_SECRET=... \
  -- tailnet-mcp
```

### Claude Desktop and other clients

```json
{
  "mcpServers": {
    "tailnet": {
      "command": "tailnet-mcp",
      "env": {
        "TAILSCALE_OAUTH_CLIENT_ID": "...",
        "TAILSCALE_OAUTH_CLIENT_SECRET": "..."
      }
    }
  }
}
```

## Example prompts

- "Which devices haven't checked in for a month, and whose keys expire this week?"
- "Who can SSH to 100.101.102.103?"
- "If I remove group:contractors from the second ACL rule, what can alice@example.com still reach? Validate it first."

## Design

- **Read-only unless asked.** Write tools are not registered at all without `-allow-writes`, and they carry `destructiveHint` so clients ask for confirmation.
- **Errors the model can act on.** API and argument errors come back as tool results with `isError`, not protocol failures, so the assistant can correct itself. Unknown arguments are rejected rather than silently ignored.
- **Resilient HTTP.** Retries on 429 and 5xx with capped exponential backoff and jitter, honoring `Retry-After`. Responses are size-limited, every request carries the caller's context, and cancelling a tool call (`notifications/cancelled`) stops its in-flight requests.
- **Protocol.** JSON-RPC 2.0 over stdio, protocol versions 2025-06-18, 2025-03-26, and 2024-11-05. Requests run concurrently; replies are serialized on stdout.

```
cmd/tailnet-mcp      flags, environment, wiring, signal handling
internal/mcp         MCP server: framing, dispatch, cancellation, tool results
internal/tailscale   Tailscale API client: auth, retries, devices, policy
internal/tools       tool definitions, argument validation, audit logic
```

## Development

```sh
make check   # gofmt, go vet, staticcheck, tests with the race detector
make build
```

## License

MIT
