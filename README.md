# bunny-mcp

An MCP server for debugging bunny.net CDN sites and managing bunny Shield, the bunny.net web application firewall (WAF).

This is an unofficial project. It is not affiliated with or endorsed by bunny.net.

It covers pull zones (CDN sites), edge rules, cache purges, CDN statistics, origin error logs, and Shield: WAF settings, custom WAF rules, rate limits, bot detection and WAF event logs. It does not cover DNS, storage, Stream or edge scripts. For those, see [anvme/bunnycdn-mcp](https://github.com/anvme/bunnycdn-mcp) or [Digitizers/bunny-mcp](https://github.com/Digitizers/bunny-mcp).

## What it does differently

- **Explains what rules will really do.** `get_shield_zone` returns `notes` that warn, for example, when Block rules only log because the zone's WAF execution mode is Log.
- **Reads WAF event logs.** `shield_event_logs` shows what the WAF blocked, challenged or logged in the last 72 hours, grouped by rule, IP, JA4 fingerprint and more.
- **Reports what changed.** Update tools return a before-and-after diff. `update_pull_zone` also lists settings bunny.net changed that you did not ask for.
- **Keeps responses small.** Pull zones, edge rules, origin errors and event logs are summarised. Pass `detail: true` for the raw response.
- **Hides credentials.** Token authentication keys, AWS signing keys, TLS certificates and private keys, log forwarding tokens, and cookie or `Authorization` values in edge rule triggers are replaced with `<hidden>`, also in raw responses.

## Requirements

- Node.js 20 or later
- A bunny.net account API key, from **Account settings > API key** in the bunny.net dashboard. This key gives full access to the account.

## Install

Claude Code:

```sh
claude mcp add bunny --env BUNNY_API_KEY=your-key -- npx -y @fullfatthings/bunny-mcp
```

Other MCP clients (for example Claude Desktop):

```json
{
  "mcpServers": {
    "bunny": {
      "command": "npx",
      "args": ["-y", "@fullfatthings/bunny-mcp"],
      "env": { "BUNNY_API_KEY": "your-key" }
    }
  }
}
```

## Configuration

| Variable | Meaning |
|---|---|
| `BUNNY_API_KEY` | Required. Your bunny.net account API key. |
| `BUNNY_READONLY` | Set to `1` to register only the read tools. Write tools are then absent from the tool list, so the assistant cannot call them. |

## Tools

Read tools:

| Tool | Purpose |
|---|---|
| `list_pull_zones` | List pull zones with IDs, origins and hostnames. |
| `get_pull_zone` | One pull zone: hostnames, readable edge rules, and caching, origin and security settings. |
| `cdn_statistics` | Bandwidth, requests, cache hit rate and error responses. |
| `origin_errors` | Failed requests from bunny.net to your origin on one day, with counts by error. |
| `get_shield_zone` | WAF settings, custom rules, rate limits and bot detection, with `notes`. |
| `shield_event_logs` | Requests the WAF blocked, challenged or logged in the last 72 hours. |

Write tools (not registered when `BUNNY_READONLY=1`):

| Tool | Purpose |
|---|---|
| `update_pull_zone` | Change pull zone settings. |
| `purge_cache` | Purge one URL or a whole pull zone. |
| `save_edge_rule` | Create or update an edge rule. |
| `set_edge_rule_enabled` | Switch an edge rule on or off. |
| `delete_edge_rule` | Delete an edge rule. |
| `update_shield_zone` | Change WAF settings, including adding or removing single rule IDs from lists. |
| `update_bot_detection` | Change bot detection mode and sensitivity. |
| `save_waf_rule` | Create or update a custom WAF rule. |
| `save_rate_limit` | Create or update a rate limit. |
| `delete_shield_rule` | Delete a custom WAF rule or rate limit. |

To test a new WAF rule safely, save it with action Log, check `shield_event_logs`, then save it again with action Block.

## Development

```sh
npm install
npm test
```

## Licence

MIT. See [LICENSE](LICENSE).
