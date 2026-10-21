# spec-graph launchd agent

A user LaunchAgent template that runs `spec-graph mcp` as a Streamable HTTP
MCP server on `127.0.0.1:8765` (per the `listen_address` field in
`spec-graph.config.json`). Auto-restarts on crash and at login.

## Install

```bash
cp bootstrap/launchctl/com.velenza.spec-graph.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.velenza.spec-graph.plist
launchctl print gui/$UID/com.velenza.spec-graph | grep -E "state|last exit"
```

## Hot-reload workflow after a code change

```bash
cd /opt/velenza/velenza-canon
go build -o bin/spec-graph .
launchctl kickstart -k gui/$UID/com.velenza.spec-graph
```

Claude Code reconnects on the next MCP call — no Claude Code restart needed.

## Logs

- `~/Library/Logs/spec-graph.out.log` (stdout)
- `~/Library/Logs/spec-graph.err.log` (stderr — includes the `listening on
  127.0.0.1:8765` banner)

## Uninstall

```bash
launchctl bootout gui/$UID/com.velenza.spec-graph
rm ~/Library/LaunchAgents/com.velenza.spec-graph.plist
```

## Claude Code MCP entry (~/.claude.json)

Replace the stdio `command`/`args` block with:

```json
"spec-graph": {
  "type": "http",
  "url": "http://127.0.0.1:8765/"
}
```

Restart Claude Code once to pick up the new MCP entry shape.
