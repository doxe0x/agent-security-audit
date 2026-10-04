# Hardening templates

Tighten-only changes. Each one lists what it costs so the user can choose.

## Permission rules

Rules live in `~/.claude/settings.json` under `permissions`. `deny` blocks a tool, `ask` forces a confirmation prompt even in auto mode. MCP tools are addressed as `mcp__<server>__<tool>`; copy exact names from the session's tool list.

```json
{
  "permissions": {
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.gnupg/**)",
      "Read(~/Library/Keychains/**)",
      "mcp__<exchange-server>__createOrder"
    ],
    "ask": [
      "Bash(git push:*)",
      "Bash(gh repo create:*)",
      "Bash(gh repo edit:*)",
      "mcp__<drive-server>__share_file"
    ]
  }
}
```

- **Deny** what an injected instruction must never reach: trading and withdrawals, credential stores, tools that rewrite their own guardrails.
- **Ask** for outbound or destructive actions the user still performs sometimes: publishing, sharing, deleting, merging.
- Cost: one confirmation per gated action. Gate rare, high-impact actions only; approval fatigue turns every prompt into a reflex click.
- `Read(...)` rules gate the Read tool, not a shell `cat`; they are one layer of several.

## Rule of Two session split

A session may hold at most two of: private data, untrusted content, an outbound channel. Practical split:

- Research sessions (web, social feeds, unknown repos) run without private connectors (finance, drive, notes) and without publishing tools.
- Private-data sessions (finance, notes, repos) avoid browsing untrusted pages and reading unknown repos.
- When a task needs all three, a human approves each outbound action.

## Sandboxing

Claude Code's sandbox (`/sandbox`) isolates Bash with filesystem and network limits. Cost: commands that need the network or paths outside the project need explicit allowances. Use it for unknown repos and third-party scripts.

## Plugins, MCP servers, connectors

- Disable what the user does not use; every enabled plugin hook and connector is standing attack surface.
- Pin launchers: replace `npx pkg@latest` with an exact version in your own MCP config.
- Read a plugin's diff before updating it, hooks first.

## Transcript hygiene

- Credentials stay out of chat: load them from the environment or a file the agent never prints; check auth with `gh auth status` rather than commands that print tokens.
- `cleanupPeriodDays` in settings sets how long transcripts are kept locally (default 30).
- After a leak: rotate first, then redact transcripts with the user's consent.

## Credential scoping

- Exchange API keys for agents: read-only, no trading, no withdrawals, IP-restricted.
- GitHub: fine-grained tokens on named repositories with expiry; avoid classic tokens with `repo` scope for automation.
- One credential per tool, so revoking one does not break the rest.
