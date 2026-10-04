# Hardening templates

Tighten-only changes. Each one lists what it costs so the user can choose.

## Permission rules

Rules live in `~/.claude/settings.json` under `permissions` and are evaluated deny, then ask, then allow; the first match wins. `deny` blocks a call. `ask` forces a confirmation prompt, in auto mode too, where it takes the decision away from the classifier.

```json
{
  "permissions": {
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.gnupg/**)",
      "Read(~/Library/Keychains/**)",
      "Bash(gh auth token *)",
      "Bash(security find-generic-password *)",
      "mcp__*__createOrder"
    ],
    "ask": [
      "Bash(git push *)",
      "Bash(git * push *)",
      "Bash(gh repo create *)",
      "Bash(gh repo edit *)",
      "Read(//**/.env)",
      "Edit(~/Library/LaunchAgents/**)",
      "mcp__*__share_file"
    ]
  }
}
```

- **Deny** what an injected instruction must never reach: trading and withdrawals, credential stores, commands that print tokens, tools that rewrite their own guardrails.
- **Ask** for outbound or destructive actions the user still performs sometimes: publishing, sharing, deleting, merging, and persistence points (shell rc files, LaunchAgents, global git config, git remotes).
- Cost: one confirmation per gated action. Gate rare, high-impact actions only; approval fatigue turns every prompt into a reflex click.

Syntax that decides whether a rule fires:

- MCP tools are `mcp__<server>__<tool>`, and the server segment differs by surface: the desktop app can list a connector under an id, the CLI as `mcp__claude_ai_<Name>`. Deny and ask rules accept globs in the tool name, so `mcp__*__createOrder` covers every surface. MCP rules take no parentheses; Claude Code skips a rule that has them.
- Path rules: `~/path` is home-relative, `//path` is absolute, and `/path` in user settings means `~/.claude/path`. `Read(//**/.env)` matches every `.env` on disk.
- `Read` and `Edit` rules also cover the shell file commands Claude Code recognizes (`cat`, `head`, `tail`, `sed`, `tee`, redirections), but not `grep -r` or a script that opens files itself. A `Read` deny also blocks edits to that path.
- A Bash rule matches the command as written, after compound commands are split at `&&`, `;`, `|`. `Bash(git push *)` misses `git -C dir push`, hence the second rule; a bare `Bash(sh)` ask catches `curl ... | sh`. Text rules are one layer; the sandbox is the boundary.
- Writes to protected files (`.zshrc`, `.gitconfig`, `.claude/`) go to the classifier in auto mode; an explicit `Edit(...)` ask turns that into a prompt.
- Verify after editing: an unknown tool name or a skipped rule shows up as a startup warning and in `claude doctor`.

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
- A desktop extension or MCP server with its own file and process tools (Desktop Commander) bypasses `Read`, `Edit` and `Bash` rules; gate its tools by name and narrow its own allowed directories.

## Transcript hygiene

- Credentials stay out of chat: load them from the environment or a file the agent never prints; check auth with `gh auth status` rather than commands that print tokens.
- `cleanupPeriodDays` sets how long CLI transcripts are kept (default 30). Sessions the desktop app created are exempt from that sweep until `desktopSessionCleanupPeriodDays` is set, so they stay on disk indefinitely. Either setting deletes old transcripts, so it is the user's decision.
- After a leak: rotate first, then redact transcripts with the user's consent.

## Credential scoping

- Exchange API keys for agents: read-only, no trading, no withdrawals, IP-restricted.
- GitHub: fine-grained tokens on named repositories with expiry; avoid classic tokens with `repo` scope for automation.
- One credential per tool, so revoking one does not break the rest.
