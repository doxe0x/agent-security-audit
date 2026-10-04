# Candidate checklist

Condensed from the OWASP Agentic Skills Top 10 (v1.0, 2026) for a personal setup. Each item is pass, fail, or not applicable, with evidence. The full checklist lives at https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/checklist.md.

## AST01 Malicious Skills (Critical)

- Source is the real publisher, not a look-alike name; the repo has history beyond a single dump commit.
- Every instruction file and script read in full: no encoded payloads, no fetches to unknown hosts, no credential access beyond the stated purpose, no text telling the agent to hide actions from the user.
- No writes to agent identity or memory files (`CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, `~/.claude/settings.json`) unless that is the declared purpose.

## AST02 Supply Chain Compromise (Critical)

- Pinned to an immutable reference: commit SHA or SHA-256 of the archive, not a branch or `@latest`.
- Nested dependencies locked (`requirements.txt` with versions, lockfiles); installs happen after review.
- Repo configuration treated as executable code: `.claude/settings.json` hooks and `env` overrides, `.mcp.json` servers. Claude Code CVE-2025-59536 (CVSS 8.7) ran a project hook before the trust dialog; CVE-2026-21852 leaked API keys through a project base-URL override.

## AST03 Over-Privileged Skills (High)

- `allowed-tools` absent or scoped to specific commands; `Bash` without a pattern or `Bash(x:*)` for an interpreter is a fail.
- File access limited to what the purpose needs; no reads of `~/.ssh`, `~/.aws`, `.env`, wallets, keychains, or browser profiles.
- Network access limited to named domains.
- Credentials scoped per tool: read-only exchange keys, fine-grained tokens on named repos, short expiry.

## AST04 Insecure Metadata (High)

- Description matches observed behaviour; no hidden capability.
- No zero-width, bidi, or Unicode tag characters, HTML comments carrying instructions, or base64 blobs in `SKILL.md` and manifests (`scripts/scan_skill.py` flags them).
- YAML parsed with safe loaders; no brand impersonation.

## AST05 Untrusted External Instructions (High)

- Inventory every URL the skill reads at runtime. Prefer inlined, reviewed copies; a runtime fetch from a mutable page is a fail unless pinned to a hash.
- Follow references transitively: a pinned page that links to a live script is still live.

## AST06 Weak Isolation (High)

- Scripts run in a sandbox or with the minimum filesystem and network scope.
- No workspace precedence trap: the skill resolves its own scripts from its install folder, not from the current project.
- Local control interfaces (MCP over HTTP, WebSocket) bound to localhost with auth.

## AST07 Update Drift (Medium)

- Updates arrive as diffs you read before accepting; auto-update off or gated.
- Plugins with hooks get re-reviewed on every version bump.

## AST08 Poor Scanning (Medium)

- Both layers reviewed: code and natural-language instructions.
- A scanner verdict is advisory; scanners are evaded by moving payloads into prose, splitting them across skills, or hiding them in images.
- Credential scan run on the candidate itself.

## AST09 No Governance (Medium)

- Installed skills recorded with source, commit, date, and reviewer.
- Review cadence set; removal path known.

## AST10 Cross-Platform Reuse (Medium)

- A skill written for another agent (Copilot CLI, Amp, OpenClaw, Codex) re-checked for this platform's permission model; security properties do not survive porting automatically.

## OWASP Top 10 for Agentic Applications 2026 mapping

| ASI | Risk | Where it shows up in a setup |
|---|---|---|
| ASI01 | Agent Goal Hijack | instructions inside web pages, posts, issues, tool output, skill text |
| ASI02 | Tool Misuse | an outbound or destructive tool reachable from an injected instruction |
| ASI03 | Identity & Privilege Abuse | broad tokens, full-disk tools, exchange keys with trade rights |
| ASI04 | Agentic Supply Chain | skills, plugins, MCP servers, `@latest` launchers |
| ASI05 | Unexpected Code Execution | hooks, project config, install scripts, scripts inside skills |
| ASI06 | Memory & Context Poisoning | `CLAUDE.md`, memory files, SessionStart hooks injecting context |
| ASI07 | Insecure Inter-Agent Communication | subagents and channels passing unvalidated content |
| ASI08 | Cascading Failures | one poisoned skill or memory reused by every later session |
| ASI09 | Human-Agent Trust Exploitation | approval fatigue, convincing summaries hiding an action |
| ASI10 | Rogue Agents | agents acting beyond the task, persisting or spreading |

## Claude Code specifics

- Plugin hooks run shell commands on events; a `SessionStart` hook that prints text injects it into every session's context.
- `.mcp.json` servers launched with `npx pkg@latest` execute whatever version is current at each start.
- Permission rules gate Claude Code's own tools. A desktop extension or MCP server that executes processes (for example Desktop Commander's `start_process`) sits outside the `Bash(...)` rules unless its tools are also gated.
