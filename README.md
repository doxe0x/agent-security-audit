# agent-security-audit

A Claude skill that reviews agent tooling the way you would review a dependency: before a skill, plugin, MCP server, or hook lands, and periodically for the whole Claude Code setup.

It grew out of a real audit of a personal setup, which found live bot tokens and API credentials sitting in local transcripts, an exchange trading tool reachable by the agent, a full-disk process tool outside Claude Code's permission rules, and an MCP server launched from `npx ...@latest`.

## Modes

- **PRE-INSTALL**: fetch the candidate inert, scan it, read every instruction file and script, walk the OWASP Agentic Skills Top 10, give a verdict and record provenance.
- **SETUP AUDIT**: inventory settings, plugins, hooks, MCP servers, connectors, skills, and secrets in transcripts; map the lethal trifecta; propose tighten-only permission rules.
- **INCIDENT**: contain, scope, rotate, clean.

## Contents

- `SKILL.md`: the skill.
- `references/checklist.md`: AST01-AST10 checks for personal setups, OWASP agentic (ASI) mapping, Claude Code specifics.
- `references/hardening.md`: permission rule templates, Rule of Two session split, sandboxing, transcript hygiene, credential scoping.
- `scripts/scan_skill.py`: static scan of a candidate folder (hidden text, AI-directed instructions, pipe-to-shell, secret paths, exfiltration endpoints, code execution, unpinned launchers, broad pre-approvals, hooks, MCP servers, URLs).
- `scripts/inventory.py`: read-only inventory of a Claude Code setup with masked secrets.
- `scripts/build_bundle.py`, `SHA256SUMS`, `agent-security-audit.skill`: deterministic bundle and its checksum.

## Install (Claude Code)

```bash
git clone https://github.com/doxe0x/agent-security-audit.git ~/.claude/skills/agent-security-audit
git -C ~/.claude/skills/agent-security-audit checkout <commit-you-reviewed>
```

Start a new session and check `/skills`. Requests like "is this skill safe to install", "review this MCP server", or "audit my Claude Code setup" trigger it.

## Is it safe to run

Both scripts use the Python standard library only, read files without modifying them, make no network calls, and never execute or import the folder they scan. `inventory.py` prints secret types, counts, and locations, never values. The skill changes your settings only after you agree, and only to tighten them.

`python3 scripts/build_bundle.py --check` verifies that the bundle matches the sources and that no hidden text slipped into them; CI runs it on every push and PR. See `SECURITY.md`.

## License

MIT. See `LICENSE`.
