#!/usr/bin/env python3
"""Read-only inventory of a Claude Code setup for a security review.

    python3 inventory.py [--no-transcripts]

Reports settings and permission rules, plugins with their hooks and MCP
launchers, configured MCP servers, installed skills and their provenance,
desktop extensions, and secrets sitting in local transcripts. Secret values are
never printed: only types, counts, distinct counts, and file locations. Nothing
is modified and nothing is sent over the network.
"""
import collections
import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
CLAUDE = HOME / ".claude"
SENSITIVE_KEY = re.compile(r"(?i)(key|token|secret|passw|auth|cookie|bearer|credential|private)")
SECRET_RULES = {
    "anthropic_api_key": r"sk-ant-[A-Za-z0-9_\-]{20,}",
    "openai_api_key": r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}",
    "openrouter_api_key": r"sk-or-v1-[a-f0-9]{40,}",
    "github_token": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}",
    "slack_token": r"xox[abpr]-[A-Za-z0-9-]{10,}",
    "aws_access_key_id": r"\bAKIA[0-9A-Z]{16}\b",
    "telegram_bot_token": r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b",
    "notion_token": r"\b(?:secret_[A-Za-z0-9]{40,}|ntn_[A-Za-z0-9]{40,})",
    "private_key_pem": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----(?:\\n|\s){1,4}[A-Za-z0-9+/=]{40}",
    "eth_private_key_in_context": r"(?i)(?:private[_ ]?key|privkey|PRIVATE_KEY)\W{0,10}(?:0x)?[a-f0-9]{64}\b",
}
PLACEHOLDER = re.compile(r"(?i)(x{4,}|0{8,}|\*{3,}|your|example|dummy|fake|placeholder|redact|sample)")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def masked(d: dict) -> str:
    return ", ".join(f"{k}=<{len(str(v))} chars>" if SENSITIVE_KEY.search(k) or len(str(v)) > 30 else f"{k}={v}"
                     for k, v in (d or {}).items())


def entropy(s: str) -> float:
    c = collections.Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0.0


def section(title: str):
    print(f"\n## {title}\n")


def settings():
    section("Settings and permission rules")
    for name in ["settings.json", "settings.local.json"]:
        d = load_json(CLAUDE / name)
        if d is None:
            continue
        perms = d.get("permissions", {}) or {}
        print(f"- `{name}`: allow={len(perms.get('allow', []))} ask={len(perms.get('ask', []))} deny={len(perms.get('deny', []))}"
              f" defaultMode={perms.get('defaultMode', 'default')} sandbox={'on' if (d.get('sandbox') or {}).get('enabled') else 'off'}"
              f" cleanupPeriodDays={d.get('cleanupPeriodDays', 'default')}")
        for kind in ["allow", "ask", "deny"]:
            for rule in perms.get(kind, []):
                flag = "  <- broad" if kind == "allow" and re.search(r"Bash\((\*|[\w.-]+:\*)\)|^Bash$|^mcp__[^_]+$", rule) else ""
                print(f"  - {kind}: `{rule}`{flag}")
        for event, entries in (d.get("hooks") or {}).items():
            for e in entries:
                for h in e.get("hooks", []):
                    print(f"  - hook {event} [{e.get('matcher', '*')}]: {(h.get('command') or '')[:120]}")
        if d.get("env"):
            print(f"  - env keys: {', '.join(d['env'].keys())}")
        for mname, m in (d.get("extraKnownMarketplaces") or {}).items():
            src = m.get("source", {})
            print(f"  - marketplace `{mname}`: {src.get('source')} {src.get('repo') or src.get('url')}")


def plugins():
    section("Plugins: hooks and MCP launchers")
    d = load_json(CLAUDE / "plugins" / "installed_plugins.json") or {}
    enabled = (load_json(CLAUDE / "settings.json") or {}).get("enabledPlugins", {})
    for name, entries in (d.get("plugins", d) or {}).items():
        for e in entries if isinstance(entries, list) else [entries]:
            path = Path(e.get("installPath", ""))
            state = "enabled" if enabled.get(name) else "disabled"
            print(f"- `{name}` v{e.get('version')} sha={(e.get('gitCommitSha') or 'none')[:10]} ({state})")
            for hf in list(path.rglob("hooks.json")) if path.exists() else []:
                hd = load_json(hf) or {}
                for event, arr in (hd.get("hooks", hd) or {}).items():
                    for m in arr if isinstance(arr, list) else []:
                        for h in m.get("hooks", []):
                            print(f"  - hook {event} [{m.get('matcher', '*')}]: {(h.get('command') or '')[:110]}")
            for mf in [path / ".mcp.json"] if (path / ".mcp.json").exists() else []:
                md = load_json(mf) or {}
                for sname, cfg in (md.get("mcpServers", md) or {}).items():
                    if isinstance(cfg, dict):
                        cmd = f"{cfg.get('command', '')} {' '.join(map(str, cfg.get('args', [])))} {cfg.get('url', '')}".strip()
                        flag = "  <- unpinned" if "@latest" in cmd else ""
                        print(f"  - MCP `{sname}`: {cmd}{flag}")


def mcp_servers():
    section("MCP servers in ~/.claude.json")
    d = load_json(HOME / ".claude.json") or {}

    def show(scope, servers):
        for name, cfg in (servers or {}).items():
            cmd = f"{cfg.get('command', '')} {' '.join(map(str, cfg.get('args', [])))}".strip()
            print(f"- [{scope}] `{name}`: {cfg.get('type', 'stdio')} {cmd} {cfg.get('url', '')}"
                  f" env[{masked(cfg.get('env'))}] headers[{masked(cfg.get('headers'))}]")
    show("user", d.get("mcpServers"))
    for proj, pc in (d.get("projects") or {}).items():
        show(f"project {Path(proj).name}", pc.get("mcpServers"))
    print("- Remote connectors added in the Claude app are not stored here: classify them from the session's tool list.")


def skills():
    section("Skills in ~/.claude/skills")
    root = CLAUDE / "skills"
    for d in sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []:
        prov = "copied, no provenance"
        if (d / ".git").exists():
            remote = subprocess.run(["git", "-C", str(d), "remote", "get-url", "origin"], capture_output=True, text=True).stdout.strip()
            head = subprocess.run(["git", "-C", str(d), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
            prov = f"git {remote} @ {head}"
        text = (d / "SKILL.md").read_text(encoding="utf-8", errors="ignore") if (d / "SKILL.md").exists() else ""
        tools = re.search(r"(?m)^allowed-tools:\s*(.+)$", text)
        code = [p.name for p in d.rglob("*") if p.suffix in {".py", ".sh", ".js", ".ts"} and ".git" not in p.parts]
        print(f"- `{d.name}`: {prov}; allowed-tools: {tools.group(1) if tools else 'none'}; code files: {len(code)}")


def desktop():
    base = HOME / "Library" / "Application Support" / "Claude"
    if not base.exists():
        return
    section("Claude desktop extensions")
    for s in sorted((base / "Claude Extensions Settings").glob("*.json")):
        d = load_json(s) or {}
        print(f"- `{s.stem}`: enabled={d.get('isEnabled')}")
    dc = load_json(HOME / ".claude-server-commander" / "config.json")
    if dc is not None:
        dirs = dc.get("allowedDirectories")
        print(f"- Desktop Commander: allowedDirectories={dirs or 'EMPTY = whole disk'}, blockedCommands={len(dc.get('blockedCommands') or [])}, telemetry={dc.get('telemetryEnabled')}")


def transcripts():
    section("Secrets in local transcripts (values never printed)")
    files = [p for p in (CLAUDE / "projects").rglob("*") if p.is_file()] + [CLAUDE / "history.jsonl"]
    files += [p for d in ["paste-cache", "file-history", "shell-snapshots"] for p in (CLAUDE / d).rglob("*") if p.is_file()]
    rules = {k: re.compile(v) for k, v in SECRET_RULES.items()}
    distinct = collections.defaultdict(set)
    where = collections.defaultdict(set)
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for k, rx in rules.items():
            for m in rx.finditer(text):
                v = m.group(0)
                if PLACEHOLDER.search(v) or entropy(v) < 3.0:
                    continue
                distinct[k].add(hashlib.sha256(v.encode()).hexdigest()[:12])
                where[k].add(str(p.relative_to(CLAUDE)).split("/")[1] if p.is_relative_to(CLAUDE / "projects") else p.name)
    if not distinct:
        print("- none found")
    for k in sorted(distinct, key=lambda x: -len(distinct[x])):
        print(f"- {k}: {len(distinct[k])} distinct value(s) in {len(where[k])} location(s): {', '.join(sorted(where[k])[:6])}")
    print("- Rotate every real credential listed here first; redacting transcripts only limits future exposure.")


def main() -> int:
    print("# Claude Code setup inventory")
    settings()
    plugins()
    mcp_servers()
    skills()
    desktop()
    if "--no-transcripts" not in sys.argv:
        transcripts()
    return 0


if __name__ == "__main__":
    sys.exit(main())
