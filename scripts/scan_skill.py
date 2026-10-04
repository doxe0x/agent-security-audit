#!/usr/bin/env python3
"""Static, read-only scan of a skill, plugin, or MCP server folder before install.

    python3 scan_skill.py <folder> [--json]

Nothing in the scanned folder is executed or imported, and nothing is sent over
the network. Every hit is a lead to read in context, not a verdict: the reviewer
still reads each instruction file and script in full. Exit code 2 when a
high-severity lead is present, 0 otherwise.
"""
import json
import re
import sys
from pathlib import Path

TEXT_SUFFIXES = {".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
                 ".json", ".yaml", ".yml", ".toml", ".cmd", ".ps1", ".rb", ".go", ".rs", ".html", ""}
COMMENT_OPEN = "<" + "!--"
RULES = [
    # (id, severity, AST tag, description, regex)
    ("hidden-unicode", "high", "AST04", "zero-width, bidi, or Unicode tag characters",
     re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")),
    ("ai-directive", "high", "AST01", "text steering the agent away from the user",
     re.compile(r"(?i)((ignore|disregard) (all |any )?(the )?(previous|prior|above|earlier|other|system) (instructions|rules|directions|prompts?)|do not (tell|mention|inform|show) (this to )?the user|without (asking|telling|notifying) the user|keep this (secret|hidden) from)")),
    ("pipe-to-shell", "high", "AST02", "download piped into a shell",
     re.compile(r"(curl|wget)[^\n|]{0,200}\|\s*(ba|z)?sh\b")),
    ("secret-paths", "high", "AST03", "reads credential stores, wallets, or browser data",
     re.compile(r"(?i)(~/\.ssh|\.ssh/id_|~/\.aws|\.aws/credentials|~/\.gnupg|\.env\b|keychain|wallet\.dat|keystore|Local Extension Settings|Login Data|Cookies\.binarycookies)")),
    ("exfil-endpoints", "high", "AST01", "paste or webhook endpoints often used for exfiltration",
     re.compile(r"(?i)(discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|webhook\.site|ngrok\.(io|app))")),
    ("encoded-payload", "medium", "AST04", "long base64 blob",
     re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")),
    ("html-comment", "medium", "AST04", "HTML comment: invisible when rendered, read by the model",
     re.compile(re.escape(COMMENT_OPEN))),
    ("code-exec", "medium", "AST06", "process execution or dynamic code",
     re.compile(r"\b(subprocess\.|os\.system|os\.popen|exec\(|eval\(|shell\s*=\s*True|child_process|execSync|spawn\(|pickle\.loads|yaml\.load\()")),
    ("unpinned-launcher", "medium", "AST07", "package launched from a moving version",
     re.compile(r"(npx\s+(-y\s+)?[@\w./-]+@latest|\"[@\w./-]+@latest\"|uvx\s+[\w.-]+(\s|$)|pip install (?!-r)[\w-]+(\s|$)|npm (i|install) -g [\w@/.-]+(\s|$))")),
    ("network", "low", "AST05", "network access in code",
     re.compile(r"\b(requests\.(get|post|put)|urllib\.request|http\.client|httpx\.|aiohttp|fetch\(|axios\.|socket\.socket|WebSocket\()")),
    ("broad-allow", "high", "AST03", "broad tool pre-approval",
     re.compile(r"(?m)(^allowed-tools:.*\bBash\b(?!\()|\"Bash\((\*|[\w.-]+:\*)\)\"|Bash\(\*\))")),
]


def frontmatter(text: str) -> dict:
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def scan(root: Path) -> dict:
    report = {"root": str(root), "skills": [], "hooks": [], "mcp": [], "binaries": [],
              "symlinks": [], "urls": set(), "leads": []}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if ".git" in rel.parts:
            continue
        if p.is_symlink():
            target = p.resolve()
            inside = str(target).startswith(str(root.resolve()))
            report["symlinks"].append(f"{rel} -> {target}" + ("" if inside else "  (points outside the folder)"))
            continue
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            report["binaries"].append(f"{rel} ({p.stat().st_size} bytes)")
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            report["binaries"].append(f"{rel} (not UTF-8)")
            continue
        if p.name == "SKILL.md":
            fm = frontmatter(text)
            report["skills"].append({"file": str(rel), "name": fm.get("name"),
                                     "allowed-tools": fm.get("allowed-tools"),
                                     "model-invocable": fm.get("disable-model-invocation") != "true",
                                     "description_chars": len(fm.get("description", ""))})
        if p.name == "hooks.json" or (p.suffix == ".json" and "hooks" in rel.parts):
            try:
                data = json.loads(text)
                for event, entries in (data.get("hooks", data) or {}).items():
                    for e in entries if isinstance(entries, list) else []:
                        for h in e.get("hooks", []):
                            report["hooks"].append(f"{rel}: {event} [{e.get('matcher', '*')}] {h.get('type')}: {(h.get('command') or h.get('prompt') or '')[:140]}")
            except (json.JSONDecodeError, AttributeError):
                report["hooks"].append(f"{rel}: unparseable hooks file")
        if p.name in {".mcp.json", "mcp.json"} or (p.name == "plugin.json" and "mcpServers" in text):
            try:
                data = json.loads(text)
                servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
                for name, cfg in servers.items():
                    if not isinstance(cfg, dict) or not ({"command", "url"} & cfg.keys()):
                        continue
                    report["mcp"].append(f"{rel}: {name}: {cfg.get('command', '')} {' '.join(map(str, cfg.get('args', [])))} {cfg.get('url', '')}".strip())
            except json.JSONDecodeError:
                report["mcp"].append(f"{rel}: unparseable MCP config")
        for url in re.findall(r"https?://[^\s)\"'<>`]+", text):
            report["urls"].add(url.rstrip(".,;"))
        for lineno, line in enumerate(text.splitlines(), 1):
            for rid, sev, tag, desc, rx in RULES:
                if rx.search(line):
                    report["leads"].append({"severity": sev, "rule": rid, "ast": tag, "desc": desc,
                                            "where": f"{rel}:{lineno}", "line": line.strip()[:160]})
    report["urls"] = sorted(report["urls"])
    return report


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    root = Path(sys.argv[1]).expanduser()
    if not root.is_dir():
        print(f"not a folder: {root}")
        return 1
    r = scan(root)
    if "--json" in sys.argv:
        print(json.dumps(r, indent=1))
    else:
        print(f"# Static scan: {r['root']}\n")
        for title, key in [("Skills", "skills"), ("Hooks", "hooks"), ("MCP servers", "mcp"),
                           ("Binary or non-UTF-8 files", "binaries"), ("Symlinks", "symlinks"),
                           ("URLs referenced", "urls")]:
            items = r[key]
            print(f"## {title} ({len(items)})")
            for it in items[:60]:
                print(f"- {it}")
            if len(items) > 60:
                print(f"- ... {len(items) - 60} more")
            print()
        order = {"high": 0, "medium": 1, "low": 2}
        print(f"## Leads ({len(r['leads'])})")
        for ld in sorted(r["leads"], key=lambda x: (order[x["severity"]], x["where"]))[:200]:
            print(f"- [{ld['severity']}] {ld['rule']} ({ld['ast']}) {ld['where']}: {ld['line']}")
    return 2 if any(ld["severity"] == "high" for ld in r["leads"]) else 0


if __name__ == "__main__":
    sys.exit(main())
