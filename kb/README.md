# Knowledge base (sample)

This is a small sample of the knowledge base: four short, generic entries that
show the format. It is not a complete reference. Operators bring their own
entries, written from their own work, and sanitised of any target data.

Entries are written for agents to consume: terse, command-first, placeholders
instead of real hosts or credentials. Start from `_template.md`.

## Categories
- `tools/` — one file per tool or toolset (flags, invocation, gotchas)
- `techniques/` — one file per attack technique
- `payloads/` — reusable payloads and snippets, by theme
- `platforms/` — sanitised per-product patterns (auth mechanism, version quirks)

## Index

| Entry | Category | Summary |
|---|---|---|
| [service-enumeration](tools/service-enumeration.md) | tools | Per-service recon commands after a port scan |
| [sql-injection](techniques/sql-injection.md) | techniques | Detect and confirm SQLi by hand, then with sqlmap |
| [kerberoasting](techniques/kerberoasting.md) | techniques | Request service tickets and crack them offline |
| [prompt-injection](techniques/prompt-injection.md) | techniques | Direct and indirect prompt injection against LLM apps |

## Adding an entry
1. Copy `_template.md` into the right category folder, with a kebab-case slug.
2. Fill the frontmatter (`category`, `updated`, `summary`).
3. Add a row to the index above.
4. Put no real hosts, IPs, credentials or client names in it.
