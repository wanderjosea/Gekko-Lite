---
title: <Short title>
slug: <kebab-case-slug>
category: <tools | techniques | payloads | platforms>
updated: <YYYY-MM-DD or "unknown">
summary: "<one terse line — this is the index purpose>"
tags: [<tag>, <tag>]
sensitive: false   # set true if it contains creds/tokens (tag values may rotate)
---

<!-- Keep it terse and command-first. Delete any section below that doesn't apply. -->

# <Title>

## When to use
<1–3 lines: the exact situation where this entry is the answer.>
<Preconditions, if any: what must already be true or held for this to work
(creds, open port, foothold, specific version).>

## Key facts / commands
<Command-first. Tables and short bullets. Real, copy-pasteable commands with
placeholders (TARGET, DOMAIN, USER, PASS) instead of real values.>

```bash
# example command with the flags that actually matter
```

## Gotchas
- <non-obvious thing that wastes time if you don't know it>
- <error-vs-success oracle, size deltas, required headers, etc.>

## Cleanup / rollback   <!-- only if the technique mutates target state -->
- <what artifact or change it leaves behind, and the exact command to undo it>
- <what to note in the report so the change is auditable and reversible>

## References
- Related: [[slug-a]], [[slug-b]]   # 2–5 entries genuinely related
- <source path / URL / module>
