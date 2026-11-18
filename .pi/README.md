# Pi project configuration

Start Pi from the Gekko repository root to load `.pi/settings.json`. This file
does not install configuration on another machine or apply to sessions launched
outside this checkout.

## Earlier compaction

`compaction.enabled` is deliberately NOT set here: a project value would override the
operator's global one and make Pi's `/settings` -> Auto-compact toggle a no-op. Pi's
default is enabled.

The project override in `settings.json` (`provider/<model-id>`; replace the id with
the model your endpoint serves) assumes a declared context window of 131072 tokens
and reserves 24904 tokens, so automatic compaction starts when context usage exceeds
106168 tokens (about 81%). The recent-message budget remains 20000 tokens. Model
output limits and server settings are unchanged. Project overrides take precedence
over global settings. Recalculate the reserve if the model's declared context window
changes.

This is a headroom mitigation, not a fix for unbounded summary growth. To request a
shorter checkpoint:

```text
/compact Limit the summary to 500 words. Keep current goals, scope restrictions, evidence paths, unresolved decisions and next steps. Remove obsolete history and completed items that are no longer needed.
```

The word limit is an instruction, not an enforced cap. If compaction keeps failing,
preserve the session and start a new one using the local worklog. Verify that
critical scope restrictions and pending work survive the handoff.
