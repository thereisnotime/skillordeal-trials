# r00-aborted

First attempt at r01, stopped by hand on 2026-09-23 after 13 of 72 bouts. Kept for the record; **not scored and not part of any result**.

Why it was stopped: engine v0.1.1 collected findings through the CLI's structured output. With long, nested reports Opus sometimes wrote the `findings` array as XML inside the `summary` string, so structured output rejected it. One bout ended in `structured_output_retry_exhausted`, another "passed" with a throwaway `{"summary": "test", "findings": []}` it sent while debugging the tool. Both would have counted against the skills unfairly.

Engine v0.1.2 has the agent write `/out/findings.json` instead and validates it itself. r01 was re-locked and re-run from scratch on v0.1.2.

The bout `b-54c1f22883c60d3e` record was hand-edited from `error` to `schema_violation` before the root cause was known (see its `reclassified` field); that classification was wrong, the cause was the harness.
