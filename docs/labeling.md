# Label findings

[Back to README](../README.md)

Ground truth can't settle everything: warpgate-operator has none yet, and dvpwa's is not exhaustive. Humans fill the gap.

```bash
just score  trial=2026-09-secure-coding-audit round=r01   # ground-truth matches first
just review trial=2026-09-secure-coding-audit round=r01   # prints a local URL for the review UI
```

The UI shows one finding at a time with its code excerpt, the ground-truth match and the judge's verdict, and hides which contender wrote it. Pick `tp`, `fp`, `dup` or `unsure` (keys `t`, `f`, `d`, `u`), optionally link a ground-truth issue and add a note. Every verdict appends one line to `trials/<trial>/labels/labels.jsonl`:

```json
{"finding_hash": "…", "finding_id": "b-…:3", "arena": "dvpwa", "verdict": "tp",
 "issue_id": "dvpwa-sqli-student-create", "labeler": "human:<you>", "ts": "…", "note": ""}
```

- Later lines override earlier ones for the same `finding_hash` and `labeler`, so fixing a label is just labeling again.
- Labels are keyed by `finding_hash`, so they carry over to any round where the same finding shows up.
- A `tp` with no `issue_id` is a candidate for promotion into ground truth by hand: add it to the arena's `groundtruth.yaml` with `source: human-label`.
- Commit `labels.jsonl` and re-run `just report …` to update the results.
