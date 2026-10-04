# Memory-safety hunting pipeline — static stages

Methodology only. **No vulnerability details, proof-of-concept inputs, or patches are included here**, by
design: see `.gitignore`. The findings this pipeline produced are unreported and unpatched upstream at the time
of writing, so they are deliberately kept out of version control.

* `ARCHITECTURE.md` — the pipeline, with measured precision for each stage and the triage gates.
* `scanners/` — three C memory-safety shape scanners. Read §2 of ARCHITECTURE.md first: two of the three are
  measured as **not worth running broadly**, and that negative result is the point.
* `catalog/` — the gated target lists (297 single-file libraries → 62 format parsers).

The one-line summary: **static analysis earned its keep selecting *targets*, not detecting *sites*.**
Target gating ran at ~100% precision (2 survivors from 297, both yielding findings); shape scanning ran under
2% (60 hits, one already-known bug).
