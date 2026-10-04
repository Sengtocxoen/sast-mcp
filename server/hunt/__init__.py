"""
hunt/ - first-party tooling for the memory-safety hunt pipeline.

Every other package in this server wraps somebody else's scanner: build an
opengrep command line, parse its JSON, hand it back. These modules are different
in kind - the analysis is here, in this repo, as code. That is deliberate, and
docs/hunt-pipeline/ARCHITECTURE.md is why: the measured result of the
OSS-Hunt-2026-09-30 campaign was that static analysis earned its keep selecting
*targets* (~100% precision) and almost completely failed at detecting *sites*
(<2%). No off-the-shelf scanner answers "which library should I attack", so that
tool has to be built.

    ghclient    pooled, cached, rate-limit-aware GitHub access (shared)
    catalog     the single_file_libs README -> candidate repos, by category
    gating      Stage A: G1-G4 + the GHSA sweep, the ~100% precision stage
    evidence    the negative-result gates: prove a clean run actually ran
    disclosure  where a report can actually be sent, before it is written
    shapes      Stage B: the three C shape scanners, with their measured verdicts

Every module here is importable without Flask and takes its I/O through an
injected client or runner, so each one is testable offline against fixtures -
the same rule the pipeline applies to itself: prove the tool works on a known
input before believing what it says about a new one.
"""
