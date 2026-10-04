"""
evidence.py - prove the run happened before believing it found nothing.

This is the triage half of docs/hunt-pipeline/ARCHITECTURE.md section 4, and it
is the module with the highest value per line, because the failure it prevents
is invisible by construction: a fuzzer that never started reports zero crashes,
and so does a fuzzer that found none. During the campaign six "0 crashes"
verdicts were never tests at all - `nohup cmd &` died the moment the tool call
returned - and two of those five targets were sitting on real bugs.

The same shape appeared twice more:

* **0 exec/s.** vgmstream's harness wrote a temp file per execution: 14,309
  executions across 455 parsers in 40 minutes, libFuzzer's own counter rounding
  to zero. Serving the companion-file opens from memory instead (~40 lines over
  the STREAMFILE vtable) gave 3,934 exec/s, 198,260 executions, and *raised*
  coverage 3,689 -> 4,087.
* **cov: 20.** A fluidsynth build reported 30 coverage counters, which was the
  harness alone - fluid_sffile.c.o had zero sanitizer_cov symbols because CMake
  silently ignored -DCMAKE_C_FLAGS on a reconfigure. After a clean rebuild:
  12,990 counters, cov: 1480. A blind fuzzer still runs and still reports
  "0 crashes".

So every function here returns `clean_claim_admissible`, and the server refuses
to describe a result as clean unless something proves the test ran. The rule is
the same one section 5 applies to the SAST side with its canary file: validate
the tool before believing a negative.
"""
import logging
import os
import re

import subprocess
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# Below this, a run is not a test - it is a harness fighting the filesystem.
# vgmstream sat at ~6 exec/s derived (reported 0); the fixed harness hit 3,934.
MIN_EXEC_RATE = int(os.environ.get("HUNT_MIN_EXEC_RATE", 50))
# fluidsynth's harness-only build reported 20 counters; the real one, 1,480.
MIN_COVERAGE = int(os.environ.get("HUNT_MIN_COVERAGE", 100))

# Flags that make a "clean" claim inadmissible. Anything else is advisory.
BLOCKING_FLAGS = frozenset({
    "never_started", "build_failed", "throughput_collapse",
    "coverage_suspiciously_low", "no_execution_count",
})

_GO_MARKERS = ("fuzz: elapsed:", "execs:", "[build failed]", "--- FAIL: Fuzz")
_CRASH_RE = re.compile(r"==\d+==ERROR:\s*(\w+)")
_SAN_WORDS = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "MemorySanitizer",
              "LeakSanitizer", "ThreadSanitizer")
_LF_EXECS_RE = re.compile(r"^#(\d+)", re.MULTILINE)
_LF_DONE_RE = re.compile(r"Done\s+(\d+)\s+runs\s+in\s+(\d+)\s+second", re.I)
_LF_COV_RE = re.compile(r"\bcov:\s*(\d+)")
_LF_RATE_RE = re.compile(r"exec/s:\s*(\d+)")
_GO_EXECS_RE = re.compile(r"execs:\s*(\d+)")
_GO_RATE_RE = re.compile(r"\((\d+)/sec\)")
_BUILD_FAIL_RE = re.compile(r"\[build failed\]|build failed|error: |undefined reference", re.I)
_FS_CALL_RE = re.compile(
    r"\b(fopen|freopen|fdopen|tmpfile|tmpnam|mkstemp|mkstemps|mkdtemp|"
    r"fwrite|fread|fprintf|fscanf|unlink|remove|rename|creat|truncate|"
    r"ftruncate|fseek|rewind|opendir|stat|access)\s*\(")
# The seams most media libraries already have, where a memory-backed reader
# replaces the filesystem round trip.
KNOWN_SEAMS = ("STREAMFILE", "SDL_RWops", "fluid_file_callbacks_t", "stbi_io_callbacks",
               "ma_decoder_read_proc", "AVIOContext", "drwav_read_proc")
_ASSERT_RE = re.compile(r"\bassert\s*\(|\bNS_ASSERT|\bFBXDOCUMENT_ASSERT")
_RECOVERY_RE = re.compile(r"\breturn\b|\bgoto\s+\w*(fail|err|cleanup)|\blongjmp\b|"
                          r"\bError\s*\(|\bthrow\b|\bbreak\b")
_WRITE_RE = re.compile(r"\b(memcpy|memmove|memset|strcpy|strcat|sprintf|\w+\s*\[[^\]]+\]\s*=)")
_OPT_RE = re.compile(r"-O([1-9sfzg]|fast)")

Runner = Callable[[Sequence[str]], Any]

# check_instrumentation is reachable from an HTTP endpoint, so the symbol reader
# is chosen from this list rather than taken from the request. Everything here
# runs argv-style with shell=False: the object paths are attacker-influenced and
# must never reach a shell.
ALLOWED_SYMBOL_TOOLS = ("nm", "llvm-nm", "llvm-nm-18", "llvm-nm-17", "llvm-nm-16",
                        "gnm", "eu-nm", "objdump")


def _default_runner(argv: Sequence[str]):
    """Run a short local command argv-style. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(list(argv), shell=False, capture_output=True,
                           text=True, timeout=120)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except FileNotFoundError as e:
        return 127, "", f"{argv[0] if argv else 'tool'} not found: {e}"
    except Exception as e:  # pragma: no cover - platform dependent
        return 127, "", f"{type(e).__name__}: {e}"


def _as_text(source: str) -> str:
    """Accept either source text or a path to it."""
    if not source:
        return ""
    if len(source) < 400 and "\n" not in source:
        try:
            if os.path.isfile(source):
                with open(source, "r", errors="ignore") as f:
                    return f.read()
        except (OSError, ValueError):
            pass
    return source


# ------------------------------------------------------------------ fuzz logs

def validate_fuzz_log(text: str, min_exec_rate: int = MIN_EXEC_RATE,
                      min_coverage: int = MIN_COVERAGE) -> Dict[str, Any]:
    """Read a fuzzing log and decide whether it proves anything.

    Returns the measured numbers plus `clean_claim_admissible`, which is the
    only field a caller should trust when deciding whether "0 crashes" means
    the target is clean or that nothing was ever tested.
    """
    text = text or ""
    flags: List[str] = []
    hints: List[str] = []

    engine = "unknown"
    if any(m in text for m in _GO_MARKERS):
        engine = "go"
    if "INITED" in text or "libFuzzer" in text or "MERGE-OUTER" in text:
        engine = "libfuzzer"

    execs: Optional[int] = None
    coverage: Optional[int] = None
    rate: Optional[int] = None
    derived_rate: Optional[int] = None
    duration: Optional[int] = None

    if engine == "libfuzzer":
        counts = [int(m) for m in _LF_EXECS_RE.findall(text)]
        done = _LF_DONE_RE.search(text)
        if done:
            counts.append(int(done.group(1)))
            duration = int(done.group(2))
        execs = max(counts) if counts else None
        covs = _LF_COV_RE.findall(text)
        coverage = int(covs[-1]) if covs else None
        # The INITED line always prints exec/s: 0, so take the best rate the tool
        # itself reported. runs/seconds from the DONE line is kept separately as a
        # cross-check rather than overwriting what libFuzzer said.
        rates = [int(r) for r in _LF_RATE_RE.findall(text)]
        rate = max(rates) if rates else None
        if execs and duration and duration > 0:
            derived_rate = int(execs / duration)
            if rate is None:
                rate = derived_rate
    else:
        e = _GO_EXECS_RE.findall(text)
        execs = max(int(x) for x in e) if e else None
        r = _GO_RATE_RE.findall(text)
        rate = max(int(x) for x in r) if r else None

    crash = _CRASH_RE.search(text)
    sanitizer = crash.group(1) if crash else next(
        (w for w in _SAN_WORDS if w in text), "")
    crash_detected = bool(crash) or any(
        w in text for w in ("SEGV on unknown address", "heap-buffer-overflow",
                            "stack-overflow", "use-after-free", "panic: runtime error"))

    build_failed = bool(_BUILD_FAIL_RE.search(text)) and not execs
    if build_failed:
        flags.append("build_failed")
        hints.append("the target never built; fix the build before reading this as clean")

    started = bool(execs) or "INITED" in text
    if not started:
        flags.append("never_started")
        hints.append("no INITED line and no execution count: this log does not show a run. "
                     "A backgrounded `nohup cmd &` dies when the tool call returns - "
                     "run it in the foreground or under a job runner that outlives the call.")
    elif execs is None:
        flags.append("no_execution_count")
        hints.append("the log shows a start but no execution count; cannot size the run")

    # Judge throughput on the best of what the tool reported and what the run
    # actually averaged, so a missing exec/s field cannot fake a collapse.
    best_rate = max(rate or 0, derived_rate or 0) if (rate is not None or derived_rate is not None) else None
    if started and execs and best_rate is not None and best_rate < min_exec_rate:
        flags.append("throughput_collapse")
        hints.append(
            f"{best_rate} exec/s is not a test. The usual cause is a harness touching the "
            f"filesystem per execution (vgmstream: 14,309 execs in 40 minutes at a "
            f"reported 0 exec/s). Reimplement the reader over memory - the seam is "
            f"usually {', '.join(KNOWN_SEAMS[:4])} - which also tends to RAISE coverage, "
            f"because companion-file opens get served from the same buffer.")

    if started and coverage is not None and coverage < min_coverage:
        flags.append("coverage_suspiciously_low")
        hints.append(
            f"cov: {coverage} is about what a harness alone reports. Verify the TARGET's "
            f"objects are instrumented (nm <obj> | grep -c sanitizer_cov); CMake silently "
            f"ignores -DCMAKE_C_FLAGS on a reconfigure, so wipe the build dir and set "
            f"CMAKE_C_FLAGS_DEBUG. fluidsynth went 30 -> 12,990 counters this way.")

    blocking = [f for f in flags if f in BLOCKING_FLAGS]
    return {
        "engine": engine,
        "ran": bool(started),
        "execs": execs,
        "coverage": coverage,
        "exec_per_sec": rate,
        "exec_per_sec_derived": derived_rate,
        "duration_seconds": duration,
        "crash_detected": bool(crash_detected),
        "sanitizer": sanitizer,
        "flags": flags,
        "blocking_flags": blocking,
        "hints": hints,
        # A crash means "clean" is not the question any more, so it is false here too.
        "clean_claim_admissible": bool(started) and not blocking and not crash_detected,
    }


# ------------------------------------------------------- instrumentation check

def check_instrumentation(object_paths: Sequence[str], runner: Optional[Runner] = None,
                          min_counters: int = 1, nm: str = "nm") -> Dict[str, Any]:
    """Count sanitizer coverage symbols in the target's own objects.

    The fluidsynth case in section 3: the harness was instrumented and the
    parser was not, so coverage looked alive while the code under test was
    invisible. An object with zero sanitizer_cov symbols means the fuzzer is
    blind to it, whatever the crash count says.
    """
    run = runner or _default_runner
    per_object: Dict[str, int] = {}
    errors: List[str] = []

    tool = nm if nm in ALLOWED_SYMBOL_TOOLS else "nm"
    for path in object_paths:
        # argv-style, never through a shell: these paths come from a request body.
        rc, out, err = run([tool, path])
        if rc != 0:
            errors.append(f"{path}: {(err or out or 'nm failed').strip()[:200]}")
            continue
        per_object[path] = sum(1 for line in (out or "").splitlines()
                               if "sanitizer_cov" in line)

    uninstrumented = [p for p, n in per_object.items() if n < min_counters]
    total = sum(per_object.values())
    return {
        "counters_by_object": per_object,
        "total_counters": total,
        "uninstrumented": uninstrumented,
        "blind": bool(uninstrumented),
        "errors": errors,
        "clean_claim_admissible": not uninstrumented and not errors and bool(per_object),
        "hint": ("wipe the build directory and set CMAKE_C_FLAGS_DEBUG (not CMAKE_C_FLAGS, "
                 "which a reconfigure silently ignores) so -fsanitize-coverage reaches the "
                 "target's objects, not just the harness")
        if uninstrumented else "",
    }


# ------------------------------------------------------------ harness I/O smell

def check_harness_filesystem_io(source: str) -> Dict[str, Any]:
    """Flag a harness that touches the filesystem per execution.

    This is the single highest-leverage harness defect the campaign found: the
    fix was ~40 lines and bought a 3,934x throughput improvement plus better
    coverage. Most media libraries already have the seam for it.
    """
    text = _as_text(source)
    hits: List[Dict[str, Any]] = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "*", "/*", "#")):
            continue
        for m in _FS_CALL_RE.finditer(line):
            hits.append({"call": m.group(1), "line": i, "text": line.strip()[:160]})

    seams = [s for s in KNOWN_SEAMS if s in text] or list(KNOWN_SEAMS[:4])
    return {
        "filesystem_io": bool(hits),
        "hits": hits,
        "seams": seams,
        "hint": (f"replace the per-execution file round trip with a memory-backed reader over "
                 f"{seams[0]}; vgmstream went 0 -> 3,934 exec/s and 3,689 -> 4,087 coverage")
        if hits else "harness reads from memory",
    }


# ---------------------------------------------------------------- assert triage

def classify_assert_crash(source: str, line: int, window: int = 8) -> Dict[str, Any]:
    """Is an assert crash reportable, or does a correct path exist below it?

    Section 4's sharpest case: OpenFBX's 6 crashes were all one assert(false)
    whose very next line was `return Error(...)`, so under -DNDEBUG the library
    behaves correctly - not reportable. dmc_unrar's assert looked identical and
    had no fallback, so it SEGVs under NDEBUG - reportable. Same symptom,
    opposite verdict, and only the surrounding lines tell you which.
    """
    text = _as_text(source)
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return {"verdict": "unknown", "detail": f"line {line} is outside the file "
                                                f"({len(lines)} lines)", "evidence": {}}

    target = lines[line - 1]
    if not _ASSERT_RE.search(target):
        return {"verdict": "unknown",
                "detail": f"line {line} is not an assert: {target.strip()[:120]!r}",
                "evidence": {"line_text": target.strip()[:160]}}

    below = lines[line:line + window]
    recovery_at = None
    write_at = None
    for off, l in enumerate(below, 1):
        stripped = l.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        if write_at is None and _WRITE_RE.search(stripped):
            write_at = line + off
        if recovery_at is None and _RECOVERY_RE.search(stripped):
            recovery_at = line + off
        if stripped == "}" and recovery_at is None and write_at is None:
            break

    evidence = {
        "assert_line": line,
        "assert_text": target.strip()[:160],
        "recovery_line": recovery_at,
        "unguarded_write_line": write_at,
        "window": [w.strip()[:120] for w in below],
    }

    if recovery_at and (write_at is None or recovery_at <= write_at):
        return {"verdict": "not_reportable",
                "detail": (f"a correct non-assert path exists at line {recovery_at}, so the "
                           f"library behaves correctly under -DNDEBUG. Rebuild with -DNDEBUG "
                           f"and confirm before reporting (OpenFBX: 6 crashes, all clean)."),
                "evidence": evidence}
    return {"verdict": "reportable",
            "detail": ("no correct fallback below the assert" +
                       (f"; an unguarded write at line {write_at}" if write_at else "") +
                       ". Confirm it SEGVs under -DNDEBUG, which is what made the "
                       "dmc_unrar case reportable where OpenFBX's was not."),
            "evidence": evidence}


# --------------------------------------------------- timeouts and PoC building

def needs_single_threaded_rerun(log: str, jobs: int = 1) -> Dict[str, Any]:
    """A timeout under -jobs>1 may just be CPU contention.

    Five fluidsynth "timeouts" completed in 97-235 ms when re-run alone;
    vgmstream's did hang standalone and were real. The re-run is what tells
    them apart, so a parallel timeout is never reported as a finding.
    """
    text = log or ""
    timed_out = bool(re.search(r"timeout after|libFuzzer: timeout|ERROR: libFuzzer: "
                               r"deadly signal.*timeout|-timeout=", text, re.I))
    workers = jobs
    m = re.search(r"Running\s+(\d+)\s+workers", text, re.I)
    if m:
        workers = max(workers, int(m.group(1)))

    required = bool(timed_out and workers > 1)
    return {
        "timed_out": timed_out,
        "workers": workers,
        "rerun_required": required,
        "command_hint": ("re-run this input single-threaded (-jobs=1 -workers=1) before "
                         "believing the timeout: 5 of the campaign's parallel timeouts "
                         "completed in under 250 ms alone") if required else "",
        "detail": ("parallel run: a timeout here is not evidence of a hang"
                   if required else
                   "single-threaded timeout: believable" if timed_out else "no timeout in log"),
    }


def check_poc_build_flags(command: str, signal: str = "store") -> Dict[str, Any]:
    """A store-signal PoC must be built at -O0.

    At -O1 the compiler's dead-store elimination deleted paldither's overflowing
    memcpy outright and the PoC reported "survived" - indistinguishable from a
    fixed library. ASan-signalled PoCs are exempt: ASan reports the access
    itself, so optimisation cannot quietly remove the evidence.
    """
    cmd = command or ""
    has_asan = "-fsanitize=address" in cmd or "-fsanitize=undefined" in cmd
    opt = _OPT_RE.search(cmd)
    if signal.lower() == "asan" or has_asan:
        return {"valid": True, "signal": "asan", "optimisation": opt.group(0) if opt else "-O0",
                "detail": "ASan reports the access itself, so the optimisation level is not "
                          "load-bearing for this PoC"}
    if opt:
        return {"valid": False, "signal": signal, "optimisation": opt.group(0),
                "detail": (f"rebuild at -O0: at {opt.group(0)} dead-store elimination can delete "
                           f"the overflowing write, and the PoC then reports 'survived' - "
                           f"indistinguishable from a fixed library (paldither)")}
    return {"valid": True, "signal": signal, "optimisation": "-O0",
            "detail": "no optimisation flag: the store will survive to runtime"}


# --------------------------------------------------------------------- verdict

def assess(log: str = "", claimed_crashes: int = 0,
           object_paths: Optional[Sequence[str]] = None,
           harness_source: str = "", jobs: int = 1,
           runner: Optional[Runner] = None, **kw: Any) -> Dict[str, Any]:
    """One verdict over every piece of evidence a fuzzing run can offer."""
    report: Dict[str, Any] = {"log": validate_fuzz_log(log, **{
        k: v for k, v in kw.items() if k in ("min_exec_rate", "min_coverage")})}
    blocking = list(report["log"]["blocking_flags"])

    if object_paths:
        inst = check_instrumentation(object_paths, runner=runner)
        report["instrumentation"] = inst
        if inst["blind"]:
            blocking.append("uninstrumented_target")
        if inst["errors"]:
            blocking.append("instrumentation_unverified")

    if harness_source:
        io = check_harness_filesystem_io(harness_source)
        report["harness"] = io
        if io["filesystem_io"] and "throughput_collapse" not in blocking:
            # Advisory on its own: a slow harness that still ran fast enough is
            # a performance problem, not a disproof.
            report["harness"]["advisory"] = True

    if log:
        report["timeouts"] = needs_single_threaded_rerun(log, jobs=jobs)
        if report["timeouts"]["rerun_required"]:
            blocking.append("parallel_timeout_unconfirmed")

    crashed = report["log"]["crash_detected"] or claimed_crashes > 0
    if crashed:
        verdict = "crash"
    elif not blocking and report["log"]["ran"]:
        verdict = "proven_clean"
    else:
        verdict = "unproven"

    return {
        "verdict": verdict,
        "clean_claim_admissible": verdict == "proven_clean",
        "blocking_flags": blocking,
        "claimed_crashes": claimed_crashes,
        "evidence": report,
        "rule": ("ARCHITECTURE.md section 4: demand a cov:/INITED line before believing a "
                 "negative. Six campaign verdicts of '0 crashes' were never tests, and two "
                 "of those targets held real bugs."),
    }
