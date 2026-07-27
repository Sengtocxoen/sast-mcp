"""
Fuzzing endpoint: POST /api/fuzz — discover Go native fuzz targets in a checked-
out repo and run them time-boxed as a BACKGROUND job, collecting crashers.

Fuzzing is long-running and CPU/memory heavy, so unlike the SAST endpoints this
always runs as a background job (poll /api/jobs/<id>). Each `go test -fuzz` run
goes through core.execute_command, so it inherits the per-scan memory cap and
enhanced PATH. Crashers land in the repo's testdata/fuzz/<Func>/ dir and their
paths + failure snippets are returned in the job result.

v1 supports the Go native fuzzing engine (go test -fuzz), which needs no harness
build. A libFuzzer engine for C/C++ can be added alongside later.
"""
import logging
import os
import re
import shlex
import traceback
from typing import Any, Dict, List

from flask import Flask, request, jsonify

from core import execute_command, validate_scan_target, run_scan_in_background

logger = logging.getLogger(__name__)

_FUZZ_FUNC_RE = re.compile(r"^func\s+(Fuzz[A-Za-z0-9_]*)\s*\(", re.MULTILINE)
_FUZZTIME_RE = re.compile(r"^\d+(ms|s|m|h|x)?$")
_CRASHER_RE = re.compile(r"Failing input written to (\S+)")
_SKIP_DIRS = {".git", "vendor", "node_modules", "dist", "build", "third_party"}
_MAX_TARGETS_CAP = 50


def _fuzztime_seconds(fuzztime: str) -> int:
    """Best-effort convert a Go -fuzztime value to a wall-clock second budget."""
    m = re.match(r"^(\d+)(ms|s|m|h|x)?$", fuzztime)
    if not m:
        return 60
    n, unit = int(m.group(1)), m.group(2)
    if unit == "x":       # N iterations, not time — cap the wall budget generously
        return 600
    return {"ms": max(1, n // 1000), "s": n, "m": n * 60, "h": n * 3600, None: n}.get(unit, n)


def _discover_go_fuzz(root: str, max_targets: int) -> List[Dict[str, str]]:
    """Find Go native fuzz targets: func Fuzz*(f *testing.F) in *_test.go files."""
    targets: List[Dict[str, str]] = []
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith("_test.go"):
                continue
            fpath = os.path.join(dirpath, fn)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    src = f.read()
            except Exception:
                continue
            for func in _FUZZ_FUNC_RE.findall(src):
                key = (dirpath, func)  # a Fuzz name is unique within its package
                if key in seen:
                    continue
                seen.add(key)
                targets.append({
                    "func": func,
                    "pkg_dir": dirpath,
                    "pkg_rel": os.path.relpath(dirpath, root),
                })
                if len(targets) >= max_targets:
                    return targets
    return targets


def _summarize_failure(output: str) -> str:
    """Pull the most telling line out of a failing `go test -fuzz` log."""
    for pat in ("panic:", "fatal error:", "runtime error:", "--- FAIL"):
        for line in output.splitlines():
            if pat in line:
                return line.strip()[:300]
    return ""


def run_go_fuzz(params: Dict[str, Any]) -> Dict[str, Any]:
    """Background worker: run each discovered/selected Go fuzz target time-boxed.

    Module-level so it is picklable for the process-pool job executor. Never
    raises — returns a result dict (a crash is a finding, not an error).
    """
    root = validate_scan_target(params["target"])
    fuzztime = params.get("fuzztime", "60s")
    if not _FUZZTIME_RE.match(fuzztime):
        fuzztime = "60s"
    max_targets = min(int(params.get("max_targets", 10)), _MAX_TARGETS_CAP)
    wanted = set(params.get("targets") or [])

    discovered = _discover_go_fuzz(root, _MAX_TARGETS_CAP)
    if wanted:
        discovered = [t for t in discovered if t["func"] in wanted]
    discovered = discovered[:max_targets]

    per_target_timeout = _fuzztime_seconds(fuzztime) + 240  # build + startup buffer
    results: List[Dict[str, Any]] = []
    crashed = 0
    for t in discovered:
        q = shlex.quote
        cmd = (
            f"cd {q(t['pkg_dir'])} && GOFLAGS=-mod=mod "
            f"go test -run='^$' -fuzz={q('^' + t['func'] + '$')} "
            f"-fuzztime={q(fuzztime)} . 2>&1"
        )
        res = execute_command(cmd, timeout=per_target_timeout)
        output = (res.get("stdout") or "") + (res.get("stderr") or "")
        rc = res.get("return_code", 0)
        is_crash = rc not in (0,) and ("FAIL" in output or "panic" in output.lower())
        entry: Dict[str, Any] = {
            "func": t["func"],
            "pkg": t["pkg_rel"],
            "crashed": bool(is_crash),
            "return_code": rc,
            "timed_out": res.get("timed_out", False),
        }
        if is_crash:
            crashed += 1
            entry["failure"] = _summarize_failure(output)
            mcr = _CRASHER_RE.search(output)
            if mcr:
                crasher_rel = mcr.group(1)
                crasher_path = os.path.join(t["pkg_dir"], crasher_rel) if not os.path.isabs(crasher_rel) else crasher_rel
                entry["crasher_path"] = crasher_path
                try:
                    with open(crasher_path, "r", errors="ignore") as f:
                        entry["crasher_input"] = f.read()[:1000]
                except Exception:
                    pass
            entry["log_tail"] = output[-1500:]
        results.append(entry)

    return {
        "success": True,
        "engine": "go",
        "target": root,
        "fuzztime_per_target": fuzztime,
        "targets_discovered": len(discovered),
        "targets_crashed": crashed,
        "results": results,
        "summary": {"targets": len(discovered), "crashed": crashed},
        "note": "a crashed target is a confirmed reproducer (crasher_input); triage reachability from untrusted input before reporting",
    }


def register(app: Flask) -> None:
    @app.route("/api/fuzz", methods=["POST"])
    def fuzz():
        try:
            params = request.json or {}
            if not params.get("target"):
                return jsonify({"error": "target (path to a checked-out repo/module) is required"}), 400
            engine = params.get("engine", "go")
            if engine != "go":
                return jsonify({"error": f"engine {engine!r} not supported yet (v1: go native fuzzing)"}), 400

            # Fast synchronous discovery mode: list fuzz targets without running.
            if params.get("discover_only"):
                root = validate_scan_target(params["target"])
                targets = _discover_go_fuzz(root, _MAX_TARGETS_CAP)
                return jsonify({"target": root, "count": len(targets), "targets": targets})

            # Fuzzing is long-running -> always background, regardless of FORCE_SYNC_SCANS.
            return jsonify(run_scan_in_background("fuzz-go", params, run_go_fuzz))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"fuzz: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
