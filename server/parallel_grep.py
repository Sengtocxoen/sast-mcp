"""
parallel_grep.py - sharded, load-balanced opengrep/semgrep scanning for large repos.

A single opengrep process over a big tree either blows the per-scan systemd
MemoryMax cap and gets OOM-killed (with --max-memory 0 + parallel jobs), or runs
past the request window. This splits the target into byte-balanced shards (LPT
bin-packing so scan cost is even across workers), runs them through a pool sized
by BOTH cpu cores and a memory budget (peak RSS stays bounded), and merges the
per-shard JSON back into one semgrep-shaped result.

Additive by design: routes/sast.py::_opengrep_scan tries this first and falls
back to the original single-command path on None/any error, so a bug here can
never make scans worse than before.
"""
import heapq
import json
import logging
import os
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from config import SCAN_MEMORY_MAX_MB, MAX_PROCESS_WORKERS
from core import ENHANCED_ENV, _probe_memory_limiter

logger = logging.getLogger(__name__)

# ---- tunables (env-overridable) -------------------------------------------
SHARD_MIN_FILES    = int(os.environ.get("GREP_SHARD_MIN_FILES", 350))
SHARD_TARGET_BYTES = int(os.environ.get("GREP_SHARD_TARGET_BYTES", 2_500_000))
SHARD_MEM_MB       = int(os.environ.get("GREP_SHARD_MEM_MB", 1024))
MAX_CONCURRENCY    = int(os.environ.get("GREP_MAX_CONCURRENCY", 0))  # 0 = auto
BINS_PER_WORKER    = int(os.environ.get("GREP_BINS_PER_WORKER", 6))

_SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build",
              "testdata", "third_party", ".venv", "venv", "__pycache__"}
_SRC_EXT = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".inc",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue",
    ".py", ".rb", ".go", ".java", ".scala", ".kt", ".kts",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs",
    ".rs", ".swift", ".m", ".pl", ".pm", ".sh", ".bash",
    ".html", ".htm", ".tf", ".yaml", ".yml", ".json", ".xml",
}


def _total_ram_mb() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 4096


def _memory_budget_mb() -> int:
    env = os.environ.get("SCAN_TOTAL_MEMORY_BUDGET_MB")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    return max(SCAN_MEMORY_MAX_MB, int(_total_ram_mb() * 0.65))


def _plan_concurrency(per_shard_mb: int) -> int:
    by_mem = max(1, _memory_budget_mb() // max(256, per_shard_mb))
    by_cpu = max(1, os.cpu_count() or 4)
    cap = MAX_CONCURRENCY if MAX_CONCURRENCY > 0 else max(1, MAX_PROCESS_WORKERS)
    return max(1, min(cap, by_cpu, by_mem))


def _enumerate(root: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        for name in fn:
            if os.path.splitext(name)[1].lower() not in _SRC_EXT:
                continue
            p = os.path.join(dp, name)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if sz:
                out.append((p, sz))
    return out


def _shard(files: List[Tuple[str, int]], num_bins: int) -> List[List[str]]:
    """LPT bin-packing: biggest files into the lightest bin -> even bytes/bin."""
    bins: List[List[str]] = [[] for _ in range(num_bins)]
    loads = [(0, i) for i in range(num_bins)]
    heapq.heapify(loads)
    for path, sz in sorted(files, key=lambda t: t[1], reverse=True):
        load, idx = heapq.heappop(loads)
        bins[idx].append(path)
        heapq.heappush(loads, (load + sz, idx))
    return [b for b in bins if b]


def _wrap_mem(cmd: str, mem_mb: int) -> str:
    if not _probe_memory_limiter():
        return cmd
    user = "" if os.geteuid() == 0 else "--user "
    return (f"systemd-run --scope --quiet --collect {user}"
            f"-p MemoryMax={mem_mb}M -p MemorySwapMax=0 -- /bin/sh -c {shlex.quote(cmd)}")


def _run_shard(engine, config, lang, severity, output_format, extra_args,
               files, mem_mb, timeout) -> Dict[str, Any]:
    inner = (f"{engine} scan --config={shlex.quote(config)} --jobs 1 "
             f"--max-memory {mem_mb} --timeout 10 --timeout-threshold 3 --metrics=off")
    if lang:
        inner += f" --lang={shlex.quote(lang)}"
    if severity:
        inner += f" --severity={shlex.quote(severity)}"
    inner += f" --{output_format}"
    if extra_args:
        inner += f" {extra_args}"
    inner += " " + " ".join(shlex.quote(f) for f in files)
    cmd = _wrap_mem(inner, mem_mb)
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           env=ENHANCED_ENV, timeout=timeout)
        return {"stdout": p.stdout, "stderr": p.stderr, "rc": p.returncode, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        so = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return {"stdout": so, "stderr": "", "rc": -1, "timed_out": True}


def _merge(shard_outs: List[Dict[str, Any]]) -> Dict[str, Any]:
    results, errors, scanned = [], [], []
    version = ""
    parsed_ok = 0
    for s in shard_outs:
        try:
            d = json.loads(s.get("stdout") or "")
        except Exception:
            continue
        parsed_ok += 1
        results += d.get("results", []) or []
        errors += d.get("errors", []) or []
        scanned += (d.get("paths", {}) or {}).get("scanned", []) or []
        version = version or d.get("version", "")
    merged = {"version": version, "results": results, "errors": errors,
              "paths": {"scanned": scanned}}
    return {"json": json.dumps(merged), "parsed_ok": parsed_ok,
            "findings": len(results), "parse_warnings": len(errors)}


def run_parallel_grep_scan(*, engine, config, lang, severity, output_format,
                           extra_args, resolved_target, timeout) -> Optional[Dict[str, Any]]:
    """execute_command-shaped result from a sharded parallel scan, or None when
    sharding does not apply (caller then runs the original single path)."""
    if output_format != "json" or not os.path.isdir(resolved_target):
        return None
    files = _enumerate(resolved_target)
    if len(files) < SHARD_MIN_FILES:
        return None
    per_shard_mb = SHARD_MEM_MB
    concurrency = _plan_concurrency(per_shard_mb)
    if concurrency < 2:
        return None

    total_bytes = sum(sz for _, sz in files)
    # One shard per worker: each opengrep process pays the ~4s rule-compile
    # cost once, in parallel. More bins than workers would re-pay it serially.
    num_bins = concurrency
    shards = _shard(files, num_bins)

    t0 = time.monotonic()
    outs: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(_run_shard, engine, config, lang, severity, output_format,
                          extra_args, sh, per_shard_mb, timeout) for sh in shards]
        for fu in as_completed(futs):
            outs.append(fu.result())
    elapsed = round(time.monotonic() - t0, 1)

    merged = _merge(outs)
    any_timeout = any(o["timed_out"] for o in outs)
    fatals = sum(1 for o in outs if o["rc"] == 2)
    if merged["parsed_ok"] == 0 and fatals:
        rc = 2
    else:
        rc = 1 if merged["findings"] else 0
    logger.info("parallel grep: %d files / %d shards / x%d workers / %ss / %d findings",
                len(files), len(shards), concurrency, elapsed, merged["findings"])
    return {
        "stdout": merged["json"],
        "stderr": (f"{fatals}/{len(shards)} shard(s) fatal" if fatals else ""),
        "return_code": rc, "success": rc in (0, 1),
        "timed_out": any_timeout, "partial_results": any_timeout,
        "command": f"[parallel-sharded {engine}] {len(shards)} shards x{concurrency} workers",
        "scan_mode": "parallel-sharded",
        "shard_stats": {"files": len(files), "shards": len(shards),
                        "concurrency": concurrency, "per_shard_mem_mb": per_shard_mb,
                        "elapsed_s": elapsed, "total_bytes": total_bytes,
                        "fatal_shards": fatals},
    }
