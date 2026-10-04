"""
Repo-scan endpoint: POST a Git URL or local path -> stage the tree -> detect
languages AND build-system markers -> run EVERY installed tool that applies ->
write JSON reports -> normalize and cross-check them into one ranked finding set.

One call replaces the manual clone -> pick-tools -> launch -> collect -> dedupe
loop. All tools run through core.execute_command, so they inherit the per-scan
memory cap and the enhanced PATH automatically.

Three things govern how fast this is:

* **Staging** copies the tree off the vmhgfs/fuse share with a streamed `tar`
  pipe rather than a per-file Python copy, and skips the copy entirely when the
  source already lives on local disk.
* **Scheduling** is weighted, not a flat worker count. Tools cost wildly
  different amounts of CPU (semgrep runs N internal jobs; gitleaks is one
  goroutine pool; graudit is grep), so the runner keeps the *sum of weights* in
  flight under a core budget and starts the expensive, long-tailed tools first.
  A flat pool either under-uses the box or oversubscribes it into swap.
* **Selection** asks tool_registry which binaries exist before planning, so an
  uninstalled tool costs nothing instead of a failed process spawn per repo.
"""
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
import traceback
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set

from flask import Flask, request, jsonify

import correlate
import staging
import tool_registry
from config import (
    ALLOWED_MOUNTS,
    MOUNT_POINT,
    REPO_SCAN_CPU_BUDGET,
    REPO_SCAN_TOOL_CONCURRENCY,
)
from core import (
    execute_command,
    resolve_grep_engine,
    validate_scan_target,
)

logger = logging.getLogger(__name__)

# Only clone from these hosts over HTTPS. Keeps a user-supplied URL from turning
# into scp-style git remotes, file:// reads, or command injection.
_URL_RE = re.compile(
    r"^https://(github\.com|gitlab\.com|bitbucket\.org|"
    r"[a-z0-9.-]+\.googlesource\.com)/[A-Za-z0-9._/-]+?(\.git)?$"
)
# Sanitized directory name for the checkout (owner-repo).
_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")

# Source extensions -> (semgrep config packs, extra per-language tool keys).
_LANG_MAP = {
    ".go":    (["p/golang", "p/security-audit"], ["gosec"]),
    ".py":    (["p/python", "p/security-audit"], ["bandit"]),
    ".js":    (["p/javascript", "p/security-audit"], ["nodejsscan", "eslint"]),
    ".jsx":   (["p/javascript"], ["nodejsscan", "eslint"]),
    ".mjs":   (["p/javascript"], ["nodejsscan", "eslint"]),
    ".cjs":   (["p/javascript"], ["nodejsscan", "eslint"]),
    ".ts":    (["p/typescript", "p/javascript"], ["nodejsscan", "eslint"]),
    ".tsx":   (["p/typescript"], ["nodejsscan", "eslint"]),
    ".vue":   (["p/javascript"], ["nodejsscan"]),
    ".rb":    (["p/ruby", "p/security-audit"], ["brakeman"]),
    ".java":  (["p/java", "p/security-audit"], []),
    ".kt":    (["p/kotlin"], []),
    ".scala": (["p/scala"], []),
    ".php":   (["p/php"], []),
    ".c":     (["p/c"], []),
    ".cc":    (["p/c"], []),
    ".cpp":   (["p/cpp"], []),
    ".cs":    (["p/csharp"], []),
    ".rs":    (["p/rust"], []),
    ".swift": (["p/swift"], []),
    ".tf":    (["p/terraform"], ["checkov", "tfsec"]),
    ".yaml":  ([], ["checkov"]),
    ".yml":   ([], ["checkov"]),
}
# Extensions that only pull in IaC tooling — a repo of pure YAML shouldn't be
# reported as "a YAML project" nor drag in the generic security-audit packs.
_IAC_ONLY_EXT = {".yaml", ".yml", ".tf"}

_SKIP_DIRS = {".git", "vendor", "node_modules", "dist", "build", "testdata",
              "third_party", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}
_CLONE_TIMEOUT = 300
# Clone + scan here (local disk) by default. Scanning off the vmhgfs share is
# ~100x slower due to per-file fuse round-trips; only the small JSON reports
# get copied back to the mount for the user.
REPO_SCAN_LOCAL_DIR = os.environ.get("REPO_SCAN_LOCAL_DIR", "/var/tmp/sast-repos")
_SEMGREP_TIMEOUT = 1800
_TOOL_TIMEOUT = 900
_FAST_TIMEOUT = 300

# Filesystem types where per-file I/O is slow enough to justify staging a copy.
# Shared with the per-tool endpoints via server/staging.py, so a filesystem
# added in one place is slow in both.
_SLOW_FSTYPES = staging.SLOW_FSTYPES


def _default_base_dir() -> str:
    """Where to clone by default: a repo-scans/ dir under an allowed mount."""
    root = ALLOWED_MOUNTS[0] if ALLOWED_MOUNTS else MOUNT_POINT
    return os.path.join(root, "repo-scans")


def _clone(url: str, ref: str, base_dir: str) -> Dict[str, Any]:
    name = _NAME_RE.sub("-", url.rstrip("/").split("/")[-1].replace(".git", "")) or "repo"
    dest = os.path.join(base_dir, name)
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, dest]
    subprocess.run(cmd, check=True, timeout=_CLONE_TIMEOUT,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {"dest": dest, "name": name, "reused": False, "url": url}


def _fstype(path: str) -> str:
    """Filesystem type of the mount backing `path` ('' when undeterminable)."""
    try:
        target = os.path.abspath(path)
        best, best_type = "", ""
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mnt, fstype = parts[1], parts[2]
                if (target == mnt or target.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best):
                    best, best_type = mnt, fstype
        return best_type
    except Exception:
        return ""


def _stage_local(path: str, base_dir: str, mode: str = "auto") -> Dict[str, Any]:
    """Get the repo onto fast local disk before scanning.

    Scanning in place over a vmhgfs/fuse share is ~100x slower (per-file
    round-trips), so the copy pays for itself many times over. But the copy
    itself used to be `shutil.copytree` — a serial, per-file Python loop, which
    is the *same* per-file round-trip cost it exists to avoid. A streamed `tar`
    pipe moves the tree in one sequential read/write instead, which is where the
    bulk of the staging speedup comes from.

    mode: "auto"   - stage only when the source is on a slow (network/fuse) FS
          "always" - always stage (previous behaviour)
          "never"  - scan in place
    Always a fresh copy, so the CURRENT working state of the repo (including
    uncommitted local changes) is what gets scanned.
    """
    src = os.path.abspath(path)
    if not os.path.isdir(src):
        raise ValueError(f"path is not a directory: {src}")
    name = _NAME_RE.sub("-", os.path.basename(src.rstrip("/")) or "repo")

    slow = _fstype(src) in _SLOW_FSTYPES
    if mode == "never" or (mode == "auto" and not slow):
        # Already on local disk: scanning in place skips the copy entirely, which
        # on a big monorepo is the single largest chunk of wall clock.
        return {"dest": src, "name": name, "reused": True, "staged": False,
                "source_path": src, "source_fstype": _fstype(src)}

    dest = os.path.join(base_dir, name)
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)

    excludes = " ".join(f"--exclude={shlex.quote(d)}" for d in sorted(_SKIP_DIRS))
    cmd = (f"tar -C {shlex.quote(src)} {excludes} -cf - . | "
           f"tar -C {shlex.quote(dest)} -xf -")
    res = execute_command(cmd, timeout=_CLONE_TIMEOUT * 2)
    if not os.listdir(dest):
        # tar unavailable or refused the tree — fall back to the original copy so
        # staging can never be the reason a scan produces nothing.
        logger.warning(f"tar staging produced nothing for {src}; falling back to copytree")
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(src, dest, ignore=shutil.ignore_patterns(*_SKIP_DIRS),
                        symlinks=False, ignore_dangling_symlinks=True)
    return {"dest": dest, "name": name, "reused": False, "staged": True,
            "source_path": src, "source_fstype": _fstype(src),
            "stage_stderr": (res.get("stderr") or "")[:200] or None}


# ---------------------------------------------------------------------------
# repo context detection
# ---------------------------------------------------------------------------
# Marker files that decide which ecosystem tools can run at all. Running
# `npm audit` without a lockfile or `safety` without a requirements file just
# burns a process, so tools are gated on these rather than on file extensions.
_MARKERS = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "setup.py",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "Cargo.toml", "Cargo.lock", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".eslintrc.json", ".eslintrc.js", "config.ru",
}


def _detect_context(root: str) -> Dict[str, Any]:
    """One walk that collects languages, marker files, and where they live.

    Doing this in a single pass matters: the old code walked for languages and
    then each tool re-walked the tree. On a fuse-backed monorepo those extra
    walks cost more than some of the scans.
    """
    langs: Counter = Counter()
    markers: Dict[str, List[str]] = {}
    req_files: List[str] = []
    tf_dirs: Set[str] = set()
    npm_dirs: Set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        for fn in filenames:
            if fn.endswith("_test.go") or fn.endswith((".test.ts", ".spec.ts", ".d.ts")):
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext in _LANG_MAP:
                langs[ext] += 1
            if ext == ".tf":
                tf_dirs.add(dirpath)
            # Markers are gated on depth (a lockfile 6 levels down belongs to a
            # vendored sub-project, not this repo) but the WALK is not: languages
            # must be counted everywhere or deep monorepos get the wrong packs.
            if fn in _MARKERS and depth <= 3:
                markers.setdefault(fn, []).append(os.path.join(dirpath, fn))
            if depth <= 3 and re.fullmatch(r"requirements.*\.txt", fn):
                req_files.append(os.path.join(dirpath, fn))
            if depth <= 3 and fn in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                npm_dirs.add(dirpath)

    return {"langs": langs, "markers": markers, "req_files": req_files[:5],
            "tf_dirs": sorted(tf_dirs)[:5], "npm_dirs": sorted(npm_dirs)[:5]}


def _parse_findings(path: str, tool: str) -> Dict[str, Any]:
    """Return {findings, parse_errors?} from a tool's JSON report."""
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception as e:
        return {"error": f"unreadable report: {e}"}
    if tool in ("semgrep", "opengrep"):
        return {"findings": len(d.get("results", [])), "parse_errors": len(d.get("errors", []))}
    if tool == "bandit":
        return {"findings": len(d.get("results", []))}
    if tool == "gosec":
        return {"findings": len(d.get("Issues", []))}
    if tool == "nodejsscan":
        n = sum(len(v.get("files", [])) for v in d.get("nodejs", {}).values())
        return {"findings": n}
    if tool in ("gitleaks", "trufflehog"):
        return {"findings": len(d) if isinstance(d, list) else 0}
    if tool == "trivy":
        n = sum(len(r.get("Vulnerabilities", []) or []) +
                len(r.get("Misconfigurations", []) or []) +
                len(r.get("Secrets", []) or [])
                for r in (d.get("Results") or []))
        return {"findings": n}
    if tool == "brakeman":
        return {"findings": len(d.get("warnings", []))}
    if tool == "eslint":
        return {"findings": sum(len(f.get("messages", [])) for f in d)} if isinstance(d, list) else {"findings": 0}
    if tool == "checkov":
        blocks = d if isinstance(d, list) else [d]
        return {"findings": sum(len((b.get("results") or {}).get("failed_checks") or [])
                                for b in blocks if isinstance(b, dict))}
    if tool == "tfsec":
        return {"findings": len(d.get("results") or [])}
    if tool == "graudit":
        return {"findings": len(d.get("matches") or [])}
    # Anything the correlator can normalize gets a count from there.
    n = len(correlate.normalize(tool, path, ""))
    return {"findings": n if n else None}


# ---------------------------------------------------------------------------
# tool execution
# ---------------------------------------------------------------------------
def _jsonl_to_json(path: str) -> None:
    """trufflehog emits JSON-lines; the correlator wants one array."""
    try:
        with open(path, errors="replace") as fh:
            rows = [json.loads(line) for line in fh if line.strip().startswith("{")]
    except Exception:
        rows = []
    with open(path, "w") as fh:
        json.dump(rows, fh)


_GRAUDIT_LINE = re.compile(r"^(?P<file>[^\s:][^:]*):(?P<line>\d+):(?P<text>.*)$")


def _graudit_to_json(path: str) -> None:
    """graudit is grep-shaped text; turn it into something correlatable."""
    matches = []
    try:
        with open(path, errors="replace") as fh:
            for raw in fh:
                m = _GRAUDIT_LINE.match(raw.rstrip("\n"))
                if m:
                    matches.append({"file": m.group("file"), "line": int(m.group("line")),
                                    "text": m.group("text").strip()[:200], "rule": "graudit"})
    except Exception:
        pass
    with open(path, "w") as fh:
        json.dump({"matches": matches[:2000]}, fh)


_POST = {"trufflehog": _jsonl_to_json, "graudit": _graudit_to_json}


def _run_tool(tool: str, command: str, report: str, timeout: int) -> Dict[str, Any]:
    res = execute_command(command, timeout=timeout)
    out = {"tool": tool, "report": report, "return_code": res.get("return_code"),
           "timed_out": res.get("timed_out", False), "duration": res.get("duration")}
    post = _POST.get(tool)
    if post and os.path.exists(report):
        try:
            post(report)
        except Exception as e:
            logger.warning(f"{tool}: post-processing failed: {e}")
    if os.path.exists(report) and os.path.getsize(report) > 0:
        out.update(_parse_findings(report, tool))
    else:
        out["error"] = (res.get("stderr") or res.get("stdout") or "no report written")[:300]
    return out


def _grep_jobs_mem():
    """Native multi-core sizing: jobs*per-worker-mem stays under ~80% of the cap.
    Env overrides: OPENGREP_JOBS (0=auto), OPENGREP_MAX_MEMORY_MB."""
    from config import MAX_PROCESS_WORKERS, SCAN_MEMORY_MAX_MB, OPENGREP_JOBS, OPENGREP_MAX_MEMORY_MB
    per = OPENGREP_MAX_MEMORY_MB
    if OPENGREP_JOBS > 0:
        return OPENGREP_JOBS, per
    jobs = max(1, min(os.cpu_count() or 4, MAX_PROCESS_WORKERS))
    jobs = max(1, min(jobs, int(SCAN_MEMORY_MAX_MB * 0.8) // per))
    return jobs, per


class _WeightedGate:
    """Admission control by cost, not by headcount.

    A plain ThreadPoolExecutor(max_workers=N) treats `semgrep --jobs 8` and
    `graudit` as equally expensive. They are not, and the two failure modes that
    causes are exactly the ones this endpoint hits: pick N low and the cheap
    tools serialize behind nothing; pick N high and several multi-threaded tools
    land together and drive the host into swap. Gating on summed weight lets many
    cheap tools run alongside one expensive one while keeping total in-flight
    cost under a core budget.
    """

    def __init__(self, budget: int):
        self.budget = max(1, budget)
        self._used = 0
        self._cv = threading.Condition()

    def acquire(self, weight: int) -> None:
        w = max(1, min(weight, self.budget))  # an over-budget tool still gets to run, alone
        with self._cv:
            while self._used + w > self.budget:
                self._cv.wait()
            self._used += w

    def release(self, weight: int) -> None:
        w = max(1, min(weight, self.budget))
        with self._cv:
            self._used -= w
            self._cv.notify_all()


def _run_plan_parallel(plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the independent scanners concurrently under a shared CPU budget.

    Each tool writes its own report file and has no dependency on the others.
    Work is submitted heaviest-first so the long tail (semgrep, dependency-check)
    starts immediately instead of being scheduled last behind a queue of cheap
    tools — with an uneven plan that ordering alone is worth a large slice of
    wall clock. Results preserve plan order.
    """
    if not plan:
        return []
    budget = REPO_SCAN_CPU_BUDGET if REPO_SCAN_CPU_BUDGET > 0 else (os.cpu_count() or 4)
    gate = _WeightedGate(budget)
    # Thread count is only an upper bound; the gate does the real limiting.
    workers = max(1, min(len(plan), max(REPO_SCAN_TOOL_CONCURRENCY, budget)))
    results: List[Optional[Dict[str, Any]]] = [None] * len(plan)

    def _guarded(entry: Dict[str, Any]) -> Dict[str, Any]:
        w = int(entry.get("weight", 1))
        gate.acquire(w)
        try:
            return _run_tool(entry["tool"], entry["command"], entry["report"], entry["timeout"])
        finally:
            gate.release(w)

    order = sorted(range(len(plan)), key=lambda i: -int(plan[i].get("weight", 1)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut_to_idx = {ex.submit(_guarded, plan[i]): i for i in order}
        for fut in as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as e:  # a single tool crashing must not sink the repo scan
                results[i] = {"tool": plan[i]["tool"], "report": plan[i]["report"],
                              "error": f"runner failed: {e}"}
    return [r for r in results if r is not None]


def _publish_reports(out_dir: str, mount_base: str, name: str) -> str:
    dest = os.path.join(mount_base, name, "_sast_reports")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copytree(out_dir, dest, dirs_exist_ok=True)
    return dest


# ---------------------------------------------------------------------------
# planning
# ---------------------------------------------------------------------------
# ESLint's CLI is not stable across majors: v9 dropped .eslintrc discovery and
# v10 removed --no-eslintrc and --ext outright, so one hardcoded command line
# silently produces zero findings on whichever major the host happens to have.
# Probe the version once and emit the matching invocation.
_ESLINT_GLOBS = ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", "**/*.ts", "**/*.tsx"]
_ESLINT_LEGACY_CONFIG = {
    "plugins": ["security"],
    "extends": ["plugin:security/recommended-legacy"],
    "parserOptions": {"ecmaVersion": 2022, "sourceType": "module"},
    "env": {"node": True, "browser": True, "es2022": True},
}
_eslint_probe: Dict[str, Any] = {}


def _eslint_env() -> Dict[str, Any]:
    """{major, plugin_dir} for the installed eslint, probed once per process."""
    if not _eslint_probe:
        major = 0
        res = execute_command("eslint --version", timeout=30)
        m = re.search(r"v?(\d+)\.", (res.get("stdout") or "") + (res.get("stderr") or ""))
        if m:
            major = int(m.group(1))
        plugin_dir = ""
        root = (execute_command("npm root -g", timeout=30).get("stdout") or "").strip()
        for cand in (root, "/usr/lib/node_modules", "/usr/local/lib/node_modules"):
            if cand and os.path.isdir(os.path.join(cand, "eslint-plugin-security")):
                plugin_dir = cand
                break
        _eslint_probe.update({"major": major, "plugin_dir": plugin_dir})
    return _eslint_probe


def _eslint_entry(dest: str, out_dir: str, rep_path: str) -> Optional[Dict[str, Any]]:
    """Build the eslint plan entry for whichever eslint major is installed."""
    env = _eslint_env()
    major, plugin_dir = env["major"], env["plugin_dir"]
    if not major:
        return None
    if not plugin_dir:
        # Without eslint-plugin-security, eslint contributes only style noise.
        logger.info("eslint: eslint-plugin-security not installed; skipping")
        return None
    q = shlex.quote
    if major >= 9:
        # Flat config. The plugin is imported by absolute path because the config
        # lives in the report dir, not next to a node_modules that resolves it.
        cfg_path = os.path.join(out_dir, "eslint.config.mjs")
        plugin_path = os.path.join(plugin_dir, "eslint-plugin-security", "index.js")
        with open(cfg_path, "w") as fh:
            fh.write(
                f"import security from {json.dumps(plugin_path)};\n"
                f"export default [{{\n"
                f"  files: {json.dumps(_ESLINT_GLOBS)},\n"
                f"  plugins: {{ security }},\n"
                f"  rules: security.configs.recommended.rules,\n"
                f"  languageOptions: {{ ecmaVersion: 2022, sourceType: \"module\" }}\n"
                f"}}];\n"
            )
        cmd = (f"cd {q(dest)} && NODE_PATH={q(plugin_dir)} eslint --no-config-lookup "
               f"-c {q(cfg_path)} -f json -o {q(rep_path)} . || true")
    else:
        cfg_path = os.path.join(out_dir, "eslintrc.security.json")
        with open(cfg_path, "w") as fh:
            json.dump(_ESLINT_LEGACY_CONFIG, fh)
        cmd = (f"ESLINT_USE_FLAT_CONFIG=false eslint --no-eslintrc -c {q(cfg_path)} "
               f"--resolve-plugins-relative-to {q(plugin_dir)} "
               f"--ext .js,.jsx,.mjs,.cjs,.ts,.tsx -f json -o {q(rep_path)} "
               f"{q(dest)} || true")
    return {"tool": "eslint", "command": cmd, "report": rep_path,
            "timeout": _FAST_TIMEOUT, "weight": 1}


def _build_plan(ctx: Dict[str, Any], dest: str, out_dir: str,
                want: Dict[str, bool]) -> List[Dict[str, Any]]:
    """Assemble the command list: every installed tool that applies to this repo.

    Gating is three-way — the language/marker must be present, the binary must be
    installed, and the caller must not have switched the group off. Anything that
    fails a gate is recorded in the coverage report rather than silently dropped.
    """
    langs: Counter = ctx["langs"]
    markers: Dict[str, List[str]] = ctx["markers"]
    plan: List[Dict[str, Any]] = []
    q = shlex.quote
    have = tool_registry.have
    binary = tool_registry.binary_for

    def add(tool: str, command: str, report: str, timeout: int = _TOOL_TIMEOUT,
            weight: int = 1) -> None:
        plan.append({"tool": tool, "command": command, "report": report,
                     "timeout": timeout, "weight": weight})

    def rep(name: str) -> str:
        return os.path.join(out_dir, f"{name}.json")

    code_langs = {e for e in langs if e not in _IAC_ONLY_EXT}

    def has(*names: str) -> bool:
        """True when the repo carries any of these build-system marker files."""
        return any(n in markers for n in names)

    # --- semgrep/opengrep: union of config packs for all detected languages ---
    if have("semgrep"):
        configs: List[str] = []
        for ext in langs:
            configs += _LANG_MAP[ext][0]
        configs = list(dict.fromkeys(configs))
        if configs:
            engine = resolve_grep_engine()
            excl = " ".join(f"--exclude {q(d)}" for d in sorted(_SKIP_DIRS))
            cfg = " ".join(f"--config {q(c)}" for c in configs)
            jobs, mem = _grep_jobs_mem()
            add("semgrep",
                f"{engine} scan {cfg} --jobs {jobs} --max-memory {mem} "
                f"--timeout 10 --timeout-threshold 3 --metrics=off {excl} "
                f"--json --output={q(rep('semgrep'))} {q(dest)}",
                rep("semgrep"), _SEMGREP_TIMEOUT, weight=jobs)

    # --- per-language SAST ---
    if ".py" in langs and have("bandit"):
        # --severity-level medium drops B101 assert_used, which is ~95% of bandit's raw
        # output on any repo with a test suite: a test file is made of asserts, and bandit
        # flags every one at LOW severity. Measured on a real repo, 10,255 of 10,789 findings
        # were B101 and 10,719 sat under tests/ - the filter takes that repo to 26 findings
        # without losing anything MEDIUM or above.
        add("bandit",
            f"bandit -r {q(dest)} -f json -o {q(rep('bandit'))} -q --severity-level medium",
            rep("bandit"))

    if code_langs & {".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs"}:
        if have("nodejsscan"):
            njs = binary("nodejsscan")
            add("nodejsscan", f"{njs} --json -o {q(rep('nodejsscan'))} {q(dest)}",
                rep("nodejsscan"), weight=2)
        if have("eslint") and want.get("eslint", True):
            entry = _eslint_entry(dest, out_dir, rep("eslint"))
            if entry:
                plan.append(entry)

    if ".go" in langs and have("gosec") and want.get("gosec", True):
        # Contained by the per-scan memory cap; opt out with {"gosec": false}.
        add("gosec", f"cd {q(dest)} && gosec -fmt=json -out={q(rep('gosec'))} -no-fail ./...",
            rep("gosec"), weight=2)

    if ".rb" in langs and have("brakeman"):
        add("brakeman",
            f"brakeman -p {q(dest)} -f json -o {q(rep('brakeman'))} "
            f"--no-exit-on-warn --no-exit-on-error -q || true",
            rep("brakeman"))

    # bearer covers js/ts/ruby/java/php/go/python with dataflow + PII rules, so it
    # is the main independent second opinion against semgrep on those languages.
    if code_langs and have("bearer") and want.get("bearer", True):
        add("bearer",
            f"bearer scan {q(dest)} --format json --output {q(rep('bearer'))} "
            f"--quiet --exit-code 0 --disable-version-check || true",
            rep("bearer"), _SEMGREP_TIMEOUT, weight=2)

    # graudit is grep-grade: cheap, noisy on its own, useful purely as a
    # corroborating vote. Normalized at "low" severity for that reason.
    if code_langs and have("graudit") and want.get("graudit", True):
        add("graudit", f"graudit -z -c 0 {q(dest)} > {q(rep('graudit'))} 2>/dev/null || true",
            rep("graudit"), _FAST_TIMEOUT)

    # --- secrets: two independent detectors ---
    if want.get("secrets", True):
        if have("gitleaks"):
            add("gitleaks",
                f"gitleaks detect --source {q(dest)} --no-git --report-format json "
                f"--report-path {q(rep('gitleaks'))} --exit-code 0",
                rep("gitleaks"))
        if have("trufflehog"):
            # trufflehog verifies candidates against live services, so its hits
            # promote a gitleaks match from "looks like a key" to "is a key".
            add("trufflehog",
                f"trufflehog filesystem {q(dest)} --json --no-update "
                f"> {q(rep('trufflehog'))} 2>/dev/null || true",
                rep("trufflehog"), weight=2)

    # --- dependencies: every ecosystem scanner that has a manifest to read ---
    if want.get("deps", True):
        if have("trivy"):
            add("trivy",
                f"trivy fs --scanners vuln,secret,misconfig --quiet --format json "
                f"--output {q(rep('trivy'))} --no-progress {q(dest)}",
                rep("trivy"), weight=2)
        if have("osv-scanner"):
            add("osv-scanner",
                f"osv-scanner --format json --output {q(rep('osv-scanner'))} "
                f"-r {q(dest)} || true",
                rep("osv-scanner"))
        for req in ctx["req_files"][:1]:
            if have("safety"):
                add("safety",
                    f"safety check -r {q(req)} --json --output {q(rep('safety'))} || true",
                    rep("safety"), _FAST_TIMEOUT)
            if have("pip-audit"):
                add("pip-audit",
                    f"pip-audit -r {q(req)} -f json -o {q(rep('pip-audit'))} || true",
                    rep("pip-audit"), _FAST_TIMEOUT)
        for npm_dir in ctx["npm_dirs"][:1]:
            if have("npm"):
                add("npm-audit",
                    f"cd {q(npm_dir)} && npm audit --json > {q(rep('npm-audit'))} 2>/dev/null || true",
                    rep("npm-audit"), _FAST_TIMEOUT)
        if has("pom.xml", "build.gradle", "build.gradle.kts") and have("dependency-check"):
            dc = binary("dependency-check")
            # --noupdate: the NVD feed refresh takes minutes and dominates the
            # scan; trivy/osv already cover freshness across the fleet.
            add("dependency-check",
                f"{dc} --scan {q(dest)} --format JSON --out {q(out_dir)} "
                f"--noupdate --disableAssembly --prettyPrint || true",
                os.path.join(out_dir, "dependency-check-report.json"),
                _SEMGREP_TIMEOUT, weight=2)
        if have("snyk") and want.get("snyk", False):
            # Off by default: needs an authenticated account, and an unauthed run
            # fails slowly on every repo in a fleet scan.
            add("snyk",
                f"cd {q(dest)} && snyk test --json > {q(rep('snyk'))} 2>/dev/null || true",
                rep("snyk"), _FAST_TIMEOUT)

    # --- IaC / containers ---
    if want.get("iac", True):
        iac_present = (".tf" in langs or has("Dockerfile", "docker-compose.yml",
                                             "docker-compose.yaml")
                       or ".yaml" in langs or ".yml" in langs)
        if iac_present and have("checkov"):
            add("checkov",
                f"checkov -d {q(dest)} -o json --quiet --compact --soft-fail "
                f"> {q(rep('checkov'))} 2>/dev/null || true",
                rep("checkov"), _TOOL_TIMEOUT, weight=2)
        if ".tf" in langs and have("tfsec"):
            tf = binary("tfsec")
            cmd = (f"tfsec {q(dest)} --format json --out {q(rep('tfsec'))} --soft-fail"
                   if tf == "tfsec" else
                   f"trivy config --format json --output {q(rep('tfsec'))} --quiet {q(dest)}")
            add("tfsec", f"{cmd} || true", rep("tfsec"), _FAST_TIMEOUT)

    return plan


def _coverage(ctx: Dict[str, Any], plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What ran, what was skipped, and why — so gaps are visible, not silent."""
    avail = tool_registry.availability()
    planned = {p["tool"] for p in plan}
    # "semgrep" in the plan may be the opengrep binary; report the engine actually used.
    return {
        "tools_planned": sorted(planned),
        "tools_installed": sorted(k for k, v in avail.items() if v),
        "tools_missing": sorted(k for k, v in avail.items() if not v),
        "engine": resolve_grep_engine(),
        "markers_found": sorted(ctx["markers"].keys()),
    }


def register(app: Flask) -> None:
    @app.route("/api/repo-scan", methods=["POST"])
    def repo_scan():
        try:
            params = request.json or {}
            url = (params.get("url") or "").strip()
            path = (params.get("path") or "").strip()
            if not url and not path:
                return jsonify({"error": "provide either 'path' (a local/mounted repo dir) or 'url' (git https URL)"}), 400

            # Reports are published to an allowed mount so the user can read them.
            mount_base = validate_scan_target(params.get("base_dir") or _default_base_dir())
            # Everything is scanned on fast local disk; only the small JSON reports
            # get copied back to the mount.
            base_dir = REPO_SCAN_LOCAL_DIR
            os.makedirs(base_dir, exist_ok=True)

            want = {
                "secrets":  params.get("secrets", True),
                "deps":     params.get("deps", True),
                "iac":      params.get("iac", True),
                "gosec":    params.get("gosec", True),
                "bearer":   params.get("bearer", True),
                "graudit":  params.get("graudit", True),
                "eslint":   params.get("eslint", True),
                "snyk":     params.get("snyk", False),
            }
            stage_mode = str(params.get("stage", "auto")).lower()
            if stage_mode not in ("auto", "always", "never"):
                stage_mode = "auto"

            if path:
                # Local-path mode: validate the path is under an allowed mount,
                # then stage to local disk (or scan in place) and scan there.
                src = validate_scan_target(path)
                cloned = _stage_local(src, base_dir, stage_mode)
                origin = {"path": cloned.get("source_path", src)}
            else:
                if not _URL_RE.match(url):
                    return jsonify({"error": "url must be an https URL on github/gitlab/bitbucket/googlesource"}), 400
                ref = params.get("ref", "")
                if ref and re.search(r"[^A-Za-z0-9._/-]", ref):
                    return jsonify({"error": "invalid ref"}), 400
                cloned = _clone(url, ref, base_dir)
                origin = {"url": url}

            dest = cloned["dest"]
            # Reports live OUTSIDE the scanned tree, always. With reports inside it,
            # the secret scanners read the other tools' output and re-report every
            # finding as a fresh secret in the repo — each tool added makes the
            # false positives worse.
            out_dir = os.path.join(base_dir, cloned["name"] + "_sast_reports")
            shutil.rmtree(out_dir, ignore_errors=True)
            os.makedirs(out_dir, exist_ok=True)

            ctx = _detect_context(dest)
            langs = ctx["langs"]
            if not langs and not (want["secrets"] or want["deps"]):
                return jsonify({"error": "no supported source files detected", "repo": cloned}), 200

            plan = _build_plan(ctx, dest, out_dir, want)
            results = _run_plan_parallel(plan)

            # Cross-check: normalize every report into one schema and cluster the
            # findings the tools agree on. Never allowed to fail the scan.
            try:
                xcheck = correlate.cross_check(results, dest)
            except Exception as e:
                logger.error(f"repo-scan: cross-check failed: {e}")
                xcheck = {"error": str(e)}

            published_dir = _publish_reports(out_dir, mount_base, cloned["name"])
            if isinstance(xcheck, dict) and "findings" in xcheck:
                try:
                    with open(os.path.join(published_dir, "cross_check.json"), "w") as fh:
                        json.dump(xcheck, fh, indent=2)
                except Exception as e:
                    logger.warning(f"repo-scan: could not write cross_check.json: {e}")

            total = sum(r.get("findings") or 0 for r in results)
            top_n = max(1, min(int(params.get("top_n", 25) or 25), 200))
            top = (xcheck.get("findings") or [])[:top_n] if isinstance(xcheck, dict) else []
            summary = {k: v for k, v in xcheck.items() if k != "findings"} if isinstance(xcheck, dict) else {}

            return jsonify({
                "repo": cloned,
                **origin,
                "languages": {k: v for k, v in langs.most_common()},
                "output_dir": published_dir,
                "scanned_on": "local-disk" if cloned.get("staged", True) else "in-place",
                "tools_run": [r["tool"] for r in results],
                "total_findings": total,
                "results": results,
                "coverage": _coverage(ctx, plan),
                "cross_check": summary,
                "top_findings": top,
                "note": ("raw per-tool counts are in results[]; cross_check collapses them "
                         "into unique findings ranked by how many independent tools agree. "
                         "Triage 'corroborated' and 'confirmed' first."),
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except subprocess.TimeoutExpired:
            return jsonify({"error": "git clone timed out"}), 504
        except Exception as e:
            logger.error(f"repo-scan: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
