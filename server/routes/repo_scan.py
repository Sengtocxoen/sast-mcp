"""
Repo-scan endpoint: POST a Git URL -> shallow clone + language auto-detect +
run a language-appropriate SAST tool matrix + write JSON reports + return a
parsed finding summary.

One call replaces the manual clone -> pick-tools -> launch -> collect loop.
All tools run through core.execute_command, so they inherit the per-scan memory
cap and the enhanced PATH automatically.
"""
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import traceback
from collections import Counter
from typing import Any, Dict, List

from flask import Flask, request, jsonify

from config import ALLOWED_MOUNTS, MOUNT_POINT
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

# Source extensions -> (semgrep config packs, extra per-language tool key).
_LANG_MAP = {
    ".go":   (["p/golang", "p/security-audit"], None),
    ".py":   (["p/python", "p/security-audit"], "bandit"),
    ".js":   (["p/javascript", "p/security-audit"], "nodejsscan"),
    ".jsx":  (["p/javascript"], "nodejsscan"),
    ".ts":   (["p/typescript", "p/javascript"], "nodejsscan"),
    ".tsx":  (["p/typescript"], "nodejsscan"),
    ".rb":   (["p/ruby", "p/security-audit"], None),
    ".java": (["p/java", "p/security-audit"], None),
    ".php":  (["p/php"], None),
    ".c":    (["p/c"], None),
    ".cpp":  (["p/cpp"], None),
    ".cs":   (["p/csharp"], None),
}
_SKIP_DIRS = {".git", "vendor", "node_modules", "dist", "build", "testdata", "third_party"}
_CLONE_TIMEOUT = 300
# Clone + scan here (local disk) by default. Scanning off the vmhgfs share is
# ~100x slower due to per-file fuse round-trips; only the small JSON reports
# get copied back to the mount for the user.
REPO_SCAN_LOCAL_DIR = os.environ.get("REPO_SCAN_LOCAL_DIR", "/var/tmp/sast-repos")
_SEMGREP_TIMEOUT = 1800
_TOOL_TIMEOUT = 900


def _default_base_dir() -> str:
    """Where to clone by default: a repo-scans/ dir under an allowed mount."""
    root = ALLOWED_MOUNTS[0] if ALLOWED_MOUNTS else MOUNT_POINT
    return os.path.join(root, "repo-scans")


def _clone(url: str, ref: str, base_dir: str) -> Dict[str, Any]:
    """Shallow-clone url into base_dir/<owner-repo>. Injection-safe (list args)."""
    m = re.match(r"^https://[^/]+/(.+?)(?:\.git)?$", url)
    slug = m.group(1) if m else url
    name = _NAME_RE.sub("-", slug.strip("/")) or "repo"
    dest = os.path.join(base_dir, name)
    os.makedirs(base_dir, exist_ok=True)
    if os.path.isdir(os.path.join(dest, ".git")):
        return {"dest": dest, "name": name, "reused": True}
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, dest]
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=_CLONE_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {proc.stdout[-500:]}")
    return {"dest": dest, "name": name, "reused": False}


def _detect_languages(root: str) -> Counter:
    counts: Counter = Counter()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith("_test.go") or fn.endswith((".test.ts", ".spec.ts", ".d.ts")):
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext in _LANG_MAP:
                counts[ext] += 1
    return counts


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
    if tool == "gitleaks":
        return {"findings": len(d) if isinstance(d, list) else 0}
    if tool == "trivy":
        n = sum(len(r.get("Vulnerabilities", []) or []) for r in (d.get("Results") or []))
        return {"findings": n}
    return {"findings": None}


def _run_tool(tool: str, command: str, report: str, timeout: int) -> Dict[str, Any]:
    res = execute_command(command, timeout=timeout)
    out = {"tool": tool, "report": report, "return_code": res.get("return_code"),
           "timed_out": res.get("timed_out", False)}
    if os.path.exists(report):
        out.update(_parse_findings(report, tool))
    else:
        out["error"] = (res.get("stderr") or res.get("stdout") or "no report written")[:300]
    return out


def _grep_jobs_mem():
    """Native multi-core sizing: jobs*per-worker-mem stays under ~80% of the cap."""
    from config import MAX_PROCESS_WORKERS, SCAN_MEMORY_MAX_MB
    per = 512
    jobs = max(1, min(os.cpu_count() or 4, MAX_PROCESS_WORKERS))
    jobs = max(1, min(jobs, int(SCAN_MEMORY_MAX_MB * 0.8) // per))
    return jobs, per


def _publish_reports(out_dir: str, mount_base: str, name: str) -> str:
    """Copy the JSON reports from local scratch to the mount so the user can read them."""
    dest = os.path.join(mount_base, name, "_sast_reports")
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copytree(out_dir, dest, dirs_exist_ok=True)
        return dest
    except Exception as e:
        logger.warning(f"repo-scan: could not publish reports to mount: {e}")
        return out_dir


def _build_plan(langs: Counter, dest: str, out_dir: str, want: Dict[str, bool]) -> List[Dict[str, Any]]:
    """Assemble the tool command list for the detected languages."""
    plan: List[Dict[str, Any]] = []
    q = shlex.quote

    # semgrep: union of config packs for all detected languages (one pass).
    configs: List[str] = []
    extra_tools = set()
    for ext, n in langs.items():
        packs, extra = _LANG_MAP[ext]
        configs += packs
        if extra:
            extra_tools.add(extra)
    configs = list(dict.fromkeys(configs))  # dedupe, keep order
    if configs:
        engine = resolve_grep_engine()
        rep = os.path.join(out_dir, "semgrep.json")
        cfg = " ".join(f"--config {q(c)}" for c in configs)
        excl = " ".join(f"--exclude {q(d)}" for d in sorted(_SKIP_DIRS))
        jobs, mem = _grep_jobs_mem()
        cmd = (f"{engine} scan {cfg} --jobs {jobs} --max-memory {mem} "
               f"--timeout 10 --timeout-threshold 3 --metrics=off {excl} "
               f"--json --output={q(rep)} {q(dest)}")
        plan.append({"tool": "semgrep", "command": cmd, "report": rep, "timeout": _SEMGREP_TIMEOUT})

    if "bandit" in extra_tools:
        rep = os.path.join(out_dir, "bandit.json")
        plan.append({"tool": "bandit", "report": rep, "timeout": _TOOL_TIMEOUT,
                     "command": f"bandit -r {q(dest)} -f json -o {q(rep)}"})
    if "nodejsscan" in extra_tools:
        rep = os.path.join(out_dir, "nodejsscan.json")
        plan.append({"tool": "nodejsscan", "report": rep, "timeout": _TOOL_TIMEOUT,
                     "command": f"njsscan --json -o {q(rep)} {q(dest)}"})
    if want.get("secrets", True):
        rep = os.path.join(out_dir, "gitleaks.json")
        plan.append({"tool": "gitleaks", "report": rep, "timeout": _TOOL_TIMEOUT,
                     "command": f"gitleaks detect --source {q(dest)} --no-git --report-format json --report-path {q(rep)} --exit-code 0"})
    if want.get("deps", True):
        rep = os.path.join(out_dir, "trivy.json")
        plan.append({"tool": "trivy", "report": rep, "timeout": _TOOL_TIMEOUT,
                     "command": f"trivy fs --scanners vuln --quiet --format json --output {q(rep)} {q(dest)}"})
    if want.get("gosec", False) and ".go" in langs:
        # opt-in: gosec type-loads the whole module and can be memory-hungry
        # (contained by the per-scan cap, but often yields nothing on big modules).
        rep = os.path.join(out_dir, "gosec.json")
        plan.append({"tool": "gosec", "report": rep, "timeout": _TOOL_TIMEOUT,
                     "command": f"cd {q(dest)} && gosec -fmt=json -out={q(rep)} -no-fail ./... "})
    return plan


def register(app: Flask) -> None:
    @app.route("/api/repo-scan", methods=["POST"])
    def repo_scan():
        try:
            params = request.json or {}
            url = (params.get("url") or "").strip()
            if not _URL_RE.match(url):
                return jsonify({"error": "url must be an https URL on github/gitlab/bitbucket/googlesource"}), 400
            ref = params.get("ref", "")
            if ref and re.search(r"[^A-Za-z0-9._/-]", ref):
                return jsonify({"error": "invalid ref"}), 400

            local = params.get("local", True)
            # Reports are published here (validated to an allowed mount).
            mount_base = validate_scan_target(params.get("base_dir") or _default_base_dir())
            # Clone+scan on fast local disk by default; publish reports to the mount.
            base_dir = REPO_SCAN_LOCAL_DIR if local else mount_base
            os.makedirs(base_dir, exist_ok=True)

            want = {
                "secrets": params.get("secrets", True),
                "deps": params.get("deps", True),
                "gosec": params.get("gosec", False),
            }

            cloned = _clone(url, ref, base_dir)
            dest = cloned["dest"]
            out_dir = os.path.join(dest, "_sast_reports")
            os.makedirs(out_dir, exist_ok=True)

            langs = _detect_languages(dest)
            if not langs and not (want["secrets"] or want["deps"]):
                return jsonify({"error": "no supported source files detected", "repo": cloned}), 200

            plan = _build_plan(langs, dest, out_dir, want)
            results = [_run_tool(p["tool"], p["command"], p["report"], p["timeout"]) for p in plan]

            published_dir = _publish_reports(out_dir, mount_base, cloned["name"]) if local else out_dir
            total = sum(r.get("findings") or 0 for r in results)
            return jsonify({
                "repo": cloned,
                "url": url,
                "languages": {k: v for k, v in langs.most_common()},
                "output_dir": published_dir,
                "scanned_on": "local-disk" if local else "mount",
                "tools_run": [r["tool"] for r in results],
                "total_findings": total,
                "results": results,
                "note": "counts are raw tool output; triage for false positives before acting",
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except subprocess.TimeoutExpired:
            return jsonify({"error": "git clone timed out"}), 504
        except Exception as e:
            logger.error(f"repo-scan: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
