"""
Results API + scan trigger — dashboard integration layer.

Current flow (manual):
  Kali runs run_scans.sh → JSON files land in SAST_RESULTS_DIR/<project>/
  Dashboard reads those files directly via Node.js sast-reader.ts

Future flow (API-driven, when you're ready):
  Dashboard calls POST /api/scan/trigger  → kicks off scan as background job
  Dashboard calls GET  /api/results       → same structured data, no file I/O needed

The /api/results response shape is intentionally identical to what sast-reader.ts
currently builds from the JSON files, so switching the dashboard to API mode is a
one-line change (replace the fetch path).
"""
import json
import logging
import os
import shlex
import subprocess
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, request, jsonify

from config import SAST_RESULTS_DIR, RESOLA_SRC_DIR, BANDIT_TIMEOUT, OPENGREP_TIMEOUT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Project registry — mirrors KNOWN_PROJECTS in sast-reader.ts
# ---------------------------------------------------------------------------
KNOWN_PROJECTS: List[Dict[str, str]] = [
    {"name": "deca-ad-api",          "group": "Deca", "subdir": "Deca"},
    {"name": "deca-agents-exp",      "group": "Deca", "subdir": "Deca"},
    {"name": "deca-ai-gateway",      "group": "Deca", "subdir": "Deca"},
    {"name": "deca-ai-studio",       "group": "Deca", "subdir": "Deca"},
    {"name": "deca-ai-widgets-api",  "group": "Deca", "subdir": "Deca"},
    {"name": "deca-ai-widgets-app",  "group": "Deca", "subdir": "Deca"},
    {"name": "deca-api-gateway",     "group": "Deca", "subdir": "Deca"},
    {"name": "deca-apps",            "group": "Deca", "subdir": "Deca"},
    {"name": "deca-chatbot-api",     "group": "Deca", "subdir": "Deca"},
    {"name": "deca-chatbox-api",     "group": "Deca", "subdir": "Deca"},
    {"name": "deca-crm-api",         "group": "Deca", "subdir": "Deca"},
    {"name": "deca-custom-nmcm",     "group": "Deca", "subdir": "Deca"},
    {"name": "deca-data",            "group": "Deca", "subdir": "Deca"},
    {"name": "deca-forms-api",       "group": "Deca", "subdir": "Deca"},
    {"name": "deca-kb-api",          "group": "Deca", "subdir": "Deca"},
    {"name": "deca-livechat-api",    "group": "Deca", "subdir": "Deca"},
    {"name": "deca-pages-api",       "group": "Deca", "subdir": "Deca"},
    {"name": "deca-tables-api",      "group": "Deca", "subdir": "Deca"},
    {"name": "deca-uam-api",         "group": "Deca", "subdir": "Deca"},
    {"name": "deca-uam-app",         "group": "Deca", "subdir": "Deca"},
    {"name": "infra",                "group": "Deca", "subdir": "Deca"},
    {"name": "aig",                  "group": "IPS",  "subdir": "IPS"},
    {"name": "code",                 "group": "IPS",  "subdir": "IPS"},
    {"name": "custom-domains",       "group": "IPS",  "subdir": "IPS"},
    {"name": "deca-flags",           "group": "IPS",  "subdir": "IPS"},
    {"name": "fss",                  "group": "IPS",  "subdir": "IPS"},
    {"name": "jss",                  "group": "IPS",  "subdir": "IPS"},
    {"name": "mp-api",               "group": "IPS",  "subdir": "IPS"},
    {"name": "mp-liff",              "group": "IPS",  "subdir": "IPS"},
    {"name": "mp-ncg",               "group": "IPS",  "subdir": "IPS"},
    {"name": "mp-opt-out",           "group": "IPS",  "subdir": "IPS"},
    {"name": "ocs",                  "group": "IPS",  "subdir": "IPS"},
    {"name": "oss",                  "group": "IPS",  "subdir": "IPS"},
    {"name": "outgoing-webhook",     "group": "IPS",  "subdir": "IPS"},
    {"name": "rebot",                "group": "IPS",  "subdir": "IPS"},
    {"name": "rebot-etl",            "group": "IPS",  "subdir": "IPS"},
    {"name": "rebot-liff",           "group": "IPS",  "subdir": "IPS"},
    {"name": "uss",                  "group": "IPS",  "subdir": "IPS"},
]

_PROJECT_MAP = {p["name"]: p for p in KNOWN_PROJECTS}

# Projects that have Python code and should also run bandit
BANDIT_PROJECTS = {
    "deca-ai-gateway", "deca-forms-api", "deca-kb-api", "deca-pages-api",
    "mp-api", "rebot", "rebot-etl",
}

# Noise rule fragments — kept in sync with sast-reader.ts NOISE_RULE_FRAGMENTS
NOISE_RULE_FRAGMENTS = [
    "missing-integrity", "detect-non-literal-regexp", "avoid-v-html",
    "template-explicit-unescape", "prototype-pollution-loop", "plaintext-http-link",
    "no-new-privileges", "writable-filesystem-service", "csrf-exempt",
    "no-csrf-token", "django-using-request-post-after-is-valid",
    "direct-use-of-httpresponse", "logger-credential-disclosure", "missing-user",
]


def _is_noisy(rule_id: str) -> bool:
    low = rule_id.lower()
    return any(frag in low for frag in NOISE_RULE_FRAGMENTS)


# ---------------------------------------------------------------------------
# Scan trigger: background multi-project scan
# ---------------------------------------------------------------------------

# Simple in-process registry for bulk scan jobs
# (not the full JobManager — these are multi-project orchestration jobs)
_bulk_scans: Dict[str, Dict[str, Any]] = {}
_bulk_lock = threading.Lock()


# Max parallel project scans — semgrep is CPU-heavy; 4 is safe on most Kali VMs.
# Override with PARALLEL_PROJECT_SCANS env var.
_PARALLEL_PROJECT_SCANS = int(os.environ.get("PARALLEL_PROJECT_SCANS", 4))


def _scan_one_project(
    proj: Dict[str, str],
    tools: List[str],
    semgrep_config: str,
) -> tuple[str, Dict[str, Any], Optional[str]]:
    """Scan a single project; returns (name, proj_results, error_msg|None)."""
    name = proj["name"]
    src_path = os.path.join(RESOLA_SRC_DIR, proj["subdir"], name)
    out_dir = os.path.join(SAST_RESULTS_DIR, name)

    if not os.path.isdir(src_path):
        return name, {}, f"Source directory not found: {src_path}"

    os.makedirs(out_dir, exist_ok=True)
    proj_results: Dict[str, Any] = {}

    if "semgrep" in tools:
        configs = " ".join(f"--config={shlex.quote(c)}" for c in semgrep_config.split())
        out_file = shlex.quote(os.path.join(out_dir, "semgrep.json"))
        err_file = shlex.quote(os.path.join(out_dir, "semgrep.err"))
        cmd = f"semgrep scan {configs} --json --output={out_file} {shlex.quote(src_path)} 2>{err_file}"
        logger.info(f"[scan-trigger] semgrep {name}")
        try:
            proc = subprocess.run(
                cmd, shell=True, timeout=OPENGREP_TIMEOUT,
                capture_output=True, text=True,
                preexec_fn=os.setsid,
            )
            proj_results["semgrep"] = {
                "exit_code": proc.returncode,
                # rc=0: no findings, rc=1: findings found — both are success
                "ok": proc.returncode in (0, 1),
            }
        except subprocess.TimeoutExpired:
            proj_results["semgrep"] = {"exit_code": -1, "ok": False, "error": "timeout"}
            logger.warning(f"[scan-trigger] semgrep {name} timed out")
        except Exception as e:
            proj_results["semgrep"] = {"exit_code": -1, "ok": False, "error": str(e)}
            logger.error(f"[scan-trigger] semgrep {name} error: {e}")

    if "bandit" in tools and name in BANDIT_PROJECTS:
        out_file = shlex.quote(os.path.join(out_dir, "bandit.json"))
        cmd = f"bandit -r {shlex.quote(src_path)} -f json -o {out_file} 2>/dev/null"
        logger.info(f"[scan-trigger] bandit {name}")
        try:
            proc = subprocess.run(
                cmd, shell=True, timeout=BANDIT_TIMEOUT,
                capture_output=True, text=True,
                preexec_fn=os.setsid,
            )
            proj_results["bandit"] = {
                "exit_code": proc.returncode,
                "ok": proc.returncode in (0, 1),
            }
        except subprocess.TimeoutExpired:
            proj_results["bandit"] = {"exit_code": -1, "ok": False, "error": "timeout"}
        except Exception as e:
            proj_results["bandit"] = {"exit_code": -1, "ok": False, "error": str(e)}

    return name, proj_results, None


def _run_project_scan(scan_id: str, projects: List[Dict], tools: List[str], semgrep_config: str) -> None:
    """Run semgrep + bandit for a list of projects in parallel and update _bulk_scans status."""
    with _bulk_lock:
        _bulk_scans[scan_id]["status"] = "running"
        _bulk_scans[scan_id]["started_at"] = datetime.now().isoformat()

    results: Dict[str, Any] = {}
    errors: Dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=_PARALLEL_PROJECT_SCANS) as pool:
        futures = {
            pool.submit(_scan_one_project, proj, tools, semgrep_config): proj["name"]
            for proj in projects
        }
        for future in as_completed(futures):
            try:
                name, proj_results, err = future.result()
            except Exception as e:
                name = futures[future]
                proj_results = {}
                err = str(e)

            if err:
                errors[name] = err
                logger.warning(f"[scan-trigger] {name}: {err}")
            else:
                results[name] = proj_results

            with _bulk_lock:
                completed = sum(
                    1 for v in results.values()
                    if any(r.get("ok") for r in v.values())
                )
                _bulk_scans[scan_id]["completed_count"] = completed
                _bulk_scans[scan_id]["total_count"] = len(projects)

    with _bulk_lock:
        _bulk_scans[scan_id]["status"] = "completed"
        _bulk_scans[scan_id]["completed_at"] = datetime.now().isoformat()
        _bulk_scans[scan_id]["results"] = results
        _bulk_scans[scan_id]["errors"] = errors


# ---------------------------------------------------------------------------
# Results reader — mirrors sast-reader.ts readSastResults()
# ---------------------------------------------------------------------------

def _read_semgrep(project_dir: str):
    path = os.path.join(project_dir, "semgrep.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return [], None

    scanned_at = None
    try:
        scanned_at = datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
    except OSError:
        pass

    findings = []
    for r in (data.get("results") or []):
        sev_raw: str = r.get("extra", {}).get("severity") or r.get("severity") or "WARNING"
        sev_raw = sev_raw.upper()
        sev = "ERROR" if sev_raw == "ERROR" else ("INFO" if sev_raw == "INFO" else "WARNING")
        rule_id = r.get("check_id") or ""
        findings.append({
            "tool": "semgrep",
            "ruleId": rule_id,
            "severity": sev,
            "severityRaw": sev_raw,
            "file": r.get("path") or "",
            "line": (r.get("start") or {}).get("line") or 0,
            "message": (r.get("extra") or {}).get("message") or r.get("message") or "",
            "snippet": ((r.get("extra") or {}).get("lines") or "").strip() or None,
            "isNoise": _is_noisy(rule_id),
        })
    return findings, scanned_at


def _read_bandit(project_dir: str):
    path = os.path.join(project_dir, "bandit.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    findings = []
    for r in (data.get("results") or []):
        sev_raw: str = (r.get("issue_severity") or "MEDIUM").upper()
        sev = "ERROR" if sev_raw == "HIGH" else ("INFO" if sev_raw == "LOW" else "WARNING")
        rule_id = r.get("test_id") or ""
        findings.append({
            "tool": "bandit",
            "ruleId": rule_id,
            "severity": sev,
            "severityRaw": sev_raw,
            "file": r.get("filename") or "",
            "line": r.get("line_number") or 0,
            "message": r.get("issue_text") or "",
            "snippet": None,
            "isNoise": _is_noisy(rule_id),
        })
    return findings


def _build_project_result(proj: Dict[str, str]) -> Dict[str, Any]:
    name = proj["name"]
    group = proj["group"]
    project_dir = os.path.join(SAST_RESULTS_DIR, name)

    if not os.path.isdir(project_dir):
        return {
            "name": name, "group": group, "findings": [],
            "sgErr": 0, "sgWarn": 0, "bnHigh": 0, "bnMed": 0,
            "total": 0, "signalCount": 0, "noiseCount": 0,
            "scannedAt": None, "missing": True,
        }

    sg_findings, scanned_at = _read_semgrep(project_dir)
    bn_findings = _read_bandit(project_dir)
    all_findings = sg_findings + bn_findings

    sg_err  = sum(1 for f in sg_findings if f["severity"] == "ERROR")
    sg_warn = sum(1 for f in sg_findings if f["severity"] == "WARNING")
    bn_high = sum(1 for f in bn_findings if f["severityRaw"] == "HIGH")
    bn_med  = sum(1 for f in bn_findings if f["severityRaw"] == "MEDIUM")
    noise   = sum(1 for f in all_findings if f["isNoise"])

    return {
        "name": name, "group": group, "findings": all_findings,
        "sgErr": sg_err, "sgWarn": sg_warn, "bnHigh": bn_high, "bnMed": bn_med,
        "total": len(all_findings),
        "signalCount": len(all_findings) - noise,
        "noiseCount": noise,
        "scannedAt": scanned_at, "missing": False,
    }


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def register(app: Flask) -> None:

    # ── GET /api/results ────────────────────────────────────────────────────
    # Full report for all projects — same structure as sast-reader.ts readSastResults()
    @app.route("/api/results", methods=["GET"])
    def get_all_results():
        try:
            projects = [_build_project_result(p) for p in KNOWN_PROJECTS]
            projects.sort(key=lambda p: p["total"], reverse=True)
            return jsonify({
                "projects": projects,
                "totalFindings": sum(p["total"] for p in projects),
                "totalSignal": sum(p["signalCount"] for p in projects),
                "totalNoise": sum(p["noiseCount"] for p in projects),
                "scannedAt": datetime.now().isoformat(),
                "resultsDir": SAST_RESULTS_DIR,
            })
        except Exception as e:
            logger.error(f"get_all_results: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    # ── GET /api/results/projects/<name> ────────────────────────────────────
    # Single-project result
    @app.route("/api/results/projects/<string:name>", methods=["GET"])
    def get_project_result(name: str):
        try:
            proj = _PROJECT_MAP.get(name)
            if not proj:
                return jsonify({"error": f"Unknown project: {name}"}), 404
            result = _build_project_result(proj)
            return jsonify({"success": True, "project": result})
        except Exception as e:
            logger.error(f"get_project_result({name}): {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    # ── GET /api/results/projects ────────────────────────────────────────────
    # List projects with basic metadata (no findings array — faster for sidebar)
    @app.route("/api/results/projects", methods=["GET"])
    def list_projects():
        try:
            summary = []
            for proj in KNOWN_PROJECTS:
                project_dir = os.path.join(SAST_RESULTS_DIR, proj["name"])
                has_semgrep = os.path.isfile(os.path.join(project_dir, "semgrep.json"))
                has_bandit  = os.path.isfile(os.path.join(project_dir, "bandit.json"))
                scanned_at = None
                if has_semgrep:
                    try:
                        scanned_at = datetime.fromtimestamp(
                            os.path.getmtime(os.path.join(project_dir, "semgrep.json"))
                        ).isoformat()
                    except OSError:
                        pass
                summary.append({
                    "name": proj["name"],
                    "group": proj["group"],
                    "hasSemgrep": has_semgrep,
                    "hasBandit": has_bandit,
                    "scannedAt": scanned_at,
                    "missing": not (has_semgrep or has_bandit),
                })
            return jsonify({"success": True, "projects": summary, "resultsDir": SAST_RESULTS_DIR})
        except Exception as e:
            logger.error(f"list_projects: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    # ── POST /api/scan/trigger ───────────────────────────────────────────────
    # Trigger a fresh scan for one project, a list of projects, or all.
    # Returns immediately with a scan_id; poll GET /api/scan/trigger/<scan_id>
    #
    # Body:
    #   { "projects": ["all"] | ["deca-ai-gateway", "rebot"],
    #     "tools": ["semgrep", "bandit"],          // optional, default: both
    #     "semgrep_config": "p/secrets p/security-audit"  // optional
    #   }
    @app.route("/api/scan/trigger", methods=["POST"])
    def trigger_scan():
        try:
            body = request.json or {}
            requested = body.get("projects", ["all"])
            tools = body.get("tools", ["semgrep", "bandit"])
            semgrep_config = body.get("semgrep_config", "p/secrets p/security-audit")

            # Validate tools
            valid_tools = {"semgrep", "bandit"}
            unknown_tools = [t for t in tools if t not in valid_tools]
            if unknown_tools:
                return jsonify({"error": f"Unknown tools: {unknown_tools}. Valid: {list(valid_tools)}"}), 400

            # Resolve project list
            if "all" in requested:
                projects = list(KNOWN_PROJECTS)
            else:
                projects = []
                unknown = []
                for name in requested:
                    p = _PROJECT_MAP.get(name)
                    if p:
                        projects.append(p)
                    else:
                        unknown.append(name)
                if unknown:
                    return jsonify({"error": f"Unknown projects: {unknown}"}), 400

            import uuid
            scan_id = str(uuid.uuid4())[:12]
            with _bulk_lock:
                _bulk_scans[scan_id] = {
                    "scan_id": scan_id,
                    "status": "pending",
                    "projects": [p["name"] for p in projects],
                    "tools": tools,
                    "semgrep_config": semgrep_config,
                    "total_count": len(projects),
                    "completed_count": 0,
                    "created_at": datetime.now().isoformat(),
                    "started_at": None,
                    "completed_at": None,
                    "results": {},
                    "errors": {},
                }

            t = threading.Thread(
                target=_run_project_scan,
                args=(scan_id, projects, tools, semgrep_config),
                daemon=True,
            )
            t.start()

            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "message": f"Scan started for {len(projects)} project(s)",
                "projects": [p["name"] for p in projects],
                "tools": tools,
                "poll_url": f"/api/scan/trigger/{scan_id}",
            })
        except Exception as e:
            logger.error(f"trigger_scan: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    # ── GET /api/scan/trigger/<scan_id> ─────────────────────────────────────
    # Poll status of a triggered scan
    @app.route("/api/scan/trigger/<string:scan_id>", methods=["GET"])
    def get_scan_trigger_status(scan_id: str):
        try:
            with _bulk_lock:
                scan = _bulk_scans.get(scan_id)
            if not scan:
                return jsonify({"error": "Scan not found"}), 404

            # Don't include full findings in the status poll — keep it light
            status = {k: v for k, v in scan.items() if k != "results"}
            if scan["status"] == "completed":
                status["summary"] = {
                    name: {
                        "semgrep_ok": r.get("semgrep", {}).get("ok"),
                        "bandit_ok": r.get("bandit", {}).get("ok"),
                    }
                    for name, r in scan["results"].items()
                }
            return jsonify({"success": True, **status})
        except Exception as e:
            logger.error(f"get_scan_trigger_status: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
