"""
Utility routes: generic command, batch-scan-dirs, scan-project-structure,
scan-stats, mount introspection, and repo discovery.
"""
import fnmatch
import logging
import os
import shlex
from collections import Counter
from typing import Any, Dict

from flask import Flask, request, jsonify

from core import (execute_command, resolve_windows_path, to_client_path,
                  validate_scan_target, scan_stats_lock, scan_stats)
import pathmap
from config import (
    ALLOWED_MOUNTS,
    COMMAND_TIMEOUT,
    DEFAULT_PAGE_SIZE,
    SCAN_WAIT_TIMEOUT,
    MAX_PARALLEL_SCANS,
)

logger = logging.getLogger(__name__)

# Directories that are never a project of their own.
_REPO_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__",
                   ".venv", "venv", ".tox", ".idea", ".vscode", "target",
                   "$RECYCLE.BIN", "System Volume Information"}
# A directory holding one of these is a project even without a .git dir — which
# is the common case for a share that carries exported/vendored source.
_PROJECT_MARKERS = {"package.json", "go.mod", "requirements.txt", "pyproject.toml",
                    "pom.xml", "build.gradle", "Gemfile", "composer.json",
                    "Cargo.toml", "setup.py", "Makefile", "docker-compose.yml"}
_SRC_EXT = {".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".java", ".php",
            ".c", ".cc", ".cpp", ".cs", ".rs", ".kt", ".scala", ".swift", ".vue", ".tf"}
# Cap the per-repo sample: listing 134 repos must stay interactive, and the
# language mix is obvious long before every file is counted.
_SAMPLE_FILE_CAP = 400


def _looks_like_project(path: str) -> bool:
    try:
        return any(m in _PROJECT_MARKERS for m in os.listdir(path))
    except (PermissionError, OSError):
        return False


def _sample_languages(path: str) -> tuple:
    """(language counts, files sampled) from a bounded walk of the repo."""
    counts: Counter = Counter()
    seen = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in _REPO_SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in _SRC_EXT:
                counts[ext] += 1
                seen += 1
                if seen >= _SAMPLE_FILE_CAP:
                    return counts, seen
    return counts, seen


def _describe_repo(path: str, has_git: bool, include_git: bool) -> dict:
    counts, sampled = _sample_languages(path)
    info = {
        "name": os.path.basename(path.rstrip("/")),
        "path": to_client_path(path),
        "linux_path": path,
        "has_git": has_git,
        "source_files": sampled,
        "sampled": sampled >= _SAMPLE_FILE_CAP,
        "languages": {k: v for k, v in counts.most_common(6)},
    }
    if include_git and has_git:
        # One subprocess per repo — opt-in, because across 134 repos it is the
        # slowest part of an otherwise pure-filesystem listing.
        res = execute_command(
            f"git -C {shlex.quote(path)} log -1 --format=%H%x1f%cI%x1f%s "
            f"&& git -C {shlex.quote(path)} rev-parse --abbrev-ref HEAD",
            timeout=15)
        out = (res.get("stdout") or "").strip().split("\n")
        if out and "\x1f" in out[0]:
            sha, when, subject = out[0].split("\x1f", 2)
            info.update({"last_commit": sha[:12], "last_commit_at": when,
                         "last_commit_subject": subject[:120]})
        if len(out) > 1:
            info["branch"] = out[-1].strip()
    return info


# Dependency file patterns for scan-project-structure
DEPENDENCY_FILES = {
    "python": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock"],
    "nodejs": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "go": ["go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock"],
    "ruby": ["Gemfile", "Gemfile.lock", ".ruby-version"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties"],
    "php": ["composer.json", "composer.lock"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "dotnet": ["*.csproj", "*.fsproj", "*.vbproj", "packages.config", "*.sln"],
    "terraform": ["*.tf", "terraform.tfvars", "terraform.tfstate"],
    "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"],
    "kubernetes": ["*.yaml", "*.yml"],
    "config": [".env", ".env.example", "config.json", "config.yaml", "config.yml"],
}


def register(app: Flask) -> None:
    """Register utility routes on the Flask app."""

    @app.route("/api/command", methods=["POST"])
    def generic_command():
        try:
            params = request.json or {}
            command = params.get("command", "")
            cwd = params.get("cwd", None)
            timeout = params.get("timeout", COMMAND_TIMEOUT)

            if not command:
                return jsonify({"error": "Command parameter is required"}), 400

            result = execute_command(command, cwd=cwd, timeout=timeout)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in command endpoint: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/util/batch-scan-dirs", methods=["POST"])
    def batch_scan_dirs():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            max_depth = min(3, max(1, int(params.get("max_depth", 1))))
            min_files = int(params.get("min_files", 1))
            max_targets = min(50, int(params.get("max_targets", 20)))

            # Was gated on a literal "F:" drive letter, so a target on any other
            # mapped drive was passed through untranslated and then "did not exist".
            # resolve_windows_path is a no-op for paths it doesn't recognise.
            resolved_target = resolve_windows_path(target)

            if not os.path.exists(resolved_target):
                return jsonify({"error": f"Target path does not exist: {resolved_target}"}), 400
            if not os.path.isdir(resolved_target):
                return jsonify({"error": f"Target must be a directory: {resolved_target}"}), 400

            def count_files(path: str, current_depth: int = 0) -> int:
                try:
                    total = 0
                    for entry in os.scandir(path):
                        if entry.is_file(follow_symlinks=False):
                            total += 1
                        elif entry.is_dir(follow_symlinks=False) and current_depth < 2:
                            total += count_files(entry.path, current_depth + 1)
                    return total
                except PermissionError:
                    return 0

            def get_scan_targets(root_path: str, depth: int = 1) -> list:
                targets = []
                try:
                    entries = sorted(os.scandir(root_path), key=lambda e: e.name)
                    for entry in entries:
                        if entry.name.startswith(".") or entry.name in (
                            "node_modules",
                            "__pycache__",
                            ".git",
                            "vendor",
                            "dist",
                            "build",
                            ".venv",
                            "venv",
                        ):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            file_count = count_files(entry.path)
                            if file_count >= min_files:
                                linux_path = entry.path
                                # Reverse-map through the full mapping table, not
                                # just MOUNT_POINT, so targets on a second share
                                # come back as a path the client can actually send.
                                client_path = to_client_path(linux_path)
                                targets.append({
                                    "path": client_path,
                                    "linux_path": linux_path,
                                    "name": entry.name,
                                    "file_count": file_count,
                                    "is_dir": True,
                                })
                except PermissionError:
                    pass
                return targets

            targets = get_scan_targets(resolved_target, max_depth)
            if not targets:
                targets = [{
                    "path": target,
                    "linux_path": resolved_target,
                    "name": os.path.basename(resolved_target),
                    "file_count": count_files(resolved_target),
                    "is_dir": True,
                }]

            targets.sort(key=lambda t: t["file_count"], reverse=True)
            targets = targets[:max_targets]
            total_files = sum(t["file_count"] for t in targets)

            return jsonify({
                "success": True,
                "root_target": target,
                "resolved_root": resolved_target,
                "total_scan_targets": len(targets),
                "total_files_estimated": total_files,
                "targets": targets,
                "recommendation": f"Scan each target separately to keep results manageable (page_size={DEFAULT_PAGE_SIZE} findings per page)",
                "hint": "Use each target['path'] as the target parameter in your scan tool call",
            })
        except Exception as e:
            logger.error(f"Error in batch-scan-dirs: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/util/scan-project-structure", methods=["POST"])
    def scan_project_structure():
        """Shortened version: returns success, detected_types, found_files, scan_recommendations, scan_statistics."""
        try:
            params = request.json or {}
            project_path = params.get("project_path", ".")
            deep_scan = params.get("deep_scan", True)
            include_hidden = params.get("include_hidden", False)

            resolved_path = resolve_windows_path(project_path)

            if not os.path.exists(resolved_path):
                return jsonify({
                    "error": f"Project path does not exist: {resolved_path}",
                    "original_path": project_path,
                }), 404

            found_files: Dict[str, list] = {}
            detected_types = set()
            scan_recommendations: Dict[str, Any] = {}
            max_depth = 10 if deep_scan else 1

            for root, dirs, files in os.walk(resolved_path):
                depth = root[len(resolved_path) :].count(os.sep)
                if depth >= max_depth:
                    dirs[:] = []
                    continue
                if not include_hidden:
                    dirs[:] = [d for d in dirs if not d.startswith(".")]

                for project_type, patterns in DEPENDENCY_FILES.items():
                    for pattern in patterns:
                        if "*" in pattern:
                            matching = [f for f in files if fnmatch.fnmatch(f, pattern)]
                            for matched_file in matching:
                                file_path = os.path.join(root, matched_file)
                                rel_path = os.path.relpath(file_path, resolved_path)
                                found_files.setdefault(project_type, []).append(rel_path)
                                detected_types.add(project_type)
                        else:
                            if pattern in files:
                                file_path = os.path.join(root, pattern)
                                rel_path = os.path.relpath(file_path, resolved_path)
                                found_files.setdefault(project_type, []).append(rel_path)
                                detected_types.add(project_type)

            if "python" in detected_types:
                scan_recommendations["python"] = {
                    "tools": ["bandit", "safety"],
                    "targets": found_files.get("python", []),
                }
            if "nodejs" in detected_types:
                scan_recommendations["nodejs"] = {
                    "tools": ["npm-audit", "eslint-security"],
                    "targets": found_files.get("nodejs", []),
                }
            if "go" in detected_types:
                scan_recommendations["go"] = {
                    "tools": ["gosec"],
                    "targets": found_files.get("go", []),
                }
            if "ruby" in detected_types:
                scan_recommendations["ruby"] = {
                    "tools": ["brakeman"],
                    "targets": found_files.get("ruby", []),
                }
            if "terraform" in detected_types:
                scan_recommendations["terraform"] = {
                    "tools": ["tfsec", "checkov"],
                    "targets": found_files.get("terraform", []),
                }
            if "docker" in detected_types:
                scan_recommendations["docker"] = {
                    "tools": ["trivy", "checkov"],
                    "targets": found_files.get("docker", []),
                }
            scan_recommendations["universal"] = {
                "tools": ["opengrep", "trufflehog", "gitleaks"],
                "targets": [resolved_path],
            }

            scan_statistics = {
                "total_dependency_files": sum(len(v) for v in found_files.values()),
                "project_types_detected": len(detected_types),
                "recommended_tools": list(
                    set(
                        tool
                        for rec in scan_recommendations.values()
                        for tool in rec.get("tools", [])
                    )
                ),
            }

            return jsonify({
                "success": True,
                "detected_types": list(detected_types),
                "found_files": found_files,
                "scan_recommendations": scan_recommendations,
                "scan_statistics": scan_statistics,
            })
        except Exception as e:
            logger.error(f"Error scanning project structure: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/util/mounts", methods=["GET"])
    def list_mounts():
        """The active path-mapping table: what translates to what, and what exists.

        When a scan fails with "outside the allowed mount roots", this is the
        endpoint that says why — which mappings are configured, which of their
        targets are actually mounted, and which shares were auto-discovered.
        """
        try:
            info = pathmap.get().describe()
            info["success"] = True
            info["hint"] = ("Add mappings with PATH_MAPPINGS='F:/Resola=/mnt/Resola,D:/code=/mnt/code' "
                            "or a mounts.json; POST /api/util/mounts/reload after mounting a new share.")
            return jsonify(info)
        except Exception as e:
            logger.error(f"mounts: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/util/mounts/reload", methods=["POST"])
    def reload_mounts():
        """Re-read mount config and re-discover shares without a server restart.

        Mounting a new VMware shared folder used to mean editing .env and
        restarting; the allowed-root list is rebuilt in place instead.
        """
        try:
            pm = pathmap.reload()
            import config as _cfg
            _cfg.ALLOWED_MOUNTS[:] = list(pm.roots)
            for extra in (_cfg.REPO_SRC_DIR, _cfg.SAST_RESULTS_DIR):
                e = (extra or "").rstrip("/")
                if e and e not in _cfg.ALLOWED_MOUNTS:
                    _cfg.ALLOWED_MOUNTS.append(e)
            return jsonify({"success": True, "reloaded": True, **pm.describe()})
        except Exception as e:
            logger.error(f"mounts/reload: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/util/find-repos", methods=["POST"])
    def find_repos():
        """Discover git repos under the mounted shares.

        Scanning private repos on the local machine shouldn't require knowing
        (or typing) each path: point this at a root — or at nothing, to search
        every allowed mount — and feed the results straight into /api/repo-scan.
        """
        try:
            params = request.json or {}
            root = (params.get("root") or "").strip()
            max_depth = min(6, max(1, int(params.get("max_depth", 3))))
            limit = min(1000, max(1, int(params.get("limit", 500))))
            include_git = bool(params.get("include_git_info", False))
            require_git = bool(params.get("require_git", True))

            if root:
                roots = [validate_scan_target(root)]
            else:
                roots = [r for r in ALLOWED_MOUNTS if os.path.isdir(r)]
            if not roots:
                return jsonify({"success": True, "total": 0, "repos": [],
                                "roots_searched": [],
                                "note": "no allowed mount root exists on disk; check GET /api/util/mounts"})

            repos: list = []
            seen: set = set()

            def walk(base: str, depth: int) -> None:
                if len(repos) >= limit or depth > max_depth:
                    return
                try:
                    entries = sorted(os.scandir(base), key=lambda e: e.name)
                except (PermissionError, OSError):
                    return
                for entry in entries:
                    if len(repos) >= limit:
                        return
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if entry.name in _REPO_SKIP_DIRS:
                        continue
                    is_repo = os.path.isdir(os.path.join(entry.path, ".git"))
                    if is_repo or (not require_git and _looks_like_project(entry.path)):
                        real = os.path.realpath(entry.path)
                        if real in seen:
                            continue
                        seen.add(real)
                        repos.append(_describe_repo(entry.path, is_repo, include_git))
                        # A repo's subdirectories are its own content, not more repos.
                        continue
                    if entry.name.startswith("."):
                        continue
                    walk(entry.path, depth + 1)

            for r in roots:
                walk(r, 1)

            repos.sort(key=lambda x: -x.get("source_files", 0))
            return jsonify({
                "success": True,
                "roots_searched": roots,
                "total": len(repos),
                "truncated": len(repos) >= limit,
                "repos": repos,
                "hint": "POST each repo's 'path' to /api/repo-scan to run the full tool matrix",
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"find-repos: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/util/scan-stats", methods=["GET"])
    def get_scan_stats():
        try:
            with scan_stats_lock:
                current_stats = dict(scan_stats)

            return jsonify({
                "success": True,
                "max_parallel_scans": MAX_PARALLEL_SCANS,
                "scan_wait_timeout_seconds": SCAN_WAIT_TIMEOUT,
                "statistics": current_stats,
                "slots_available": MAX_PARALLEL_SCANS - current_stats.get("active_scans", 0),
            })
        except Exception as e:
            logger.error(f"Error getting scan stats: {str(e)}")
            return jsonify({"error": str(e)}), 500
