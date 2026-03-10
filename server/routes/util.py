"""
Utility routes: generic command, batch-scan-dirs, scan-project-structure, scan-stats.
"""
import fnmatch
import logging
import os
from typing import Any, Dict

from flask import Flask, request, jsonify

from core import execute_command, resolve_windows_path, scan_stats_lock, scan_stats
from config import (
    COMMAND_TIMEOUT,
    DEFAULT_PAGE_SIZE,
    MOUNT_POINT,
    WINDOWS_BASE,
    SCAN_WAIT_TIMEOUT,
    MAX_PARALLEL_SCANS,
)

logger = logging.getLogger(__name__)

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

            resolved_target = (
                resolve_windows_path(target)
                if (target.startswith("F:") or target.startswith("f:"))
                else target
            )

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
                                if linux_path.startswith(MOUNT_POINT):
                                    client_path = linux_path.replace(
                                        MOUNT_POINT, WINDOWS_BASE, 1
                                    ).replace("/", "\\")
                                else:
                                    client_path = linux_path
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
                "tools": ["semgrep", "trufflehog", "gitleaks"],
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
