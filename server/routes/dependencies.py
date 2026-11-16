"""Dependency scanning: Safety, npm audit, OWASP Dependency-Check, Snyk."""
import json
import logging
import os
import shlex
import shutil
import tempfile
import traceback

from flask import Flask, request, jsonify

from config import (
    DEPENDENCY_CHECK_DATA_DIR,
    DEPENDENCY_CHECK_DISABLE_KEV,
    DEPENDENCY_CHECK_KEV_URL,
    DEPENDENCY_CHECK_PATH,
    DEPENDENCY_CHECK_TIMEOUT,
    NVD_API_DELAY_MS,
    NVD_MAX_RETRY_COUNT,
    NVD_API_KEY,
)
from core import execute_command, resolve_windows_path, response_as_toon

logger = logging.getLogger(__name__)


def _write_nvd_property_file(api_key: str) -> str:
    """Put the NVD API key in a private property file and return its path.

    dependency-check accepts the key either as `--nvdApiKey <key>` or as
    `nvd.api.key` in a property file passed with -P. Only the second is safe:

    * argv is world-readable through /proc/<pid>/cmdline, so any local account
      could read the key for as long as a scan runs, and scans run for minutes.
    * CommandExecutor copies the command into every result it returns and into
      the logs. core.redact_command() now masks a key passed that way, but not
      putting it there is the better answer.

    The caller deletes the file when the scan finishes.
    """
    fd, path = tempfile.mkstemp(prefix="dc-nvd-", suffix=".properties")
    with os.fdopen(fd, "w") as handle:
        handle.write("nvd.api.key=%s\n" % api_key)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows has no POSIX modes
        pass
    return path


def _nvd_cache_present(data_dir: str) -> bool:
    """True when the NVD cache directory holds at least one file."""
    try:
        return any(
            os.path.isfile(os.path.join(data_dir, name))
            for name in os.listdir(data_dir)
        )
    except OSError:
        return False


def register(app: Flask) -> None:
    @app.route("/api/dependencies/safety", methods=["POST"])
    def safety():
        try:
            params = request.json or {}
            # Safety CLI 3: "safety scan" scans project directory (cwd); no more "safety check -r file"
            target = params.get("target", ".")
            resolved = resolve_windows_path(target)
            stage = params.get("stage", "")  # development | cicd | production
            key = params.get("key", "")  # API key for cicd/production; or env SAFETY_API_KEY
            debug = params.get("debug", False)
            proxy_host = params.get("proxy_host", "")
            proxy_port = params.get("proxy_port", "")
            proxy_protocol = params.get("proxy_protocol", "")
            disable_optional_telemetry = params.get("disable_optional_telemetry", False)
            additional_args = params.get("additional_args", "")
            command_parts = ["safety"]
            if stage:
                command_parts.extend(["--stage", stage])
            if key:
                command_parts.extend(["--key", key])
            if proxy_host:
                command_parts.extend(["--proxy-host", proxy_host])
                if proxy_port:
                    command_parts.extend(["--proxy-port", proxy_port])
                if proxy_protocol:
                    command_parts.extend(["--proxy-protocol", proxy_protocol])
            if disable_optional_telemetry:
                command_parts.append("--disable-optional-telemetry")
            if debug:
                command_parts.append("--debug")
            if additional_args:
                command_parts.append(additional_args)
            command_parts.append("scan")
            command = " ".join(command_parts)
            result = execute_command(command, cwd=resolved, timeout=1800)
            if result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("safety", params, result))
        except Exception as e:
            logger.error(f"safety: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dependencies/npm-audit", methods=["POST"])
    def npm_audit():
        try:
            params = request.json or {}
            target = params.get("target", ".")
            json_output = params.get("json_output", True)
            audit_level = params.get("audit_level", "")
            production = params.get("production", False)
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            # Detect pnpm projects (no package-lock.json, but pnpm-lock.yaml exists)
            use_pnpm = (
                os.path.exists(os.path.join(resolved, "pnpm-lock.yaml"))
                and not os.path.exists(os.path.join(resolved, "package-lock.json"))
            )
            if use_pnpm:
                command = "pnpm audit"
                if json_output:
                    command += " --json"
                if audit_level:
                    command += f" --audit-level={audit_level}"
            else:
                command = "npm audit"
                if json_output:
                    command += " --json"
                if audit_level:
                    command += f" --audit-level={audit_level}"
                if production:
                    command += " --production"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, cwd=resolved, timeout=180)
            result["package_manager"] = "pnpm" if use_pnpm else "npm"
            result["original_path"] = target
            result["resolved_path"] = resolved
            if json_output and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            return jsonify(response_as_toon("npm-audit", params, result))
        except Exception as e:
            logger.error(f"npm_audit: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dependencies/dependency-check", methods=["POST"])
    def dependency_check():
        """OWASP Dependency-Check.

        Two things must be right before this tool can run at all, and both were
        wrong on the Kali box:

        1. The NVD cache location. The shipped default is `[JAR]/data`, inside
           root-owned /opt/dependency-check, while the server runs as a normal
           user, so building the H2 database fails. DEPENDENCY_CHECK_DATA_DIR
           puts it somewhere writable, and the directory is created here.
        2. The NVD API key. Unauthenticated clients get 5 requests per 30
           seconds against 50 with a key, so the first cache build is the
           difference between minutes and hours. It comes from NVD_API_KEY in
           the environment or .env, and goes to the tool in a 0600 property
           file - never in argv.

        An empty NVD cache with no key is reported as an error rather than
        attempted: the run would take hours and a caller waiting on a timeout
        cannot tell that from a clean result.
        """
        prop_file = ""
        output_dir = ""
        try:
            params = request.json or {}
            target = params.get("target", ".")
            project_name = params.get("project_name", "project")
            output_format = params.get("format", "JSON")
            scan = params.get("scan", target)
            # A request may still carry its own key; the configured one is the
            # normal path, so callers never have to send a secret over the wire.
            nvd_api_key = params.get("nvd_api_key", "") or NVD_API_KEY
            data_dir = params.get("data_dir", "") or DEPENDENCY_CHECK_DATA_DIR
            noupdate = params.get("noupdate", False)
            pretty_print = params.get("pretty_print", False)
            additional_args = params.get("additional_args", "")
            resolved_target = resolve_windows_path(target)
            scan_paths = [resolve_windows_path(p.strip()) for p in str(scan).split(",") if p.strip()]

            try:
                os.makedirs(data_dir, exist_ok=True)
            except OSError as ex:
                return jsonify({
                    "error": f"NVD cache dir {data_dir} is unusable: {ex}",
                    "hint": "Set DEPENDENCY_CHECK_DATA_DIR to a path the server user can write.",
                }), 500

            cache_ready = _nvd_cache_present(data_dir)
            if not cache_ready:
                # Either branch means this scan cannot produce a usable answer.
                # Saying so beats a run that blocks until the caller's timeout,
                # which is indistinguishable from a clean result.
                if noupdate:
                    return jsonify({
                        "error": (
                            f"NVD cache at {data_dir} is empty and noupdate was requested, "
                            "so there are no advisories to match against."
                        ),
                        "hint": "Build the cache once with scripts/warm-nvd-cache.sh.",
                    }), 503
                if not nvd_api_key:
                    return jsonify({
                        "error": (
                            f"NVD cache at {data_dir} is empty and no NVD API key is configured. "
                            "Dependency-Check would spend hours at 5 requests per 30 seconds."
                        ),
                        "hint": (
                            "Set NVD_API_KEY in .env, then run scripts/warm-nvd-cache.sh once."
                        ),
                    }), 503

            output_dir = tempfile.mkdtemp()
            scan_flags = " ".join(f"-s {shlex.quote(p)}" for p in scan_paths)
            # project_name reaches us from a request body and lands in a shell
            # command, so quote it.
            command = (
                f"{DEPENDENCY_CHECK_PATH} --project {shlex.quote(str(project_name))} "
                f"{scan_flags} -f {shlex.quote(str(output_format))} -o {shlex.quote(output_dir)} "
                f"--data {shlex.quote(data_dir)} --disableVersionCheck"
            )
            if nvd_api_key:
                prop_file = _write_nvd_property_file(nvd_api_key)
                command += f" -P {shlex.quote(prop_file)}"
            if noupdate:
                command += " -n"
            else:
                # Only meaningful while updating. See config.py for why these
                # exist: the NVD 503s in bursts and retries have no backoff,
                # and a 403 on the CISA feed aborts the whole update.
                if NVD_API_DELAY_MS:
                    command += f" --nvdApiDelay {shlex.quote(NVD_API_DELAY_MS)}"
                if NVD_MAX_RETRY_COUNT:
                    command += f" --nvdMaxRetryCount {shlex.quote(NVD_MAX_RETRY_COUNT)}"
                if DEPENDENCY_CHECK_KEV_URL:
                    command += f" --kevURL {shlex.quote(DEPENDENCY_CHECK_KEV_URL)}"
                elif DEPENDENCY_CHECK_DISABLE_KEV:
                    command += " --disableKnownExploited"
            if pretty_print:
                command += " --prettyPrint"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, cwd=resolved_target, timeout=DEPENDENCY_CHECK_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved_target
            try:
                for fname in os.listdir(output_dir):
                    path = os.path.join(output_dir, fname)
                    with open(path) as f:
                        if fname.endswith(".json"):
                            result["parsed_report"] = json.load(f)
                        else:
                            result["report_content"] = f.read()
            except Exception as ex:
                logger.warning(f"Read report: {ex}")
            finally:
                try:
                    shutil.rmtree(output_dir)
                except Exception:
                    pass
                if prop_file:
                    try:
                        os.remove(prop_file)
                    except OSError:
                        pass
            return jsonify(response_as_toon("dependency-check", params, result))
        except Exception as e:
            logger.error(f"dependency_check: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dependencies/snyk", methods=["POST"])
    def snyk():
        try:
            from config import SNYK_TIMEOUT
            params = request.json or {}
            target = params.get("target", ".")
            test_type = params.get("test_type", "test")
            severity_threshold = params.get("severity_threshold", "")
            json_output = params.get("json_output", True)
            output_file = params.get("output_file", "")
            additional_args = params.get("additional_args", "")
            resolved = resolve_windows_path(target)
            resolved_out = resolve_windows_path(output_file) if output_file else ""
            command = f"snyk {test_type} {resolved}"
            if json_output:
                command += " --json"
            if severity_threshold:
                command += f" --severity-threshold={severity_threshold}"
            if resolved_out:
                command += f" > {resolved_out}"
            if additional_args:
                command += f" {additional_args}"
            result = execute_command(command, timeout=SNYK_TIMEOUT)
            result["original_path"] = target
            result["resolved_path"] = resolved
            if output_file:
                result["output_file_original"] = output_file
                result["output_file_resolved"] = resolved_out
            if json_output and result.get("stdout"):
                try:
                    result["parsed_output"] = json.loads(result["stdout"])
                except Exception:
                    pass
            if resolved_out and os.path.exists(resolved_out):
                try:
                    with open(resolved_out) as f:
                        result["file_content"] = f.read()
                        if json_output:
                            try:
                                result["parsed_output"] = json.loads(result["file_content"])
                            except Exception:
                                pass
                except Exception as ex:
                    logger.warning(f"Read snyk output: {ex}")
            return jsonify(response_as_toon("snyk", params, result))
        except Exception as e:
            logger.error(f"snyk: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500
