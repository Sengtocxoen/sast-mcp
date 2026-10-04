"""
Hunt endpoints: the memory-safety pipeline from docs/hunt-pipeline, as an API.

    GET  /api/hunt                 what the stages are and what they measured
    GET  /api/hunt/budget          GitHub API budget left, and what a run costs
    POST /api/hunt/catalog         catalog -> candidate repos, by category
    POST /api/hunt/target-gate     Stage A: G1-G4 + GHSA  (the ~100% stage)
    POST /api/hunt/shape-scan      Stage B: the C shape scanners (<2%, measured)
    POST /api/hunt/evidence        prove a clean fuzzing result actually ran
    POST /api/hunt/disclosure      where can this report actually be sent?

Unlike every other route module here, these do not wrap a third-party binary -
the analysis lives in server/hunt/ as code. Two consequences:

* The results are structured data, not tool stdout, so they are returned as
  plain JSON rather than through response_as_toon: the TOON wrapper exists to
  summarise a scanner's text output, and running it over an already-structured
  verdict would only blur it.
* Everything is fast enough to be synchronous. Gating is network-bound, not
  CPU-bound, so it runs in a thread pool inside one request; `background: true`
  is available for a whole-catalog sweep.

Request bodies reach the filesystem and the GitHub API, so every path goes
through core.validate_scan_target (mount-root confinement) and every repo slug
through _repo() before it is interpolated into a URL.
"""
import logging
import os
import re
import traceback
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, request, jsonify

from core import run_scan_in_thread, validate_scan_target
from hunt import catalog as hunt_catalog
from hunt import disclosure as hunt_disclosure
from hunt import evidence as hunt_evidence
from hunt import gating as hunt_gating
from hunt import shapes as hunt_shapes
from hunt.ghclient import GitHubClient, RateLimited

logger = logging.getLogger(__name__)

# owner/name only. This value is interpolated into api.github.com paths, so a
# slug carrying '..', a query string or a scheme must never get that far.
_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9._-]{1,100}$")

# Caps so one request cannot turn into an unbounded sweep.
MAX_REPOS_PER_CALL = int(os.environ.get("HUNT_MAX_REPOS_PER_CALL", 300))
DEFAULT_MAX_REPOS = int(os.environ.get("HUNT_DEFAULT_MAX_REPOS", 25))
MAX_OBJECTS_PER_CALL = 64

_CATALOG_TSVS = {
    "parsers": os.path.join("docs", "hunt-pipeline", "catalog", "catalog_parsers_62.tsv"),
    "all": os.path.join("docs", "hunt-pipeline", "catalog", "catalog_all_297.tsv"),
}

# One pooled client per process: the whole point of ghclient is connection reuse
# and a warm on-disk cache, and a per-request client would throw both away.
_client: Optional[GitHubClient] = None


def client() -> GitHubClient:
    global _client
    if _client is None:
        _client = GitHubClient()
    return _client


def _repo(value: Any, field: str = "repo") -> str:
    slug = str(value or "").strip().strip("/")
    if slug.lower().startswith(("http://", "https://", "github.com/")):
        normalized = hunt_catalog.normalize_repo(slug)
        slug = normalized or slug
    if not _REPO_RE.match(slug):
        raise ValueError(f"{field} must be 'owner/name' (got {str(value)[:80]!r})")
    return slug


def _repos(params: Dict[str, Any]) -> List[str]:
    raw = params.get("repos") or params.get("repo") or []
    if isinstance(raw, str):
        raw = [r for r in re.split(r"[\s,]+", raw) if r]
    if not isinstance(raw, list):
        raise ValueError("repos must be a list of 'owner/name' slugs")
    return [_repo(r, "repos[]") for r in raw[:MAX_REPOS_PER_CALL]]


def _optional_path(params: Dict[str, Any], key: str) -> Optional[str]:
    """Confine any request-supplied path to the allowed mount roots."""
    value = params.get(key)
    if not value:
        return None
    return validate_scan_target(str(value))


def _catalog_url(value: Any) -> str:
    """Validate a caller-supplied catalog URL.

    ghclient refuses a non-GitHub host anyway, but checking here turns an
    attempted SSRF into a 400 with a usable message instead of a 500, and keeps
    the rule visible at the edge where the untrusted value arrives.
    """
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != "raw.githubusercontent.com":
        raise ValueError("url must be an https://raw.githubusercontent.com/... address")
    return url


def _tags(params: Dict[str, Any]) -> Optional[List[str]]:
    tags = params.get("tags")
    if tags in (None, "", "parsers"):
        return None  # None = the default parser tag set
    if tags == "all":
        return list(hunt_catalog.PARSER_TAGS | hunt_catalog.UNGATED_PARSER_TAGS)
    if isinstance(tags, str):
        return [t for t in re.split(r"[\s,]+", tags) if t]
    if isinstance(tags, list):
        return [str(t) for t in tags]
    raise ValueError("tags must be a list, a comma-separated string, 'parsers' or 'all'")


def _load_entries(params: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    """Resolve the `catalog` parameter to entries, plus a description of it."""
    source = str(params.get("catalog") or params.get("source") or "parsers")
    if source in _CATALOG_TSVS:
        path = os.path.join(os.getcwd(), _CATALOG_TSVS[source])
        if not os.path.isfile(path):
            raise ValueError(f"committed catalog {source!r} not found at {path}")
        return hunt_catalog.load_tsv(path), f"committed TSV ({source})"
    if source in ("readme", "single_file_libs", "live"):
        url = (_catalog_url(params["url"]) if params.get("url")
               else hunt_catalog.SINGLE_FILE_LIBS_README)
        out = hunt_catalog.load_catalog(client(), url=url, refresh=bool(params.get("refresh")))
        if out.get("error"):
            raise ValueError(out["error"])
        return out["entries"], f"live README ({url})"
    if source.startswith("http"):
        url = _catalog_url(source)
        out = hunt_catalog.load_catalog(client(), url=url, refresh=bool(params.get("refresh")))
        if out.get("error"):
            raise ValueError(out["error"])
        return out["entries"], f"live README ({url})"
    raise ValueError("catalog must be 'parsers', 'all', 'readme', or a raw README URL")


def register(app: Flask) -> None:

    @app.route("/api/hunt", methods=["GET"])
    def hunt_index():
        """What the pipeline is, and which half of it is worth your budget."""
        return jsonify({
            "pipeline": "OSS memory-safety hunt (docs/hunt-pipeline/ARCHITECTURE.md)",
            "headline": ("static analysis earned its keep selecting TARGETS (~100% precision), "
                         "not detecting SITES (<2%). Spend the budget on target gating."),
            "stages": {
                "A_target_gating": {
                    "endpoint": "/api/hunt/target-gate",
                    "measured": "297 repos -> 62 parsers -> 2 survivors, 2 of 2 yielded findings",
                    "gates": {
                        "G1": "maintained - last COMMIT date, never pushed_at",
                        "G2": "not saturated - OSS-Fuzz project.yaml must 404",
                        "G3": "no in-repo fuzz harness",
                        "G4": "uncontested - distinct open-PR authors",
                        "GHSA": "no advisory ids in-tree",
                    },
                },
                "B_shape_scanning": {
                    "endpoint": "/api/hunt/shape-scan",
                    "measured": "60 hits, 1 already-known bug. scan3: 53 hits, 0 real (retired)",
                    "shapes": {k: v["measured"] for k, v in hunt_shapes.SHAPES.items()},
                },
                "triage": {
                    "endpoint": "/api/hunt/evidence",
                    "rule": ("demand a cov:/INITED line before believing a negative - six "
                             "campaign verdicts of '0 crashes' were never tests"),
                },
                "disclosure": {
                    "endpoint": "/api/hunt/disclosure",
                    "measured": "private-vulnerability-reporting was enabled:false on 11 of 12",
                },
            },
            "budget": client().budget(),
        })

    @app.route("/api/hunt/budget", methods=["GET"])
    def hunt_budget():
        n = int(request.args.get("repos", DEFAULT_MAX_REPOS))
        return jsonify({
            "budget": client().budget(),
            "cost_estimate": hunt_gating.estimate_cost(max(0, n)),
            "token_present": bool(client().token),
            "advice": ("export GITHUB_TOKEN to lift the ceiling from 60 to 5,000 requests/hour"
                       if not client().token else "authenticated"),
        })

    @app.route("/api/hunt/catalog", methods=["POST"])
    def hunt_catalog_route():
        try:
            params = request.json or {}
            entries, described = _load_entries(params)
            tags = _tags(params)
            filtered = hunt_catalog.filter_tags(entries, tags) if (
                tags is not None or params.get("filter", True)) else entries
            limit = int(params.get("limit", 0) or 0)
            shown = filtered[:limit] if limit > 0 else filtered

            by_tag: Dict[str, int] = {}
            for e in filtered:
                by_tag[e.get("tag", "misc")] = by_tag.get(e.get("tag", "misc"), 0) + 1

            return jsonify({
                "source": described,
                "total_in_catalog": len(entries),
                "after_tag_filter": len(filtered),
                "tags_used": sorted(tags) if tags else sorted(hunt_catalog.PARSER_TAGS),
                "counts_by_tag": dict(sorted(by_tag.items(), key=lambda kv: -kv[1])),
                "entries": shown,
                "repos": hunt_catalog.repos_of(shown),
                "next_step": "POST /api/hunt/target-gate with these repos",
                "known_gap": ("the 2d, json and net tags were never gated in the campaign but "
                              "contain parsers - pass tags='all' to include them"),
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"hunt/catalog: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/hunt/target-gate", methods=["POST"])
    def hunt_target_gate():
        """Stage A. The gate battery, concurrently, stopping at the API ceiling."""
        try:
            params = request.json or {}
            repos = _repos(params)
            dropped_slugs: List[str] = []
            if not repos:
                entries, _ = _load_entries(params)
                tags = _tags(params)
                # A catalog is parsed from third-party README content, so these
                # slugs are untrusted input reaching both URL construction and a
                # filesystem join. Validate them like explicit repos, but drop
                # the bad ones instead of failing the whole request.
                for slug in hunt_catalog.repos_of(hunt_catalog.filter_tags(entries, tags)):
                    try:
                        repos.append(_repo(slug, "catalog entry"))
                    except ValueError:
                        dropped_slugs.append(str(slug)[:80])
            if not repos:
                return jsonify({"error": "no repos: pass repos=[...] or catalog='parsers'"}), 400

            max_repos = min(int(params.get("max_repos", DEFAULT_MAX_REPOS) or DEFAULT_MAX_REPOS),
                            MAX_REPOS_PER_CALL)
            selected = repos[:max_repos]
            skipped_for_cap = repos[max_repos:]

            opts: Dict[str, Any] = {
                "local_root": _optional_path(params, "local_root"),
                "workers": max(1, min(int(params.get("workers", 6) or 6), 16)),
                "gates": params.get("gates") or hunt_gating.ALL_GATES,
                "fail_fast": bool(params.get("fail_fast", True)),
                "include_issues": bool(params.get("include_issues", True)),
                "max_age_days": int(params.get("max_age_days",
                                               hunt_gating.DEFAULT_MAX_AGE_DAYS)),
            }
            if params.get("use_project_index") is not None:
                opts["use_project_index"] = bool(params["use_project_index"])

            if params.get("background"):
                job_params = dict(params)
                job_params["_resolved_repos"] = selected
                # Hand the job the VALIDATED path. Copying the raw body would let
                # the background path read params['local_root'] straight from the
                # request, bypassing the mount-root confinement the synchronous
                # path applies via _optional_path.
                job_params["local_root"] = opts["local_root"]
                return jsonify(run_scan_in_thread("hunt-target-gate", job_params,
                                                  _gate_job))

            out = hunt_gating.gate_repos(client(), selected, **opts)
            out["repos_skipped_for_cap"] = skipped_for_cap
            if dropped_slugs:
                out["catalog_entries_rejected"] = dropped_slugs[:20]
            if skipped_for_cap:
                out["cap_note"] = (f"{len(skipped_for_cap)} repos were not gated (max_repos="
                                   f"{max_repos}). Gate by category rather than all at once.")
            return jsonify(out)
        except RateLimited as e:
            return jsonify({"error": str(e), "rate_limited": True,
                            "budget": client().budget()}), 429
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"hunt/target-gate: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/hunt/shape-scan", methods=["POST"])
    def hunt_shape_scan():
        """Stage B. Measured at <2% precision - the result says so, in-band."""
        try:
            params = request.json or {}
            if not params.get("target"):
                return jsonify({"error": "target (path to a checked-out C/C++ tree) "
                                         "is required"}), 400
            root = validate_scan_target(str(params["target"]))
            wanted = params.get("shapes") or params.get("shapes_wanted")
            if isinstance(wanted, str):
                wanted = [s for s in re.split(r"[\s,]+", wanted) if s]

            out = hunt_shapes.scan(
                root,
                shapes_wanted=wanted,
                allow_retired=bool(params.get("allow_retired")),
                workers=max(1, min(int(params.get("workers", 8) or 8), 16)),
                max_file_bytes=int(params.get("max_file_bytes",
                                              hunt_shapes.MAX_FILE_BYTES)),
                max_hits=int(params.get("max_hits", 500)),
            )
            out["original_path"] = params["target"]
            return jsonify(out)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"hunt/shape-scan: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    # Named _route like the other two: a view function called hunt_evidence
    # would shadow the module import of the same name inside register()'s scope,
    # and the body would then call .assess() on the view itself.
    @app.route("/api/hunt/evidence", methods=["POST"])
    def hunt_evidence_route():
        """Decide whether a fuzzing result proves anything at all."""
        try:
            params = request.json or {}
            log = params.get("log") or ""
            log_path = _optional_path(params, "log_path")
            if log_path:
                try:
                    with open(log_path, "r", errors="ignore") as f:
                        log = f.read()[-400_000:]
                except OSError as e:
                    return jsonify({"error": f"could not read log_path: {e}"}), 400

            harness = params.get("harness_source") or ""
            harness_path = _optional_path(params, "harness_path")
            if harness_path:
                try:
                    with open(harness_path, "r", errors="ignore") as f:
                        harness = f.read()[:400_000]
                except OSError as e:
                    return jsonify({"error": f"could not read harness_path: {e}"}), 400

            objects: List[str] = []
            rejected: List[str] = []
            for p in (params.get("object_paths") or [])[:MAX_OBJECTS_PER_CALL]:
                try:
                    objects.append(validate_scan_target(str(p)))
                except ValueError as e:
                    rejected.append(f"{p}: {e}")

            if not any([log, harness, objects, params.get("poc_build_command"),
                        params.get("assert_source"), params.get("assert_path")]):
                return jsonify({"error": "nothing to assess: pass log/log_path, "
                                         "object_paths, harness_source/harness_path, "
                                         "poc_build_command or assert_source/assert_path"}), 400

            out: Dict[str, Any] = hunt_evidence.assess(
                log=log,
                claimed_crashes=int(params.get("claimed_crashes", 0) or 0),
                object_paths=objects or None,
                harness_source=harness,
                jobs=int(params.get("jobs", 1) or 1),
            )
            if rejected:
                out["rejected_paths"] = rejected

            if params.get("poc_build_command"):
                out["poc_build"] = hunt_evidence.check_poc_build_flags(
                    str(params["poc_build_command"]),
                    signal=str(params.get("signal", "store")))
            # assert_source is TEXT; assert_path is a file, read here through
            # validate_scan_target. The previous version validated assert_source
            # only when it "looked like a path", which both guessed at the
            # caller's intent and rejected legitimate one-line inline source.
            assert_src = params.get("assert_source") or ""
            assert_path = _optional_path(params, "assert_path")
            if assert_path:
                try:
                    with open(assert_path, "r", errors="ignore") as f:
                        assert_src = f.read()[:400_000]
                except OSError as e:
                    return jsonify({"error": f"could not read assert_path: {e}"}), 400
            if assert_src and params.get("assert_line"):
                out["assert_triage"] = hunt_evidence.classify_assert_crash(
                    assert_src, int(params["assert_line"]))
            return jsonify(out)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"hunt/evidence: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/hunt/disclosure", methods=["POST"])
    def hunt_disclosure_route():
        """Where can this report actually go, and what must it contain?"""
        try:
            params = request.json or {}
            repos = _repos(params)
            if not repos:
                return jsonify({"error": "repo (owner/name) is required"}), 400
            repos = repos[:20]
            results = [hunt_disclosure.preflight(client(), r) for r in repos]
            if len(results) == 1:
                return jsonify(results[0])
            return jsonify({
                "count": len(results),
                "ready_to_report": [r["repo"] for r in results if r["ready_to_report"]],
                "blocked": [r["repo"] for r in results if not r["ready_to_report"]],
                "private_channel_available": [r["repo"] for r in results
                                              if r["private_ghsa_available"]],
                "results": results,
                "budget": client().budget(),
            })
        except RateLimited as e:
            return jsonify({"error": str(e), "rate_limited": True}), 429
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error(f"hunt/disclosure: {e}\n{traceback.format_exc()}")
            return jsonify({"error": str(e)}), 500


def _gate_job(params: Dict[str, Any]) -> Dict[str, Any]:
    """Background worker for a whole-catalog sweep (module-level for the runner).

    Re-validates local_root rather than trusting the dict it was handed: this
    function is the one place a request-shaped payload reaches the filesystem
    without going back through a view, so it does not assume a caller remembered.
    """
    repos = params.get("_resolved_repos") or []
    return hunt_gating.gate_repos(
        client(), repos,
        local_root=_optional_path(params, "local_root"),
        workers=max(1, min(int(params.get("workers", 6) or 6), 16)),
        gates=params.get("gates") or hunt_gating.ALL_GATES,
        fail_fast=bool(params.get("fail_fast", True)),
        include_issues=bool(params.get("include_issues", True)),
    )
