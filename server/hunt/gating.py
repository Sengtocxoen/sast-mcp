"""
gating.py - Stage A: decide which library is worth attacking.

This is the part of docs/hunt-pipeline/ARCHITECTURE.md that actually worked.
Measured on the OSS-Hunt-2026-09-30 campaign: 297 catalog repos -> 62 format
parsers -> 2 survivors, and *both* survivors yielded findings. ~100% precision.
Section 2 of the same document measures the opposite stage, pattern-matching C
for the shape of a bug, at under 2%. So this module is where the static-analysis
budget belongs, and it is the one thing the rest of this server has no
equivalent of: every other endpoint asks "what is wrong with this repo", and
this one asks "which repo should I be looking at".

Five independent gates, each of which rejected something real during the
campaign - that is the evidence they earn their place:

    G1  maintained      last COMMIT date (never pushed_at)   killed tiffloader (1784d)
    G2  not saturated   OSS-Fuzz project.yaml must 404       killed stb, dr_libs, lz4, miniz
    G3  no harness      no in-repo *fuzz* files              killed bddisasm, qoi, minimp3
    G4  uncontested     distinct open-PR authors             killed nanosvg (36 authors)
    GHSA no advisories  grep -rl "GHSA-" == 0                flagged wildmidi (swept ground)

Three design rules the document forces:

* **A failed lookup is an error, never a pass.** "Demand evidence before
  believing a negative" applies to gating too: if the commits API 500s, the repo
  is not thereby maintained. Status is 'error' and the repo cannot be a survivor.
* **Gates run cheapest-first.** G2, G3 and GHSA cost no API budget (raw.github
  content is unmetered, the other two are local filesystem reads), so they run
  before G1 and G4, which cost three metered requests between them. On the
  unauthenticated 60/hour ceiling that reordering roughly triples how many repos
  one hour can gate.
* **Thresholds are reported as heuristics**, because section 7 admits G4 has no
  principled cutoff - "36 distinct authors" was obviously contested, but there
  is no defensible line. The verdict carries the numbers so a human can judge.
"""
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import ghclient
from .ghclient import GitHubClient, RateLimited, TransportError

logger = logging.getLogger(__name__)

# G1: how stale is too stale. The campaign's rejects sat at 421-2124 days and its
# survivors inside a year, so the default lands between them.
DEFAULT_MAX_AGE_DAYS = int(os.environ.get("HUNT_MAX_AGE_DAYS", 400))

# G4 thresholds. Heuristics, flagged as such in every verdict (section 7).
DEFAULT_AUTHOR_REJECT = int(os.environ.get("HUNT_AUTHOR_REJECT", 12))
DEFAULT_PR_REJECT = int(os.environ.get("HUNT_PR_REJECT", 25))
DEFAULT_ISSUE_REJECT = int(os.environ.get("HUNT_ISSUE_REJECT", 100))

_SKIP_DIRS = {".git", ".svn", "node_modules", "build", "dist", "corpus",
              "artifacts", "third_party", "vendor", ".github"}
_HARNESS_RE = re.compile(r"fuzz", re.I)
_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
_TEXTY = (".md", ".txt", ".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".json",
          ".yml", ".yaml", ".rst", ".html", ".changelog", "")
_LLVM_ENTRY_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(")

ALL_GATES = ("G1", "G2", "G3", "G4", "GHSA")


@dataclass
class Verdict:
    gate: str
    name: str
    status: str          # pass | reject | flag | skip | error
    detail: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"gate": self.gate, "name": self.name, "status": self.status,
                "detail": self.detail, "evidence": self.evidence}


# ---------------------------------------------------------------- G1 maintained

def _last_commit(client: GitHubClient, repo: str) -> Dict[str, Any]:
    resp = client.api(f"/repos/{repo}/commits?per_page=1", ttl=ghclient.TTL_COMMIT)
    if not resp.ok:
        return {"error": f"HTTP {resp.status}", "status": resp.status}
    data = resp.json([])
    if not isinstance(data, list) or not data:
        return {"error": "no commits in response"}
    commit = (data[0] or {}).get("commit") or {}
    date = ((commit.get("committer") or {}).get("date")
            or (commit.get("author") or {}).get("date"))
    if not date:
        return {"error": "commit carried no date"}
    return {"date": date, "sha": (data[0] or {}).get("sha", "")[:12]}


def _age_days(iso: str, now: Optional[float] = None) -> Optional[float]:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            t = time.strptime(iso.replace("+00:00", "Z"), fmt)
            return ((now or time.time()) - time.mktime(t) + time.timezone) / 86400.0
        except (ValueError, OverflowError):
            continue
    return None


def gate_maintained(client: GitHubClient, repo: str,
                    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
                    include_repo_meta: bool = False,
                    now: Optional[float] = None) -> Verdict:
    """G1. Is anyone still home?

    Reads the last *commit* date. Never pushed_at: during the campaign pushed_at
    reported miniaudio as 2026-08-19 when `git log -1` said 2026-03-04, which
    would have let a five-month-stale repo through as fresh. pushed_at is
    recorded in the evidence only so the discrepancy stays visible, and it is
    explicitly labelled untrusted.
    """
    info = _last_commit(client, repo)
    if "error" in info:
        return Verdict("G1", "maintained", "error",
                       f"could not read last commit: {info['error']}",
                       {"source": "commits", "error": info["error"]})

    age = _age_days(info["date"], now)
    if age is None:
        return Verdict("G1", "maintained", "error",
                       f"unparseable commit date {info['date']!r}",
                       {"source": "commits", "last_commit": info["date"]})

    evidence: Dict[str, Any] = {
        "source": "commits",
        "last_commit": info["date"],
        "last_commit_sha": info.get("sha", ""),
        "age_days": round(age, 1),
        "max_age_days": max_age_days,
        "note": "pushed_at is not used: it over-reports freshness (miniaudio, by 5 months)",
    }

    if include_repo_meta:
        meta = client.api(f"/repos/{repo}", ttl=ghclient.TTL_COMMIT)
        if meta.ok:
            m = meta.json({}) or {}
            evidence["pushed_at_untrusted"] = m.get("pushed_at")
            evidence["archived"] = bool(m.get("archived"))
            if m.get("archived"):
                return Verdict("G1", "maintained", "reject",
                               "repo is archived upstream", evidence)

    if age > max_age_days:
        return Verdict("G1", "maintained", "reject",
                       f"last commit {int(age)}d ago (> {max_age_days}d)", evidence)
    return Verdict("G1", "maintained", "pass",
                   f"last commit {int(age)}d ago", evidence)


# ------------------------------------------------------------ G2 not saturated

OSSFUZZ_PROJECT_YAML = "google/oss-fuzz/master/projects/{project}/project.yaml"
OSSFUZZ_CONTENTS = "/repos/google/oss-fuzz/contents/projects"


def alias_names(repo: str) -> List[str]:
    """Candidate OSS-Fuzz project names for a repo.

    Checking by repo name alone is not enough - the document is explicit that
    names differ between the catalog and OSS-Fuzz - so the obvious
    transliterations are probed too. Each probe is an unmetered raw fetch.
    """
    owner, _, name = repo.partition("/")
    low = name.lower()
    out = [low]
    for variant in (low.replace("_", "-"), low.replace("-", "_"),
                    low.replace("_", "").replace("-", ""),
                    f"{owner.lower()}-{low}", owner.lower()):
        if variant and variant not in out:
            out.append(variant)
    return out


def fetch_ossfuzz_projects(client: GitHubClient) -> List[str]:
    """Every OSS-Fuzz project name, for fuzzy matching. Cached 24h; 1-2 requests.

    Worth one request on a fleet run because it catches the renames that
    per-name probing misses; callers treat failure as "index unavailable" and
    fall back to probing, never as "not saturated".
    """
    names: List[str] = []
    try:
        resp = client.api(f"{OSSFUZZ_CONTENTS}?per_page=1000", ttl=ghclient.TTL_OSSFUZZ)
        if resp.ok:
            for item in resp.json([]) or []:
                if isinstance(item, dict) and item.get("type") == "dir" and item.get("name"):
                    names.append(str(item["name"]).lower())
    except (RateLimited, TransportError) as e:
        logger.info("oss-fuzz project index unavailable (%s); falling back to name probes", e)
    return names


def _index_candidates(repo: str, index: Sequence[str]) -> List[str]:
    """Project names worth probing, found by fuzzy match against the full list."""
    name = repo.partition("/")[2].lower()
    flat = name.replace("_", "").replace("-", "")
    if len(flat) < 4:
        return []
    hits = []
    for project in index:
        pflat = project.replace("_", "").replace("-", "")
        if pflat == flat or flat in pflat or pflat in flat:
            hits.append(project)
    return hits[:5]


def gate_not_saturated(client: GitHubClient, repo: str,
                       aliases: Optional[Iterable[str]] = None,
                       project_index: Optional[Sequence[str]] = None) -> Verdict:
    """G2. Is OSS-Fuzz already grinding this code?

    A 200 on projects/<name>/project.yaml means continuous fuzzing has been
    running for years and the shallow bugs are gone - that is what killed stb,
    dr_libs, lz4, miniz and tinygltf. The inverse case is worth knowing and is
    reported rather than hidden: a *vendored* OSS-Fuzz'd dependency is a reason
    to hunt the wrapper, which is exactly how assetsys (lying to a correctly
    fuzzed miniz about a buffer size) turned into a Critical.
    """
    candidates: List[str] = []
    for n in (list(aliases) if aliases else alias_names(repo)):
        if n and n not in candidates:
            candidates.append(n)
    if project_index:
        for n in _index_candidates(repo, project_index):
            if n not in candidates:
                candidates.append(n)

    probed: List[Dict[str, Any]] = []
    for project in candidates:
        resp = client.raw(OSSFUZZ_PROJECT_YAML.format(project=project),
                          ttl=ghclient.TTL_OSSFUZZ)
        probed.append({"project": project, "status": resp.status})
        if resp.ok:
            return Verdict("G2", "not_saturated", "reject",
                           f"OSS-Fuzz already fuzzes this as {project!r}",
                           {"probed": probed, "matched_project": project,
                            "inverse_hint": ("a vendored fuzzed dependency is a reason to hunt "
                                             "the WRAPPER instead - see assetsys/miniz")})
        if resp.status not in (200, 404, 301, 410):
            # A transport-level failure is not evidence of absence.
            return Verdict("G2", "not_saturated", "error",
                           f"probe for {project!r} returned HTTP {resp.status}",
                           {"probed": probed, "matched_project": None})

    return Verdict("G2", "not_saturated", "pass",
                   f"no OSS-Fuzz project.yaml for {len(probed)} name variant(s)",
                   {"probed": probed, "matched_project": None,
                    "index_used": bool(project_index)})


# ---------------------------------------------------------------- G3 no harness

def _harness_entry_points(paths: Sequence[str], limit: int = 12) -> List[str]:
    """Which functions an existing harness actually calls.

    This is the cgltf refinement: its fuzz/main.c only called cgltf_parse and
    cgltf_validate, never cgltf_load_buffers nor the accessor readers, so the
    accessors were still fair game. An in-repo harness is only disqualifying
    for the API it covers, so the verdict has to show what it covers.
    """
    calls: List[str] = []
    for p in paths[:8]:
        if not p.lower().endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
            continue
        try:
            with open(p, "r", errors="ignore") as f:
                src = f.read(200_000)
        except OSError:
            continue
        for name in _LLVM_ENTRY_RE.findall(src):
            low = name.lower()
            if low in ("if", "for", "while", "switch", "return", "sizeof", "printf",
                       "memcpy", "memset", "free", "malloc", "fprintf", "assert"):
                continue
            if name not in calls:
                calls.append(name)
            if len(calls) >= limit:
                return calls
    return calls


def gate_no_harness(local_path: Optional[str], max_entries: int = 25) -> Verdict:
    """G3. Does the project already fuzz itself?

    An in-repo harness means the maintainer has already swept the obvious paths,
    which is what killed bddisasm, qoi, minimp3, ufbx and tinyexr. Requires a
    checkout; without one the gate reports 'skip' rather than inventing a pass.
    """
    if not local_path:
        return Verdict("G3", "no_harness", "skip",
                       "no local checkout given; clone the repo to evaluate G3",
                       {"harness_paths": []})
    if not os.path.isdir(local_path):
        return Verdict("G3", "no_harness", "skip",
                       f"{local_path!r} is not a directory", {"harness_paths": []})

    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(local_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for d in list(dirnames):
            if _HARNESS_RE.search(d):
                found.append(os.path.join(dirpath, d))
        for fn in filenames:
            if _HARNESS_RE.search(fn):
                found.append(os.path.join(dirpath, fn))
        if len(found) >= max_entries:
            break

    if not found:
        return Verdict("G3", "no_harness", "pass", "no in-repo fuzz harness",
                       {"harness_paths": []})

    rel = [os.path.relpath(p, local_path) for p in found[:max_entries]]
    return Verdict(
        "G3", "no_harness", "reject",
        f"ships {len(rel)} fuzz-related path(s); maintainer has swept this",
        {"harness_paths": rel,
         "harness_entry_points": _harness_entry_points(found),
         "override_hint": ("not disqualifying if the harness covers the WRONG API - "
                           "cgltf's fuzz/main.c called only cgltf_parse/cgltf_validate, "
                           "leaving cgltf_load_buffers and the accessors fair game. "
                           "Check harness_entry_points before accepting this reject.")})


# ------------------------------------------------------------- G4 uncontested

def gate_uncontested(client: GitHubClient, repo: str,
                     author_reject: int = DEFAULT_AUTHOR_REJECT,
                     pr_reject: int = DEFAULT_PR_REJECT,
                     issue_reject: int = DEFAULT_ISSUE_REJECT,
                     include_issues: bool = True) -> Verdict:
    """G4. Is somebody else already in here?

    Author diversity is the signal, not the raw count: nanosvg's 45 open PRs
    came from 36 distinct authors and PR #300 had already fixed the class that
    was about to be reported. Section 7 is honest that there is no principled
    cutoff, so the thresholds below are heuristics and every verdict says so.
    """
    resp = client.api(f"/repos/{repo}/pulls?state=open&per_page=100", ttl=ghclient.TTL_PULLS)
    if not resp.ok:
        return Verdict("G4", "uncontested", "error",
                       f"could not list open PRs: HTTP {resp.status}",
                       {"threshold_is_heuristic": True})
    pulls = resp.json([]) or []
    if not isinstance(pulls, list):
        pulls = []
    authors = {str(((p or {}).get("user") or {}).get("login", "")).lower()
               for p in pulls if isinstance(p, dict)}
    authors.discard("")

    evidence: Dict[str, Any] = {
        "open_prs": len(pulls),
        "distinct_authors": len(authors),
        "authors_sample": sorted(authors)[:12],
        "author_reject_at": author_reject,
        "pr_reject_at": pr_reject,
        "threshold_is_heuristic": True,
        "note": ("no principled cutoff exists (ARCHITECTURE.md section 7); these numbers "
                 "are for a human to judge, 36 distinct authors was the obvious case"),
    }

    if include_issues:
        meta = client.api(f"/repos/{repo}", ttl=ghclient.TTL_COMMIT)
        if meta.ok:
            m = meta.json({}) or {}
            evidence["open_issues_including_prs"] = m.get("open_issues_count")
            evidence["stars"] = m.get("stargazers_count")
            issues = m.get("open_issues_count") or 0
            if issues >= issue_reject:
                evidence["issue_reject_at"] = issue_reject
                return Verdict("G4", "uncontested", "reject",
                               f"{issues} open issues/PRs - heavily contested", evidence)

    if len(authors) >= author_reject or len(pulls) >= pr_reject:
        return Verdict("G4", "uncontested", "reject",
                       f"{len(pulls)} open PRs from {len(authors)} distinct authors",
                       evidence)
    if len(authors) >= max(2, author_reject // 2):
        return Verdict("G4", "uncontested", "flag",
                       f"{len(pulls)} open PRs from {len(authors)} authors - judge this one",
                       evidence)
    return Verdict("G4", "uncontested", "pass",
                   f"{len(pulls)} open PRs from {len(authors)} authors", evidence)


# --------------------------------------------------------------- GHSA sweep

def gate_no_advisories(local_path: Optional[str], max_files: int = 4000,
                       max_bytes: int = 2_000_000) -> Verdict:
    """Supplementary gate: has this project ever carried an advisory?

    `grep -rl "GHSA-" == 0` means never, and non-ecosystem C libraries are
    mostly absent from GitHub's advisory database, so this catches what the API
    misses. Every C target in the campaign returned 0 except wildmidi, whose 4
    advisories marked it as swept ground.
    """
    if not local_path or not os.path.isdir(local_path):
        return Verdict("GHSA", "no_advisories", "skip",
                       "no local checkout given; clone the repo to evaluate this gate",
                       {"advisory_ids": []})

    ids: List[str] = []
    files: List[str] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(local_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if seen >= max_files:
                break
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _TEXTY:
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
                with open(path, "r", errors="ignore") as f:
                    body = f.read(max_bytes)
            except OSError:
                continue
            seen += 1
            hits = _GHSA_RE.findall(body)
            if hits:
                rel = os.path.relpath(path, local_path)
                files.append(rel)
                for h in hits:
                    if h.upper() not in [i.upper() for i in ids]:
                        ids.append(h)
        if seen >= max_files:
            break

    if ids:
        return Verdict("GHSA", "no_advisories", "reject",
                       f"{len(ids)} advisory id(s) in-tree - swept ground",
                       {"advisory_ids": ids[:20], "files": files[:10],
                        "files_scanned": seen})
    return Verdict("GHSA", "no_advisories", "pass",
                   f"no GHSA ids in {seen} text files",
                   {"advisory_ids": [], "files_scanned": seen})


# ----------------------------------------------------------- whole-repo gating

# Cheapest-first. G2/G3/GHSA cost no metered requests, so a repo that fails one
# of them never spends API budget at all.
_GATE_ORDER = ("G2", "G3", "GHSA", "G1", "G4")


def gate_repo(client: GitHubClient, repo: str, local_path: Optional[str] = None,
              gates: Sequence[str] = ALL_GATES, fail_fast: bool = True,
              project_index: Optional[Sequence[str]] = None,
              max_age_days: int = DEFAULT_MAX_AGE_DAYS,
              include_repo_meta: bool = False,
              **kw: Any) -> Dict[str, Any]:
    """Run the gate battery against one repo and say whether it survived."""
    wanted = {g.upper() for g in gates}
    verdicts: List[Verdict] = []
    rate_limited = False

    for gate in _GATE_ORDER:
        if gate not in wanted:
            continue
        try:
            if gate == "G1":
                v = gate_maintained(client, repo, max_age_days=max_age_days,
                                    include_repo_meta=include_repo_meta)
            elif gate == "G2":
                v = gate_not_saturated(client, repo, project_index=project_index)
            elif gate == "G3":
                v = gate_no_harness(local_path)
            elif gate == "G4":
                v = gate_uncontested(client, repo,
                                     include_issues=kw.get("include_issues", True))
            else:
                v = gate_no_advisories(local_path)
        except RateLimited as e:
            rate_limited = True
            verdicts.append(Verdict(gate, gate.lower(), "error",
                                    f"stopped: {e}", {"rate_limited": True}))
            break
        except TransportError as e:
            verdicts.append(Verdict(gate, gate.lower(), "error", f"transport: {e}", {}))
            if fail_fast:
                break
            continue
        except Exception as e:  # a gate bug must not take down a fleet run
            logger.warning("gate %s on %s raised: %s", gate, repo, e)
            verdicts.append(Verdict(gate, gate.lower(), "error", f"{type(e).__name__}: {e}", {}))
            continue

        verdicts.append(v)
        if v.status == "reject" and fail_fast:
            break

    rejected = [v.gate for v in verdicts if v.status == "reject"]
    errors = [v.gate for v in verdicts if v.status == "error"]
    flagged = [v.gate for v in verdicts if v.status == "flag"]
    skipped = [v.gate for v in verdicts if v.status == "skip"]

    return {
        "repo": repo,
        "local_path": local_path,
        # A survivor must have cleared every gate that ran AND have nothing
        # unproven: an errored gate is not a pass.
        "survivor": not rejected and not errors,
        "rejected_by": rejected,
        "errors": errors,
        "flagged_by": flagged,
        "skipped": skipped,
        "needs_local": bool(skipped),
        "rate_limited": rate_limited,
        "verdicts": [v.as_dict() for v in verdicts],
        "summary": _summary_line(repo, rejected, errors, flagged, skipped),
    }


def _summary_line(repo, rejected, errors, flagged, skipped) -> str:
    if rejected:
        return f"{repo}: rejected by {','.join(rejected)}"
    if errors:
        return f"{repo}: UNPROVEN - {','.join(errors)} could not be evaluated"
    bits = [f"{repo}: survived"]
    if flagged:
        bits.append(f"flagged by {','.join(flagged)}")
    if skipped:
        bits.append(f"{','.join(skipped)} need a local checkout")
    return " (".join(bits) + (")" if len(bits) > 1 else "")


def find_local_checkout(repo: str, local_root: Optional[str]) -> Optional[str]:
    """Locate a checkout of `repo` under `local_root`, if one is there."""
    if not local_root or not os.path.isdir(local_root):
        return None
    owner, _, name = repo.partition("/")
    for candidate in (os.path.join(local_root, owner, name),
                      os.path.join(local_root, f"{owner}-{name}"),
                      os.path.join(local_root, name)):
        if os.path.isdir(candidate):
            return candidate
    return None


def estimate_cost(n_repos: int, include_issues: bool = True) -> Dict[str, Any]:
    """Metered requests a run will need, so the ceiling is visible up front."""
    per_repo = 1 + (2 if include_issues else 1)  # G1 + G4(pulls[+meta])
    return {
        "metered_requests_per_repo": per_repo,
        "metered_requests_total": n_repos * per_repo,
        "free_raw_requests_per_repo": "1-5 (G2 name probes)",
        "repos_per_hour_unauthenticated": max(0, (60 - 2) // per_repo),
        "repos_per_hour_with_token": (5000 - 2) // per_repo,
        "note": "G2/G3/GHSA are unmetered; set GITHUB_TOKEN to lift 60/hour to 5,000/hour",
    }


def gate_repos(client: GitHubClient, repos: Sequence[str],
               local_root: Optional[str] = None, workers: int = 6,
               gates: Sequence[str] = ALL_GATES, fail_fast: bool = True,
               use_project_index: Optional[bool] = None,
               local_paths: Optional[Dict[str, str]] = None,
               **kw: Any) -> Dict[str, Any]:
    """Gate a list of repos concurrently, and stop cleanly at the API ceiling.

    Results keep the input order regardless of worker count, so two runs of the
    same catalog are comparable. When the budget runs out the repos that were
    never reached come back in `not_gated` - a resume list, not a silent gap.
    """
    started = time.time()
    repos = [r for r in dict.fromkeys(r.strip() for r in repos if r and r.strip())]
    stop = threading.Event()
    results: List[Optional[Dict[str, Any]]] = [None] * len(repos)

    project_index: Optional[List[str]] = None
    if use_project_index is None:
        use_project_index = len(repos) >= 5
    if use_project_index and "G2" in {g.upper() for g in gates}:
        project_index = fetch_ossfuzz_projects(client) or None

    def work(idx_repo):
        idx, repo = idx_repo
        if stop.is_set():
            return idx, None
        local = (local_paths or {}).get(repo) or find_local_checkout(repo, local_root)
        try:
            out = gate_repo(client, repo, local_path=local, gates=gates,
                            fail_fast=fail_fast, project_index=project_index, **kw)
        except RateLimited as e:
            stop.set()
            return idx, {"repo": repo, "survivor": False, "rejected_by": [],
                         "errors": ["budget"], "flagged_by": [], "skipped": [],
                         "rate_limited": True, "verdicts": [],
                         "summary": f"{repo}: stopped at the API ceiling - {e}"}
        if out.get("rate_limited"):
            stop.set()
        return idx, out

    if workers <= 1:
        for pair in enumerate(repos):
            idx, out = work(pair)
            results[idx] = out
    else:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
            for idx, out in pool.map(work, list(enumerate(repos))):
                results[idx] = out

    gated = [r for r in results if r]
    not_gated = [repos[i] for i, r in enumerate(results) if r is None]
    survivors = [r["repo"] for r in gated if r.get("survivor")]
    rate_limited = stop.is_set() or any(r.get("rate_limited") for r in gated)

    rejects: Dict[str, int] = {}
    for r in gated:
        for g in r.get("rejected_by", []):
            rejects[g] = rejects.get(g, 0) + 1

    return {
        "repos_requested": len(repos),
        "repos_gated": len(gated),
        "survivors": survivors,
        "survivor_count": len(survivors),
        "rejects_by_gate": rejects,
        "needs_local_checkout": [r["repo"] for r in gated if r.get("needs_local")],
        "unproven": [r["repo"] for r in gated if r.get("errors")],
        "rate_limited": bool(rate_limited),
        "not_gated": not_gated,
        "results": gated,
        "budget": client.budget(),
        "cost_estimate": estimate_cost(len(repos), kw.get("include_issues", True)),
        "elapsed_seconds": round(time.time() - started, 2),
        "precision_note": ("Stage A ran at ~100% precision in the campaign "
                           "(2 survivors from 297, both yielded findings). Treat a "
                           "survivor as a target worth fuzzing, not as a finding."),
    }
