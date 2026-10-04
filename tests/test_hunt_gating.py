"""
Gating tests, built from the measured results in docs/hunt-pipeline/ARCHITECTURE.md.

Every case here is a repo the campaign actually accepted or rejected, so this
suite is the known-positive check the pipeline demands of its own tools: if
these gates no longer reproduce the campaign's verdicts, the gates are broken
and their "survivor" output should not be believed.

    tiffloader   1784d since last commit      -> G1 reject
    miniaudio    pushed_at lies by 5 months   -> G1 must read the commit date
    stb          OSS-Fuzz project.yaml = 200  -> G2 reject
    bddisasm     ships bdshemu_fuzz           -> G3 reject
    nanosvg      45 open PRs, 36 authors      -> G4 reject
    wildmidi     4 GHSA advisories in-tree    -> GHSA reject
    dmc_unrar    passes all five              -> survivor
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from hunt import gating  # noqa: E402
from hunt.ghclient import GitHubClient  # noqa: E402

DAY = 86400


def commits_payload(days_ago: int) -> str:
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days_ago * DAY))
    return json.dumps([{"sha": "deadbeef", "commit": {
        "committer": {"date": when}, "author": {"date": when}}}])


def repo_payload(**kw) -> str:
    base = {"open_issues_count": 3, "archived": False, "fork": False,
            "default_branch": "master", "pushed_at": "2026-08-19T00:00:00Z"}
    base.update(kw)
    return json.dumps(base)


def pulls_payload(authors) -> str:
    return json.dumps([{"number": i, "user": {"login": a}} for i, a in enumerate(authors)])


class FakeTransport:
    """Routes by URL substring. Records calls so budget spend is assertable."""

    def __init__(self, routes, default=(404, "", {})):
        self.routes = routes
        self.default = default
        self.calls = []

    def __call__(self, method, url, headers, timeout):
        self.calls.append(url)
        for needle, resp in self.routes.items():
            if needle in url:
                status, body = resp[0], resp[1]
                hdrs = resp[2] if len(resp) > 2 else {}
                out = {"x-ratelimit-limit": "60", "x-ratelimit-remaining": "57",
                       "x-ratelimit-reset": str(int(time.time()) + 1800)}
                out.update(hdrs)
                return status, body, out
        return self.default[0], self.default[1], {
            "x-ratelimit-limit": "60", "x-ratelimit-remaining": "57",
            "x-ratelimit-reset": str(int(time.time()) + 1800)}


def client_for(routes, **kw):
    """A client with the disk cache OFF - tests must not read a previous run."""
    return GitHubClient(token="", transport=FakeTransport(routes), cache=None,
                        use_cache=False, **kw)


# -- G1 maintained ---------------------------------------------------------

def test_g1_rejects_abandoned_tiffloader():
    c = client_for({"/commits": (200, commits_payload(1784))})
    v = gating.gate_maintained(c, "MalcolmMcLean/tiffloader")
    assert v.status == "reject"
    assert v.evidence["age_days"] >= 1780


def test_g1_passes_maintained_repo():
    c = client_for({"/commits": (200, commits_payload(30))})
    v = gating.gate_maintained(c, "DrMcCoy/dmc_unrar")
    assert v.status == "pass"
    assert v.evidence["age_days"] <= 31


def test_g1_reads_commit_date_not_pushed_at():
    """The miniaudio trap: pushed_at said 2026-08-19, git log said 2026-03-04.

    A gate that trusts pushed_at calls a 7-month-stale repo fresh. The payload
    here is deliberately contradictory and the gate must use the commit date.
    """
    c = client_for({
        "/commits": (200, commits_payload(214)),
        "/repos/mackron/miniaudio": (200, repo_payload(pushed_at="2026-08-19T00:00:00Z")),
    })
    v = gating.gate_maintained(c, "mackron/miniaudio", max_age_days=120)
    assert v.status == "reject", "trusted pushed_at instead of the commit date"
    assert v.evidence["age_days"] >= 210
    assert v.evidence["source"] == "commits"


def test_g1_rejects_archived_even_when_recently_touched():
    c = client_for({
        "/commits": (200, commits_payload(5)),
        "/repos/x/archived-lib": (200, repo_payload(archived=True)),
    })
    v = gating.gate_maintained(c, "x/archived-lib", include_repo_meta=True)
    assert v.status == "reject"
    assert "archiv" in v.detail.lower()


def test_g1_http_failure_is_an_error_not_a_pass():
    """A failed lookup must never read as 'maintained' - no false clean."""
    c = client_for({"/commits": (500, "upstream boom")})
    v = gating.gate_maintained(c, "x/y")
    assert v.status == "error"


# -- G2 not saturated ------------------------------------------------------

def test_g2_rejects_stb_which_oss_fuzz_already_covers():
    c = client_for({"oss-fuzz/master/projects/stb/project.yaml": (200, "homepage: x\n")})
    v = gating.gate_not_saturated(c, "nothings/stb")
    assert v.status == "reject"
    assert v.evidence["matched_project"] == "stb"


def test_g2_passes_when_project_yaml_is_404():
    c = client_for({}, )
    v = gating.gate_not_saturated(c, "ddiakopoulos/tinyply")
    assert v.status == "pass"
    assert v.evidence["probed"]


def test_g2_tries_name_aliases_because_names_differ():
    """dr_libs is fuzzed under a different project name than the repo's."""
    c = client_for({"projects/dr_libs/project.yaml": (200, "homepage: x")})
    v = gating.gate_not_saturated(c, "mackron/dr_libs", aliases=["drlibs", "dr_libs"])
    assert v.status == "reject"


def test_g2_costs_no_api_budget():
    """raw.githubusercontent.com is unmetered; G2 must not spend the 60/hour."""
    c = client_for({})
    gating.gate_not_saturated(c, "ddiakopoulos/tinyply")
    assert c.budget()["api_requests_made"] == 0
    assert c.budget()["raw_requests_made"] >= 1


# -- G3 no in-repo harness -------------------------------------------------

def test_g3_rejects_repo_shipping_a_fuzz_harness(tmp_path):
    (tmp_path / "bdshemu_fuzz").mkdir()
    (tmp_path / "bdshemu_fuzz" / "main.c").write_text("int LLVMFuzzerTestOneInput(){}")
    v = gating.gate_no_harness(str(tmp_path))
    assert v.status == "reject"
    assert v.evidence["harness_paths"]
    # The cgltf refinement must be reachable, not buried: a harness covering the
    # wrong API is not disqualifying, so the verdict has to say so.
    assert "override" in json.dumps(v.evidence).lower()


def test_g3_passes_clean_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "parser.c").write_text("int main(){}")
    v = gating.gate_no_harness(str(tmp_path))
    assert v.status == "pass"


def test_g3_ignores_git_internals(tmp_path):
    g = tmp_path / ".git" / "refs"
    g.mkdir(parents=True)
    (g / "fuzz-branch").write_text("ref")
    v = gating.gate_no_harness(str(tmp_path))
    assert v.status == "pass"


def test_g3_skips_without_a_checkout():
    v = gating.gate_no_harness(None)
    assert v.status == "skip"


# -- G4 uncontested --------------------------------------------------------

def test_g4_rejects_nanosvg_on_author_diversity():
    """45 open PRs from 36 distinct authors. Diversity is the signal."""
    authors = [f"dev{i}" for i in range(36)] + ["dev0"] * 9
    c = client_for({
        "/pulls": (200, pulls_payload(authors)),
        "/repos/memononen/nanosvg": (200, repo_payload(open_issues_count=60)),
    })
    v = gating.gate_uncontested(c, "memononen/nanosvg")
    assert v.status == "reject"
    assert v.evidence["distinct_authors"] == 36


def test_g4_passes_quiet_repo():
    c = client_for({
        "/pulls": (200, pulls_payload(["a", "a", "b"])),
        "/repos/DrMcCoy/dmc_unrar": (200, repo_payload(open_issues_count=2)),
    })
    v = gating.gate_uncontested(c, "DrMcCoy/dmc_unrar")
    assert v.status == "pass"
    assert v.evidence["distinct_authors"] == 2


def test_g4_rejects_issue_heavy_nuklear():
    c = client_for({
        "/pulls": (200, pulls_payload(["a", "b"])),
        "/repos/Immediate-Mode-UI/Nuklear": (200, repo_payload(open_issues_count=315)),
    })
    v = gating.gate_uncontested(c, "Immediate-Mode-UI/Nuklear")
    assert v.status == "reject"


def test_g4_records_that_its_threshold_is_a_heuristic():
    """Section 7 admits there is no principled cutoff. The output must say so."""
    authors = [f"dev{i}" for i in range(11)]
    c = client_for({"/pulls": (200, pulls_payload(authors)),
                    "/repos/x/y": (200, repo_payload())})
    v = gating.gate_uncontested(c, "x/y")
    assert v.status in ("flag", "reject")
    assert v.evidence.get("threshold_is_heuristic") is True


# -- GHSA sweep ------------------------------------------------------------

def test_ghsa_rejects_wildmidi_with_advisories_in_tree(tmp_path):
    (tmp_path / "CHANGELOG.md").write_text("fixed GHSA-1234-abcd-5678 and more")
    v = gating.gate_no_advisories(str(tmp_path))
    assert v.status == "reject"
    assert v.evidence["advisory_ids"]


def test_ghsa_passes_repo_with_none(tmp_path):
    (tmp_path / "README.md").write_text("a single-file library")
    v = gating.gate_no_advisories(str(tmp_path))
    assert v.status == "pass"


# -- whole-repo and fleet gating ------------------------------------------

def test_gate_repo_marks_survivor(tmp_path):
    (tmp_path / "dmc_unrar.c").write_text("int main(){}")
    c = client_for({
        "/commits": (200, commits_payload(20)),
        "/pulls": (200, pulls_payload(["a"])),
        "/repos/DrMcCoy/dmc_unrar": (200, repo_payload()),
    })
    r = gating.gate_repo(c, "DrMcCoy/dmc_unrar", local_path=str(tmp_path))
    assert r["survivor"] is True
    assert r["rejected_by"] == []
    assert {v["gate"] for v in r["verdicts"]} == {"G1", "G2", "G3", "G4", "GHSA"}


def test_gate_repo_stops_at_first_reject_to_save_budget():
    """An abandoned repo should not cost the remaining four gates' requests."""
    c = client_for({"/commits": (200, commits_payload(1784))})
    r = gating.gate_repo(c, "MalcolmMcLean/tiffloader", fail_fast=True)
    assert r["survivor"] is False
    assert r["rejected_by"] == ["G1"]
    assert c.budget()["api_requests_made"] == 1


def test_gate_repos_reports_partial_results_when_budget_runs_out():
    """The 60/hour ceiling must produce partial output and a resume list."""
    spent = {"x-ratelimit-remaining": "0", "x-ratelimit-limit": "60",
             "x-ratelimit-reset": str(int(time.time()) + 1200)}
    c = client_for({"/commits": (200, commits_payload(10), spent)})
    out = gating.gate_repos(c, ["a/one", "b/two", "c/three"], workers=1)
    assert out["rate_limited"] is True
    assert out["not_gated"], "must say which repos were never reached"
    assert len(out["results"]) < 3
    assert out["budget"]["remaining"] == 0


def test_gate_repos_never_claims_a_survivor_it_could_not_check():
    c = client_for({"/commits": (500, "boom")})
    out = gating.gate_repos(c, ["x/y"], workers=1)
    assert out["survivors"] == []
    assert out["results"][0]["errors"]


def test_gate_repos_is_deterministic_across_workers():
    c = client_for({"/commits": (200, commits_payload(10)),
                    "/pulls": (200, pulls_payload(["a"]))})
    repos = [f"o/r{i}" for i in range(6)]
    a = gating.gate_repos(client_for({"/commits": (200, commits_payload(10)),
                                      "/pulls": (200, pulls_payload(["a"]))}),
                          repos, workers=1)
    b = gating.gate_repos(c, repos, workers=4)
    assert [r["repo"] for r in a["results"]] == [r["repo"] for r in b["results"]]
