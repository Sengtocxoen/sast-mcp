"""
Disclosure preflight tests, from the two section 4 gates about shipping a report.

The campaign wrote "open a private GHSA" into every report before checking
whether that route existed: GET /private-vulnerability-reporting returned
enabled:false on 11 of 12 targets, so the instruction was impossible to follow.
Only nodemailer and fluidsynth had a working private channel.

And SECURITY.md has to be read before the report is written, not after:
vgmstream's contains an explicit LLM clause and calls DoS "not huge", while
raylib's directs reports to public Issues - so asking raylib for an embargo
contradicts the maintainer's own policy.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from hunt import disclosure  # noqa: E402
from hunt.ghclient import GitHubClient  # noqa: E402

VGMSTREAM_POLICY = """# Security Policy

Please report vulnerabilities by email to the maintainers.

LLM-generated reports or patches with no clear human participation may be closed
without warning. Denial of service in a media parser is not huge, and will be
treated as a normal bug.
"""

RAYLIB_POLICY = """# Security

Report any issue you find on the public GitHub Issues tracker. We do not use
private advisories.
"""

GOOD_POLICY = """# Security Policy

Please report security issues privately via GitHub Security Advisories, or by
email to security@example.com. We aim to respond within 72 hours.
"""


class FakeTransport:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, headers, timeout):
        self.calls.append(url)
        hdrs = {"x-ratelimit-limit": "60", "x-ratelimit-remaining": "55",
                "x-ratelimit-reset": str(int(time.time()) + 900)}
        for needle, (status, body) in self.routes.items():
            if needle in url:
                return status, body, hdrs
        return 404, "", hdrs


def client_for(routes):
    return GitHubClient(token="", transport=FakeTransport(routes), cache=None,
                        use_cache=False)


# -- private vulnerability reporting --------------------------------------

def test_private_reporting_disabled_is_the_common_case():
    c = client_for({"private-vulnerability-reporting": (200, json.dumps({"enabled": False}))})
    r = disclosure.check_private_reporting(c, "losnoco/vgmstream")
    assert r["enabled"] is False
    assert r["available"] is False


def test_private_reporting_enabled_is_detected():
    c = client_for({"private-vulnerability-reporting": (200, json.dumps({"enabled": True}))})
    r = disclosure.check_private_reporting(c, "nodemailer/nodemailer")
    assert r["enabled"] is True
    assert r["available"] is True


def test_private_reporting_404_is_unknown_not_enabled():
    """A 404 means the endpoint said nothing. It must not read as a channel."""
    c = client_for({})
    r = disclosure.check_private_reporting(c, "x/y")
    assert r["enabled"] is False
    assert r["status"] == 404


# -- SECURITY.md discovery ------------------------------------------------

def test_policy_found_at_github_subdir():
    c = client_for({".github/SECURITY.md": (200, GOOD_POLICY)})
    r = disclosure.fetch_security_policy(c, "o/r")
    assert r["found"] is True
    assert ".github/SECURITY.md" in r["path"]


def test_missing_policy_is_reported_as_absent():
    c = client_for({})
    r = disclosure.fetch_security_policy(c, "o/r")
    assert r["found"] is False
    assert r["text"] == ""


def test_policy_discovery_costs_no_api_budget():
    c = client_for({"SECURITY.md": (200, GOOD_POLICY)})
    disclosure.fetch_security_policy(c, "o/r")
    assert c.budget()["api_requests_made"] == 0


# -- clause scanning ------------------------------------------------------

def test_llm_clause_is_a_blocker():
    r = disclosure.scan_policy_clauses(VGMSTREAM_POLICY)
    assert r["llm_clause"]["present"] is True
    assert "llm_clause" in r["blockers"]
    assert "without warning" in r["llm_clause"]["quote"].lower()


def test_dos_downgrade_is_flagged():
    r = disclosure.scan_policy_clauses(VGMSTREAM_POLICY)
    assert r["dos_downgraded"]["present"] is True


def test_public_issue_directive_is_flagged():
    r = disclosure.scan_policy_clauses(RAYLIB_POLICY)
    assert r["public_disclosure_only"]["present"] is True
    assert "public_disclosure_only" in r["warnings"]


def test_clean_policy_has_no_blockers():
    r = disclosure.scan_policy_clauses(GOOD_POLICY)
    assert r["blockers"] == []
    assert r["contacts"]["emails"] == ["security@example.com"]


def test_empty_policy_scans_clean_but_finds_nothing():
    r = disclosure.scan_policy_clauses("")
    assert r["blockers"] == []
    assert r["contacts"]["emails"] == []


# -- combined preflight ---------------------------------------------------

def test_preflight_refuses_to_promise_a_private_ghsa_that_does_not_exist():
    """The exact defect: 11 of 12 reports told the maintainer to use a channel
    that was switched off."""
    c = client_for({
        "private-vulnerability-reporting": (200, json.dumps({"enabled": False})),
        "SECURITY.md": (200, RAYLIB_POLICY),
    })
    r = disclosure.preflight(c, "raysan5/raylib")
    assert r["route"] != "private_ghsa"
    assert r["private_ghsa_available"] is False
    assert any("public" in w for w in r["warnings"])


def test_preflight_recommends_private_ghsa_when_it_is_really_on():
    c = client_for({
        "private-vulnerability-reporting": (200, json.dumps({"enabled": True})),
        "SECURITY.md": (200, GOOD_POLICY),
    })
    r = disclosure.preflight(c, "fluidsynth/fluidsynth")
    assert r["route"] == "private_ghsa"
    assert r["ready_to_report"] is True


def test_preflight_blocks_on_the_llm_clause():
    c = client_for({
        "private-vulnerability-reporting": (200, json.dumps({"enabled": False})),
        "SECURITY.md": (200, VGMSTREAM_POLICY),
    })
    r = disclosure.preflight(c, "losnoco/vgmstream")
    assert r["ready_to_report"] is False
    assert "llm_clause" in r["blockers"]
    assert "human" in " ".join(r["required_actions"]).lower()


def test_preflight_with_no_policy_and_no_channel_says_so():
    c = client_for({})
    r = disclosure.preflight(c, "o/r")
    assert r["route"] == "no_documented_channel"
    assert r["ready_to_report"] is False


def test_preflight_falls_back_to_email_from_the_policy():
    c = client_for({
        "private-vulnerability-reporting": (200, json.dumps({"enabled": False})),
        "SECURITY.md": (200, GOOD_POLICY),
    })
    r = disclosure.preflight(c, "o/r")
    assert r["route"] == "email"
    assert "security@example.com" in r["contacts"]["emails"]


# -- regression: the real raylib policy, which the first pattern missed -----

RAYLIB_REAL = """# Security Policy

## Supported Versions

Most considerations of errors and defects can be handled using the project Issues and/or Discussions.

## Reporting a Vulnerability

Discovered vulnerability can be directly reported using the project Issues and/or Discussions. They will be reviewed as soon as possible.
"""


def test_raylib_real_policy_is_detected_as_public_disclosure():
    """Verbatim from raysan5/raylib. 'the project Issues' is the GitHub feature,
    and the first version of this pattern only knew 'GitHub Issues'."""
    r = disclosure.scan_policy_clauses(RAYLIB_REAL)
    assert r["public_disclosure_only"]["present"] is True
    assert "public_disclosure_only" in r["warnings"]


def test_report_security_issues_privately_is_not_a_public_directive():
    """The discriminator: 'issues' as the English word must not trigger it."""
    text = ("Please report security issues privately via GitHub Security Advisories. "
            "We triage reported issues within 72 hours.")
    r = disclosure.scan_policy_clauses(text)
    assert r["public_disclosure_only"]["present"] is False


def test_preflight_routes_raylib_to_a_public_issue_with_a_warning():
    c = client_for({
        "private-vulnerability-reporting": (200, json.dumps({"enabled": False})),
        "SECURITY.md": (200, RAYLIB_REAL),
    })
    r = disclosure.preflight(c, "raysan5/raylib")
    assert r["route"] == "public_issue"
    assert any("embargo" in w for w in r["warnings"])
