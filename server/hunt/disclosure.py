"""
disclosure.py - find out where a report can actually go, before writing it.

Two gates from section 4 of docs/hunt-pipeline/ARCHITECTURE.md, both of which
caught an error that had already shipped:

* **Confirm the claimed disclosure route exists.** Every report in the campaign
  originally told the maintainer to open a private GHSA. Then
  GET /repos/{o}/{r}/private-vulnerability-reporting was actually checked:
  `enabled:false` on **11 of 12** targets. The instruction was impossible to
  follow on all but nodemailer and fluidsynth.
* **Read SECURITY.md before writing the report, not after.** vgmstream's carries
  an explicit LLM clause - "LLM-generated reports or patches with no clear human
  participation may be closed without warning" - and calls DoS "not huge".
  raylib's directs reports to public Issues, so asking raylib for an embargo
  contradicts the maintainer's own stated policy.

Both are pure lookups, and both are cheap: the policy fetch is unmetered raw
content, so a preflight costs exactly one metered request. That is a trivial
price for not sending a maintainer somewhere they cannot receive it.

Note the asymmetry this module preserves deliberately: a positive answer
("private reporting is on") is only ever returned when the API says so, while
every ambiguous answer - 404, error, missing policy - lands on
`no_documented_channel`. Guessing wrong in that direction wastes a maintainer's
time and burns the reporter's credibility.
"""
import logging
import re
from typing import Any, Dict, List, Sequence

from . import ghclient
from .ghclient import GitHubClient, RateLimited, TransportError

logger = logging.getLogger(__name__)

# Where a security policy lives, in the order GitHub itself looks.
POLICY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
                "SECURITY.rst", "SECURITY.txt", ".github/SECURITY.rst")
POLICY_BRANCHES = ("HEAD", "master", "main")

# The trailing group is repeated rather than a bare [\w.-]+ so a sentence's
# final period cannot end up inside the address (security@example.com. is not
# an address anybody can mail).
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_SENTENCE_RE = re.compile(r"[^.!?\n]*(?:[.!?]|$)")

# A clause is detected by meaning, not by one phrasing: maintainers word the
# same policy a dozen ways and the cost of missing one is a closed report.
_CLAUSE_PATTERNS = {
    "llm_clause": (
        r"\b(LLM|AI[- ]generated|AI generated|generative AI|ChatGPT|Copilot|"
        r"machine[- ]generated|automated(?:ly)? generated|AI slop)\b"),
    # "Issues" here means the GitHub feature, not the English word, so a bare
    # "report security issues privately" must NOT match while raylib's "reported
    # using the project Issues and/or Discussions" must. The discriminator is a
    # preposition or verb pointing AT the tracker, so the trigger word is
    # required in front of it.
    "public_disclosure_only": (
        r"\b(?:using|via|on|through|open|file|submit|report(?:ed|ing)?\s+(?:to|at|on|via|using))"
        r"\s+(?:(?:the|a|our|project|github|public)\s+){0,3}issues?\b"
        r"|\bissues?\s*(?:and/or|and|or|,)\s*discussions?\b"
        r"|\biss(?:ue|ues)\s+tracker\b"
        r"|\bdo not (?:use )?(?:private|email)\b"
        r"|\bwe do not use private\b"),
    "dos_downgraded": (
        r"\b(denial[- ]of[- ]service|DoS)\b[^.\n]{0,120}?"
        r"\b(not (?:huge|a priority|important|in scope)|out of scope|normal bug|"
        r"low priority|won'?t be treated|not considered)\b"),
    "no_bounty": r"\b(no (?:bug )?bount(?:y|ies)|we do not (?:pay|offer)|unpaid)\b",
    "embargo_window": r"\b(\d{1,3})\s*(?:days?|weeks?)\b[^.\n]{0,60}\b(disclos|embargo|publish)",
    "cve_handling": r"\b(CVE|GHSA|advisor(?:y|ies))\b",
    "requires_poc": r"\b(proof[- ]of[- ]concept|reproducer|steps to reproduce|PoC)\b",
}

# Which clauses stop a report from going out as-is, versus merely shape it.
BLOCKING_CLAUSES = ("llm_clause",)
WARNING_CLAUSES = ("public_disclosure_only", "dos_downgraded")


def _quote_for(text: str, match: re.Match) -> str:
    """The sentence a match sits in, so the operator reads the actual policy."""
    start = text.rfind("\n", 0, match.start()) + 1
    chunk = text[start:start + 400]
    m = _SENTENCE_RE.match(chunk[match.start() - start:])
    sentence = chunk if not m else chunk[:match.start() - start] + m.group(0)
    return " ".join(sentence.split())[:300]


def check_private_reporting(client: GitHubClient, repo: str) -> Dict[str, Any]:
    """Does this repo actually accept a private vulnerability report?

    Returns available=True only when the API says enabled. 404, 403 and errors
    all mean "no evidence of a channel", because the failure that mattered was
    promising a route that did not exist.
    """
    try:
        resp = client.api(f"/repos/{repo}/private-vulnerability-reporting",
                          ttl=ghclient.TTL_POLICY)
    except (RateLimited, TransportError) as e:
        return {"enabled": False, "available": False, "status": 0,
                "detail": f"could not check: {e}", "checked": False}

    data = resp.json({}) or {}
    enabled = bool(data.get("enabled")) if isinstance(data, dict) else False
    return {
        "enabled": enabled,
        "available": bool(resp.ok and enabled),
        "status": resp.status,
        "checked": True,
        "detail": ("private vulnerability reporting is enabled" if enabled else
                   f"no private channel (HTTP {resp.status}"
                   f"{', enabled=false' if resp.ok else ''}). During the campaign this "
                   f"was the answer on 11 of 12 targets, so do not write "
                   f"'open a private GHSA' into the report"),
    }


def fetch_security_policy(client: GitHubClient, repo: str,
                          paths: Sequence[str] = POLICY_PATHS,
                          branches: Sequence[str] = POLICY_BRANCHES) -> Dict[str, Any]:
    """Fetch SECURITY.md from wherever it lives. Unmetered, so it is free."""
    tried: List[str] = []
    for branch in branches:
        for path in paths:
            ref = f"{repo}/{branch}/{path}"
            tried.append(ref)
            try:
                resp = client.raw(ref, ttl=ghclient.TTL_POLICY)
            except TransportError as e:
                logger.debug("policy fetch %s failed: %s", ref, e)
                continue
            if resp.ok and resp.body.strip():
                return {"found": True, "path": path, "branch": branch,
                        "url": f"https://github.com/{repo}/blob/{branch}/{path}",
                        "text": resp.body, "tried": tried}
    return {"found": False, "path": "", "branch": "", "url": "", "text": "",
            "tried": tried,
            "detail": "no SECURITY.md found; there is no stated policy to comply with"}


def scan_policy_clauses(text: str) -> Dict[str, Any]:
    """Pull the clauses out of a security policy that change how to report."""
    text = text or ""
    out: Dict[str, Any] = {}
    blockers: List[str] = []
    warnings: List[str] = []

    for name, pattern in _CLAUSE_PATTERNS.items():
        m = re.search(pattern, text, re.I)
        out[name] = {
            "present": bool(m),
            "quote": _quote_for(text, m) if m else "",
            "matched": m.group(0) if m else "",
        }
        if m and name in BLOCKING_CLAUSES:
            blockers.append(name)
        elif m and name in WARNING_CLAUSES:
            warnings.append(name)

    emails = []
    for e in _EMAIL_RE.findall(text):
        low = e.lower()
        if low not in emails and not low.endswith((".png", ".jpg", ".svg")):
            emails.append(low)

    out["contacts"] = {"emails": emails}
    out["blockers"] = blockers
    out["warnings"] = warnings
    out["clause_notes"] = {
        "llm_clause": ("the maintainer may close an LLM-assisted report without warning. "
                       "Disclose the tooling and show clear human participation: your own "
                       "triage reasoning, a verified PoC, and a patch you understand "
                       "(vgmstream)"),
        "public_disclosure_only": ("this project handles reports in public; asking for an "
                                   "embargo contradicts its own policy (raylib)"),
        "dos_downgraded": ("the maintainer considers DoS low severity here; lead with memory "
                           "corruption or do not report it as Critical (vgmstream)"),
    }
    return out


def preflight(client: GitHubClient, repo: str) -> Dict[str, Any]:
    """One answer to 'where does this report go, and what must it contain?'

    Costs one metered request. Returns a route that is known to exist, or
    `no_documented_channel` - never an assumed one.
    """
    pvr = check_private_reporting(client, repo)
    policy = fetch_security_policy(client, repo)
    clauses = scan_policy_clauses(policy.get("text", ""))

    emails = clauses["contacts"]["emails"]
    if pvr["available"]:
        route = "private_ghsa"
        route_detail = (f"https://github.com/{repo}/security/advisories/new")
    elif emails:
        route = "email"
        route_detail = emails[0]
    elif clauses["public_disclosure_only"]["present"]:
        route = "public_issue"
        route_detail = f"https://github.com/{repo}/issues"
    else:
        route = "no_documented_channel"
        route_detail = ("no private advisory channel and no contact in a policy. Decide "
                        "deliberately: a public issue may be the only route, which changes "
                        "what is safe to include")

    warnings = list(clauses["warnings"])
    if route == "public_issue":
        warnings.append("public_issue_route: no embargo is possible; withhold the PoC "
                        "until a fix exists or report only what is safe in the open")
    if not policy["found"]:
        warnings.append("no_security_policy: nothing states scope, severity or timelines")
    if pvr["available"] and clauses["public_disclosure_only"]["present"]:
        warnings.append("policy_contradiction: private reporting is on but the policy "
                        "points at public issues; follow the written policy")

    required: List[str] = []
    for b in clauses["blockers"]:
        note = clauses["clause_notes"].get(b, "")
        if b == "llm_clause":
            required.append("disclose AI assistance and demonstrate human participation: "
                            "your own triage, a verified reproducer, and a patch you can "
                            "defend in review. " + note)
        else:
            required.append(note or b)
    if clauses["requires_poc"]["present"]:
        required.append("the policy asks for a reproducer; attach the crashing input")

    return {
        "repo": repo,
        "route": route,
        "route_detail": route_detail,
        "private_ghsa_available": bool(pvr["available"]),
        "private_reporting": pvr,
        "policy": {k: v for k, v in policy.items() if k != "text"},
        "policy_excerpt": (policy.get("text", "")[:1200] if policy.get("found") else ""),
        "clauses": {k: v for k, v in clauses.items()
                    if k not in ("blockers", "warnings", "clause_notes", "contacts")},
        "contacts": clauses["contacts"],
        "blockers": clauses["blockers"],
        "warnings": warnings,
        "required_actions": required,
        "ready_to_report": not clauses["blockers"] and route != "no_documented_channel",
        "budget": client.budget(),
    }
