"""
correlate.py - normalize every scanner's JSON into one finding schema, then
cross-check the tools against each other.

Running 15 tools on a repo is only an improvement if their output can be read as
one result. Each tool has its own JSON shape, its own severity words, and its own
idea of which line an issue is on, so raw concatenation gives you the same bug
listed five times and no signal about which findings are real.

This module does three things:

1. **Normalize** - every tool's report becomes a list of Finding dicts with the
   same keys (file, line, severity, category, cwe, ...).
2. **Correlate** - findings that describe the same defect are clustered. Code
   findings cluster on (file, nearby line, vulnerability category); dependency
   findings cluster on (package, CVE) because file/line is meaningless there.
3. **Score** - a cluster confirmed by two or more INDEPENDENT tools is ranked
   `corroborated`; a single tool's claim is ranked `single_tool`. That ordering
   is the actual triage win: it puts the findings multiple engines agree on at
   the top and pushes one-engine noise down, without discarding anything.

Nothing here can fail a scan: every parser is defensive and an unparseable
report degrades to zero normalized findings while the raw per-tool counts in the
repo-scan response stay exactly as they were.
"""
import json
import logging
import os
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Lines that two tools report for the same defect can drift by a couple of lines
# (one flags the sink, another the enclosing statement). Cluster within this window.
LINE_WINDOW = int(os.environ.get("CORRELATE_LINE_WINDOW", 3))

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Every tool spells severity differently. Map them onto one scale.
_SEV_MAP = {
    "critical": "critical", "crit": "critical", "blocker": "critical",
    "error": "high", "high": "high", "severe": "high", "major": "high",
    "warning": "medium", "medium": "medium", "moderate": "medium", "warn": "medium",
    "note": "low", "low": "low", "minor": "low", "style": "low",
    "info": "info", "informational": "info", "unknown": "info", "none": "info",
}

# CWE -> normalized vulnerability category. Two tools agree on a defect when they
# land on the same category at the same place, even if their rule ids differ
# entirely (which they always do).
_CWE_CATEGORY = {
    "78": "command-injection", "77": "command-injection", "88": "command-injection",
    "89": "sql-injection", "564": "sql-injection", "943": "sql-injection",
    "79": "xss", "80": "xss", "116": "xss",
    "22": "path-traversal", "23": "path-traversal", "36": "path-traversal", "73": "path-traversal",
    "94": "code-injection", "95": "code-injection", "96": "code-injection",
    "502": "deserialization", "915": "deserialization",
    "611": "xxe", "827": "xxe",
    "918": "ssrf",
    "352": "csrf",
    "798": "hardcoded-secret", "259": "hardcoded-secret", "321": "hardcoded-secret",
    "327": "weak-crypto", "328": "weak-crypto", "326": "weak-crypto", "916": "weak-crypto",
    "330": "weak-random", "338": "weak-random",
    "295": "cert-validation", "297": "cert-validation", "599": "cert-validation",
    "287": "authn", "306": "authn", "863": "authz", "285": "authz", "862": "authz",
    "601": "open-redirect",
    "319": "cleartext-transmission", "312": "cleartext-storage",
    "400": "resource-exhaustion", "770": "resource-exhaustion", "1333": "redos",
    "20": "input-validation",
    "532": "log-injection", "117": "log-injection",
    "1236": "csv-injection",
    "434": "unrestricted-upload",
    "209": "info-disclosure", "200": "info-disclosure",
}

# Fallback when a rule carries no CWE: match keywords in the rule id / message.
# Ordered - first match wins, so put the specific patterns before the generic.
_KEYWORD_CATEGORY: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"sql[_\-\s]?inject|sqli\b|tainted[_\-\s]?sql", re.I), "sql-injection"),
    (re.compile(r"command[_\-\s]?inject|os[_\-\s]?command|shell[_\-\s]?exec|subprocess.*shell", re.I), "command-injection"),
    (re.compile(r"\bxss\b|cross[_\-\s]?site[_\-\s]?script", re.I), "xss"),
    (re.compile(r"path[_\-\s]?travers|directory[_\-\s]?travers|zip[_\-\s]?slip", re.I), "path-traversal"),
    (re.compile(r"\bssrf\b|server[_\-\s]?side[_\-\s]?request", re.I), "ssrf"),
    (re.compile(r"\bxxe\b|xml[_\-\s]?external[_\-\s]?entit", re.I), "xxe"),
    (re.compile(r"deserializ|pickle|unmarshal|yaml[_\-\s]?load", re.I), "deserialization"),
    (re.compile(r"\bcsrf\b|cross[_\-\s]?site[_\-\s]?request", re.I), "csrf"),
    (re.compile(r"hardcoded|hard[_\-\s]?coded.*(secret|password|key|token)|api[_\-\s]?key", re.I), "hardcoded-secret"),
    (re.compile(r"weak[_\-\s]?(crypto|cipher|hash)|\bmd5\b|\bsha1\b|\bdes\b|\brc4\b|ecb[_\-\s]?mode", re.I), "weak-crypto"),
    (re.compile(r"insecure[_\-\s]?random|weak[_\-\s]?random|math[._\-]random|pseudo[_\-\s]?random", re.I), "weak-random"),
    (re.compile(r"verify\s*=\s*false|cert.*(validat|verif)|hostname[_\-\s]?verif|insecure[_\-\s]?skip[_\-\s]?verify", re.I), "cert-validation"),
    (re.compile(r"open[_\-\s]?redirect|unvalidated[_\-\s]?redirect", re.I), "open-redirect"),
    (re.compile(r"\beval\b|exec[_\-\s]?detect|code[_\-\s]?inject|dynamic[_\-\s]?code", re.I), "code-injection"),
    (re.compile(r"redos|catastrophic[_\-\s]?backtrack|regex.*dos", re.I), "redos"),
    (re.compile(r"cleartext|http[_\-\s]?url|unencrypted|plain[_\-\s]?text[_\-\s]?(password|transmi)", re.I), "cleartext-transmission"),
    (re.compile(r"file[_\-\s]?upload|unrestricted[_\-\s]?upload", re.I), "unrestricted-upload"),
    (re.compile(r"log[_\-\s]?inject|sensitive.*log|log.*sensitive", re.I), "log-injection"),
    # IaC misconfigurations carry no CWE and no code-shaped wording, so without
    # these they all collapse into "other" and checkov/tfsec agreement becomes
    # unreadable. Placed before the generic authz/authn patterns, which would
    # otherwise swallow "public access" and "no root access".
    (re.compile(r"public[_\-\s]?(read|write|access|acl)|publicly[_\-\s]?access|"
                r"0\.0\.0\.0/0|::/0|open[_\-\s]?to[_\-\s]?(the[_\-\s]?)?(world|internet)|"
                r"anonymous[_\-\s]?access", re.I), "public-exposure"),
    (re.compile(r"(not|no|missing|disabl\w*|without)[_\-\s]?\w*[_\-\s]?encrypt|"
                r"encrypt\w*[_\-\s]?(at[_\-\s]?rest|disabled|not[_\-\s]?enabled)|"
                r"unencrypted", re.I), "missing-encryption"),
    (re.compile(r"(logging|audit[_\-\s]?log|access[_\-\s]?log|cloudtrail|"
                r"flow[_\-\s]?log)", re.I), "missing-logging"),
    (re.compile(r"privileged[_\-\s]?(container|mode)|runs?[_\-\s]?as[_\-\s]?root|"
                r"\bUSER\s+root|host[_\-\s]?(network|pid|ipc)|allowprivilegeescalation", re.I),
     "container-privilege"),
    (re.compile(r"latest[_\-\s]?tag|image[_\-\s]?tag|unpinned|:latest", re.I), "unpinned-image"),
    (re.compile(r"imds|instance[_\-\s]?metadata|metadata[_\-\s]?service", re.I), "metadata-exposure"),
    (re.compile(r"(not|no|missing|disabl\w*)[_\-\s]?\w*[_\-\s]?(versioning|backup|"
                r"snapshot|retention)", re.I), "missing-backup"),
    (re.compile(r"security[_\-\s]?group|ingress|firewall|network[_\-\s]?acl", re.I),
     "network-exposure"),
    (re.compile(r"auth(oriz|z)|access[_\-\s]?control|permission", re.I), "authz"),
    (re.compile(r"authenticat|missing[_\-\s]?auth|\bauthn\b", re.I), "authn"),
]

_CWE_RE = re.compile(r"CWE[-_\s]?(\d+)", re.I)

# Domains decide HOW a finding is clustered.
DOMAIN_CODE = "code"     # cluster on file + line + category
DOMAIN_DEP = "dependency"  # cluster on package + CVE
DOMAIN_SECRET = "secret"   # cluster on file + line (category is always the same)
DOMAIN_IAC = "iac"         # cluster on file + line + rule intent


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _sev(raw: Any) -> str:
    if raw is None:
        return "info"
    if isinstance(raw, (int, float)):  # CVSS-style numeric score
        s = float(raw)
        return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    return _SEV_MAP.get(str(raw).strip().lower(), "info")


def _cwes(*sources: Any) -> List[str]:
    """Pull every CWE id out of whatever shape a tool used to express them."""
    found: List[str] = []
    for src in sources:
        if src is None:
            continue
        if isinstance(src, (list, tuple, set)):
            for item in src:
                found += _cwes(item)
            continue
        if isinstance(src, dict):
            found += _cwes(src.get("id"), src.get("cwe"), src.get("cwe_id"))
            continue
        found += _CWE_RE.findall(str(src))
    # dedupe, preserve order
    return list(dict.fromkeys(str(int(c)) for c in found if str(c).strip().isdigit()))


def _category(cwe_ids: List[str], *text: Any) -> str:
    for c in cwe_ids:
        if c in _CWE_CATEGORY:
            return _CWE_CATEGORY[c]
    blob = " ".join(str(t) for t in text if t)
    for pattern, cat in _KEYWORD_CATEGORY:
        if pattern.search(blob):
            return cat
    return "other"


def _rel(path: Any, root: str) -> str:
    """Repo-relative, forward-slashed path — the join key across tools."""
    p = str(path or "").strip()
    if not p:
        return ""
    p = p.replace("\\", "/")
    if root:
        root_n = os.path.abspath(root).replace("\\", "/").rstrip("/")
        ap = os.path.abspath(p).replace("\\", "/") if p.startswith("/") else p
        if ap.startswith(root_n + "/"):
            p = ap[len(root_n) + 1:]
    return p.lstrip("./")


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _finding(tool: str, domain: str, **kw: Any) -> Dict[str, Any]:
    f = {"tool": tool, "domain": domain, "file": "", "line": 0, "severity": "info",
         "rule": "", "message": "", "cwe": [], "category": "other",
         "package": "", "version": "", "vuln_id": ""}
    f.update(kw)
    f["message"] = str(f["message"] or "")[:500]
    return f


def _load(path: str) -> Optional[Any]:
    try:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return None
        with open(path, errors="replace") as fh:
            return json.load(fh)
    except Exception as e:
        logger.debug(f"correlate: unreadable report {path}: {e}")
        return None


# ---------------------------------------------------------------------------
# per-tool parsers: report -> [Finding]
# ---------------------------------------------------------------------------
def _p_semgrep(d, root, tool="semgrep"):
    for r in (d.get("results") or []):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = _cwes(meta.get("cwe"), r.get("check_id"))
        rule = r.get("check_id") or ""
        yield _finding(tool, DOMAIN_CODE,
                       file=_rel(r.get("path"), root),
                       line=_int((r.get("start") or {}).get("line")),
                       severity=_sev(extra.get("severity")),
                       rule=rule, message=extra.get("message"),
                       cwe=cwe, category=_category(cwe, rule, extra.get("message")))


def _p_bandit(d, root, tool="bandit"):
    for r in (d.get("results") or []):
        cwe = _cwes(r.get("issue_cwe"))
        rule = r.get("test_id") or ""
        yield _finding(tool, DOMAIN_CODE,
                       file=_rel(r.get("filename"), root),
                       line=_int(r.get("line_number")),
                       severity=_sev(r.get("issue_severity")),
                       rule=rule, message=r.get("issue_text"),
                       cwe=cwe, category=_category(cwe, rule, r.get("issue_text")))


def _p_gosec(d, root, tool="gosec"):
    for r in (d.get("Issues") or []):
        cwe = _cwes(r.get("cwe"))
        rule = r.get("rule_id") or ""
        yield _finding(tool, DOMAIN_CODE,
                       file=_rel(r.get("file"), root),
                       line=_int(str(r.get("line", "0")).split("-")[0]),
                       severity=_sev(r.get("severity")),
                       rule=rule, message=r.get("details"),
                       cwe=cwe, category=_category(cwe, rule, r.get("details")))


def _p_njsscan(d, root, tool="nodejsscan"):
    for section in ("nodejs", "templates", "semgrep_findings"):
        for rule, body in (d.get(section) or {}).items():
            meta = body.get("metadata") or {}
            cwe = _cwes(meta.get("cwe"))
            desc = meta.get("description") or meta.get("owasp") or rule
            for hit in (body.get("files") or []):
                yield _finding(tool, DOMAIN_CODE,
                               file=_rel(hit.get("file_path"), root),
                               line=_int((hit.get("match_lines") or [0])[0]),
                               severity=_sev(meta.get("severity")),
                               rule=rule, message=desc,
                               cwe=cwe, category=_category(cwe, rule, desc))


def _p_brakeman(d, root, tool="brakeman"):
    for r in (d.get("warnings") or []):
        rule = r.get("warning_type") or ""
        cwe = _cwes(r.get("cwe_id"))
        yield _finding(tool, DOMAIN_CODE,
                       file=_rel(r.get("file"), root), line=_int(r.get("line")),
                       severity=_sev(r.get("confidence")),
                       rule=rule, message=r.get("message"),
                       cwe=cwe, category=_category(cwe, rule, r.get("message")))


def _p_bearer(d, root, tool="bearer"):
    # bearer groups findings by severity key at the top level
    for sev, items in (d or {}).items():
        if not isinstance(items, list):
            continue
        for r in items:
            cwe = _cwes(r.get("cwe_ids"))
            rule = r.get("id") or ""
            loc = r.get("source") or {}
            yield _finding(tool, DOMAIN_CODE,
                           file=_rel(r.get("filename"), root),
                           line=_int(loc.get("start") or r.get("line_number")),
                           severity=_sev(sev),
                           rule=rule, message=r.get("title") or r.get("description"),
                           cwe=cwe, category=_category(cwe, rule, r.get("title")))


def _p_eslint(d, root, tool="eslint"):
    for f in (d or []):
        for m in (f.get("messages") or []):
            rule = m.get("ruleId") or ""
            cwe = _cwes(rule)
            yield _finding(tool, DOMAIN_CODE,
                           file=_rel(f.get("filePath"), root), line=_int(m.get("line")),
                           severity=_sev("error" if m.get("severity") == 2 else "warning"),
                           rule=rule, message=m.get("message"),
                           cwe=cwe, category=_category(cwe, rule, m.get("message")))


def _p_gitleaks(d, root, tool="gitleaks"):
    for r in (d or []):
        yield _finding(tool, DOMAIN_SECRET,
                       file=_rel(r.get("File"), root), line=_int(r.get("StartLine")),
                       severity="high", rule=r.get("RuleID") or "secret",
                       message=r.get("Description"), cwe=["798"],
                       category="hardcoded-secret")


def _p_trufflehog(d, root, tool="trufflehog"):
    # trufflehog emits JSON-lines; the runner wraps them into a list for us.
    for r in (d or []):
        meta = ((r.get("SourceMetadata") or {}).get("Data") or {})
        fs = meta.get("Filesystem") or meta.get("Git") or {}
        verified = bool(r.get("Verified"))
        yield _finding(tool, DOMAIN_SECRET,
                       file=_rel(fs.get("file"), root), line=_int(fs.get("line")),
                       # a verified secret is a live credential, not a maybe
                       severity="critical" if verified else "high",
                       rule=r.get("DetectorName") or "secret",
                       message=("VERIFIED live credential" if verified else "unverified secret match"),
                       cwe=["798"], category="hardcoded-secret",
                       verified=verified)


def _p_trivy(d, root, tool="trivy"):
    for res in (d.get("Results") or []):
        target = res.get("Target") or ""
        for v in (res.get("Vulnerabilities") or []):
            cvss = ((v.get("CVSS") or {}).get("nvd") or {}).get("V3Score")
            yield _finding(tool, DOMAIN_DEP,
                           file=_rel(target, root), line=0,
                           severity=_sev(v.get("Severity") or cvss),
                           rule=v.get("VulnerabilityID") or "",
                           message=v.get("Title") or v.get("Description"),
                           cwe=_cwes(v.get("CweIDs")), category="vulnerable-dependency",
                           package=str(v.get("PkgName") or "").lower(),
                           version=str(v.get("InstalledVersion") or ""),
                           vuln_id=str(v.get("VulnerabilityID") or "").upper())
        for m in (res.get("Misconfigurations") or []):
            rule = m.get("ID") or ""
            yield _finding(tool, DOMAIN_IAC,
                           file=_rel(target, root),
                           line=_int(((m.get("CauseMetadata") or {}).get("StartLine"))),
                           severity=_sev(m.get("Severity")), rule=rule,
                           message=m.get("Title"), cwe=[],
                           category=_category([], rule, m.get("Title")))
        for s in (res.get("Secrets") or []):
            yield _finding(tool, DOMAIN_SECRET,
                           file=_rel(target, root), line=_int(s.get("StartLine")),
                           severity=_sev(s.get("Severity")), rule=s.get("RuleID") or "secret",
                           message=s.get("Title"), cwe=["798"], category="hardcoded-secret")


def _p_safety(d, root, tool="safety"):
    rows = d.get("vulnerabilities") if isinstance(d, dict) else d
    for v in (rows or []):
        if not isinstance(v, dict):
            continue
        cve = str(v.get("CVE") or v.get("cve") or v.get("vulnerability_id") or "").upper()
        yield _finding(tool, DOMAIN_DEP, file="requirements", line=0,
                       severity=_sev(v.get("severity") or "high"),
                       rule=cve or "safety", message=v.get("advisory"),
                       cwe=[], category="vulnerable-dependency",
                       package=str(v.get("package_name") or v.get("package") or "").lower(),
                       version=str(v.get("analyzed_version") or v.get("installed_version") or ""),
                       vuln_id=cve)


def _p_pip_audit(d, root, tool="pip-audit"):
    for dep in (d.get("dependencies") if isinstance(d, dict) else d) or []:
        for v in (dep.get("vulns") or []):
            vid = str(v.get("id") or "").upper()
            yield _finding(tool, DOMAIN_DEP, file="requirements", line=0,
                           severity=_sev("high"), rule=vid, message=v.get("description"),
                           cwe=[], category="vulnerable-dependency",
                           package=str(dep.get("name") or "").lower(),
                           version=str(dep.get("version") or ""), vuln_id=vid)


def _p_npm_audit(d, root, tool="npm-audit"):
    for name, v in (d.get("vulnerabilities") or {}).items():
        if not isinstance(v, dict):
            continue
        ids = [str(x.get("url", "")).rsplit("/", 1)[-1]
               for x in (v.get("via") or []) if isinstance(x, dict)]
        cves = [i.upper() for i in ids if i]
        yield _finding(tool, DOMAIN_DEP, file="package.json", line=0,
                       severity=_sev(v.get("severity")), rule=cves[0] if cves else "npm-audit",
                       message=f"{name}: {v.get('severity')} advisory",
                       cwe=[], category="vulnerable-dependency",
                       package=str(name).lower(), version=str(v.get("range") or ""),
                       vuln_id=cves[0] if cves else "")


def _p_osv(d, root, tool="osv-scanner"):
    for res in (d.get("results") or []):
        for pkg in (res.get("packages") or []):
            info = pkg.get("package") or {}
            for g in (pkg.get("groups") or []) or [{}]:
                for vid in (g.get("ids") or [v.get("id") for v in (pkg.get("vulnerabilities") or [])]):
                    if not vid:
                        continue
                    yield _finding(tool, DOMAIN_DEP,
                                   file=_rel((res.get("source") or {}).get("path"), root), line=0,
                                   severity=_sev("high"), rule=str(vid), message=str(vid),
                                   cwe=[], category="vulnerable-dependency",
                                   package=str(info.get("name") or "").lower(),
                                   version=str(info.get("version") or ""),
                                   vuln_id=str(vid).upper())


def _p_depcheck(d, root, tool="dependency-check"):
    for dep in ((d.get("dependencies")) or []):
        for v in (dep.get("vulnerabilities") or []):
            vid = str(v.get("name") or "").upper()
            sev = (v.get("severity") or
                   ((v.get("cvssv3") or {}).get("baseSeverity")))
            yield _finding(tool, DOMAIN_DEP,
                           file=_rel(dep.get("filePath"), root), line=0,
                           severity=_sev(sev), rule=vid, message=v.get("description"),
                           cwe=_cwes(v.get("cwes")), category="vulnerable-dependency",
                           package=str(dep.get("fileName") or "").lower(),
                           version="", vuln_id=vid)


def _p_snyk(d, root, tool="snyk"):
    rows = d.get("vulnerabilities") if isinstance(d, dict) else d
    for v in (rows or []):
        if not isinstance(v, dict):
            continue
        ids = (v.get("identifiers") or {}).get("CVE") or []
        vid = str(ids[0] if ids else v.get("id") or "").upper()
        yield _finding(tool, DOMAIN_DEP, file="", line=0,
                       severity=_sev(v.get("severity")), rule=vid, message=v.get("title"),
                       cwe=_cwes((v.get("identifiers") or {}).get("CWE")),
                       category="vulnerable-dependency",
                       package=str(v.get("packageName") or "").lower(),
                       version=str(v.get("version") or ""), vuln_id=vid)


def _p_checkov(d, root, tool="checkov"):
    blocks = d if isinstance(d, list) else [d]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for c in ((block.get("results") or {}).get("failed_checks") or []):
            rule = c.get("check_id") or ""
            msg = c.get("check_name") or ""
            yield _finding(tool, DOMAIN_IAC,
                           file=_rel(c.get("file_path"), root),
                           line=_int((c.get("file_line_range") or [0])[0]),
                           severity=_sev(c.get("severity") or "medium"),
                           rule=rule, message=msg, cwe=[],
                           category=_category([], rule, msg))


def _p_tfsec(d, root, tool="tfsec"):
    for r in (d.get("results") or []):
        rule = r.get("long_id") or r.get("rule_id") or ""
        msg = r.get("description") or ""
        loc = r.get("location") or {}
        yield _finding(tool, DOMAIN_IAC,
                       file=_rel(loc.get("filename"), root), line=_int(loc.get("start_line")),
                       severity=_sev(r.get("severity")), rule=rule, message=msg,
                       cwe=[], category=_category([], rule, msg))


def _p_graudit(d, root, tool="graudit"):
    # graudit is grep-based text; the runner converts it to {"matches":[...]}
    for m in (d.get("matches") or []):
        msg = m.get("text") or ""
        yield _finding(tool, DOMAIN_CODE,
                       file=_rel(m.get("file"), root), line=_int(m.get("line")),
                       severity="low",  # grep-grade signal: corroboration only
                       rule=m.get("rule") or "graudit-match", message=msg,
                       cwe=[], category=_category([], msg))


_PARSERS = {
    "semgrep": _p_semgrep, "opengrep": _p_semgrep, "bandit": _p_bandit,
    "gosec": _p_gosec, "nodejsscan": _p_njsscan, "brakeman": _p_brakeman,
    "bearer": _p_bearer, "eslint": _p_eslint, "gitleaks": _p_gitleaks,
    "trufflehog": _p_trufflehog, "trivy": _p_trivy, "safety": _p_safety,
    "pip-audit": _p_pip_audit, "npm-audit": _p_npm_audit, "osv-scanner": _p_osv,
    "dependency-check": _p_depcheck, "snyk": _p_snyk, "checkov": _p_checkov,
    "tfsec": _p_tfsec, "graudit": _p_graudit,
}


def normalize(tool: str, report_path: str, repo_root: str) -> List[Dict[str, Any]]:
    """Parse one tool's report into the common schema. Never raises."""
    parser = _PARSERS.get(tool)
    if not parser:
        return []
    data = _load(report_path)
    if data is None:
        return []
    try:
        return [f for f in parser(data, repo_root, tool) if f.get("file") or f.get("package")]
    except Exception as e:
        logger.warning(f"correlate: parser for {tool} failed on {report_path}: {e}")
        return []


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Tool independence
#
# Ranking a finding higher because two tools agreed is only sound when the tools
# are INDEPENDENT. Two engines that share rule lineage, or that pattern-match the
# same syntax for different reasons, will agree constantly and their agreement
# carries no more information than either one alone. Measured over a 136-repo
# sweep, 87% of "corroborated" findings came from such pairs — 1,417 dropped to
# 180 once they were discounted, and the ranking had put 769 Django template
# matches above 55 committed secrets.
#
# Two mechanisms, because the problem occurs at two levels.
# ---------------------------------------------------------------------------

# 1. Tools that share rule provenance, per domain. Same family == one voice.
#    trivy absorbed tfsec upstream, and carries the same IaC policy family as
#    checkov, so on IaC these three are close to a single engine. On dependency
#    findings trivy is independent of npm-audit, hence the per-domain split.
_TOOL_FAMILY: Dict[str, Dict[str, str]] = {
    DOMAIN_IAC: {"trivy": "iac-policy", "tfsec": "iac-policy", "checkov": "iac-policy"},
    # Secret detection is regex and entropy over the same bytes. gitleaks, trivy's
    # secret scanner and an UNVERIFIED trufflehog detector are three implementations
    # of one technique, and trivy's secret rules derive from gitleaks' in the first
    # place. When all three match the same string they have not confirmed each other,
    # they have re-run the same match -- so on this domain they are one voice.
    #
    # This does NOT suppress trufflehog's real advantage. A hit with Verified=true is
    # an out-of-band authentication against the provider: evidence of a different KIND
    # rather than another vote. _cluster() already ranks that confidence="confirmed",
    # above corroborated, and that path does not depend on the family table.
    DOMAIN_SECRET: {"gitleaks": "secret-regex", "trivy": "secret-regex",
                    "trufflehog": "secret-regex"},
}

# 2. Specific rule pairs that fire on the same text for unrelated reasons.
#    nodejsscan's squirrelly_template is a JavaScript template-engine rule;
#    semgrep's is a Flask/Jinja rule. Both match `{{ }}` in Django .html files.
#    Neither validates the other.
_CORRELATED_RULES: Tuple[Tuple[str, str], ...] = (
    ("nodejsscan:squirrelly_template", "semgrep:python.flask.security.xss.audit."
     "template-unescaped-with-safe.template-unescaped-with-safe"),
)


def _independence(group: List[Dict[str, Any]], tools: List[str], rules: List[str]) -> Tuple[int, str]:
    """How many genuinely independent engines back this cluster, and why if reduced."""
    domain = group[0]["domain"] if group else ""
    families = _TOOL_FAMILY.get(domain, {})

    voices = {families.get(t, t) for t in tools}
    note = ""

    if len(voices) < len(tools):
        collapsed = sorted({t for t in tools if t in families})
        why = {
            DOMAIN_IAC: "trivy absorbed tfsec; checkov shares its policy family",
            DOMAIN_SECRET: "all three match secrets by regex/entropy over the same "
                           "bytes, and trivy's rules derive from gitleaks'",
        }.get(domain, "these engines share rule provenance")
        note = (f"{'+'.join(collapsed)} share rule provenance on {domain} "
                f"({why}), so they count as one engine")

    rule_set = set(rules)
    for a, b in _CORRELATED_RULES:
        if a in rule_set and b in rule_set:
            voices = {"correlated-rule-pair"}
            note = (f"{a.split(':')[0]} and {b.split(':')[0]} matched the same syntax via "
                    f"unrelated rules ({a.split(':')[1][:40]} vs a Flask/Jinja rule); "
                    f"not independent confirmation")
            break

    return len(voices), note


def _cluster_key(f: Dict[str, Any]) -> Tuple:
    """The identity a finding is matched on, per domain."""
    if f["domain"] == DOMAIN_DEP:
        # file/line is meaningless for a CVE; the package+advisory is the identity.
        return (DOMAIN_DEP, f.get("package", ""), f.get("vuln_id") or f.get("rule", ""))
    # Code/secret/IaC: same file, same neighbourhood, same kind of defect.
    return (f["domain"], f["file"], f["line"] // max(1, LINE_WINDOW), f["category"])


def _merge(group: List[Dict[str, Any]]) -> Dict[str, Any]:
    tools = sorted({f["tool"] for f in group})
    worst = min(group, key=lambda f: _SEV_RANK.get(f["severity"], 99))
    # Prefer the entry that carries the richest context as the representative.
    lead = max(group, key=lambda f: (len(f.get("cwe") or []), len(f.get("message") or "")))
    verified = any(f.get("verified") for f in group)
    rules = sorted({f"{f['tool']}:{f['rule']}" for f in group if f.get("rule")})
    # Corroboration is counted in INDEPENDENT engines, not raw tool count, so that
    # engines sharing rule lineage (or matching the same syntax by coincidence) do
    # not manufacture agreement. tool_count is kept alongside so the reduction is
    # visible rather than silently applied.
    independent, note = _independence(group, tools, rules)
    return {
        "file": lead["file"], "line": lead["line"], "domain": lead["domain"],
        "category": lead["category"], "severity": worst["severity"],
        "message": lead["message"], "cwe": sorted({c for f in group for c in (f.get("cwe") or [])}, key=int),
        "package": lead.get("package", ""), "version": lead.get("version", ""),
        "vuln_id": lead.get("vuln_id", ""),
        "tools": tools, "tool_count": len(tools),
        "independent_count": independent,
        "correlation_note": note,
        "rules": rules,
        "verified": verified,
        "confidence": "confirmed" if verified else ("corroborated" if independent > 1 else "single_tool"),
    }


def correlate(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Cluster normalized findings and rank them by confidence, then severity."""
    groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        groups[_cluster_key(f)].append(f)
    merged = [_merge(g) for g in groups.values()]
    conf_rank = {"confirmed": 0, "corroborated": 1, "single_tool": 2}
    merged.sort(key=lambda c: (conf_rank[c["confidence"]],
                               _SEV_RANK.get(c["severity"], 99),
                               -c["tool_count"], c["file"], c["line"]))
    return merged


def cross_check(tool_results: List[Dict[str, Any]], repo_root: str) -> Dict[str, Any]:
    """Full pipeline: per-tool reports -> normalized -> correlated -> summary.

    `tool_results` are the entries repo-scan already builds ({tool, report, ...}).
    Tools that errored or wrote no report simply contribute nothing.
    """
    raw: List[Dict[str, Any]] = []
    per_tool: Dict[str, int] = {}
    for r in tool_results:
        tool, report = r.get("tool", ""), r.get("report", "")
        items = normalize(tool, report, repo_root)
        per_tool[tool] = len(items)
        raw += items

    clusters = correlate(raw)
    corroborated = [c for c in clusters if c["confidence"] != "single_tool"]

    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    by_cat: Dict[str, int] = defaultdict(int)
    for c in clusters:
        by_sev[c["severity"]] += 1
        by_cat[c["category"]] += 1

    # Which tools actually agreed with each other, and how often.
    agreement: Dict[str, int] = defaultdict(int)
    for c in corroborated:
        for i, a in enumerate(c["tools"]):
            for b in c["tools"][i + 1:]:
                agreement[f"{a}+{b}"] += 1

    # Clusters where more than one tool fired but the tools were not independent.
    # Reported explicitly: silently dropping them would hide why a count changed,
    # and these are exactly the findings a reader would otherwise over-trust.
    discounted = [c for c in clusters
                  if c.get("tool_count", 1) > 1 and c.get("independent_count", 1) < 2]
    discount_reasons: Dict[str, int] = defaultdict(int)
    for c in discounted:
        if c.get("correlation_note"):
            discount_reasons["+".join(c["tools"])] += 1

    return {
        "normalized_findings": len(raw),
        "unique_findings": len(clusters),
        "duplicates_collapsed": len(raw) - len(clusters),
        "corroborated_count": len(corroborated),
        "agreement_discounted": len(discounted),
        "agreement_discounted_by_pair": dict(sorted(discount_reasons.items(), key=lambda kv: -kv[1])),
        "by_severity": by_sev,
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
        "by_tool": per_tool,
        "tool_agreement": dict(sorted(agreement.items(), key=lambda kv: -kv[1])),
        "findings": clusters,
    }
