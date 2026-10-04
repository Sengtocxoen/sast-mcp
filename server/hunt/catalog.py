"""
catalog.py - turn a library catalog into candidate repos, by category.

Stage A starts from nothings/single_file_libs because it is a curated list of
small, self-contained C/C++ libraries - which is exactly the population where an
unmined format parser can still be found. The README is a set of markdown
tables under category headings, so parsing it gives both the repo and the tag,
and the tag is what narrows 297 repos to the 62 that parse a file format.

Two parsing details that matter, both visible in the committed catalogs under
docs/hunt-pipeline/catalog/:

* Entries are deduplicated by repo, not by row. A repo can appear under several
  categories (stb is listed under 3d, image and audio), and gating it three
  times would spend three times the API budget to reach the same verdict.
* Repo slugs arrive dirty - '#anchor' fragments for libraries that live inside a
  larger repo (ands/lightmapper#lightmapper), '.git' suffixes, blob/tree paths.
  normalize_repo collapses all of those to 'owner/name', because that is the
  only form the GitHub API accepts.

load_tsv() reads the catalogs already committed to this repo, so the exact
297/62 population from the OSS-Hunt-2026-09-30 campaign can be re-gated with no
network at all.
"""
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import ghclient

logger = logging.getLogger(__name__)

SINGLE_FILE_LIBS_README = (
    "https://raw.githubusercontent.com/nothings/single_file_libs/master/README.md"
)

# The categories that contain format parsers - i.e. code that eats a byte buffer
# somebody else produced. This is the filter that took 297 repos to 62.
PARSER_TAGS = frozenset({
    "image", "audio", "3d", "mesh", "pack", "parse", "file", "serial", "video",
})

# Categories section 7 of ARCHITECTURE.md flags as never gated but known to
# contain parsers. Exposed so the known gap is addressable by passing a tag set,
# rather than being rediscovered later.
UNGATED_PARSER_TAGS = frozenset({"2d", "json", "net"})

# Heading text -> catalog tag. The README's headings are prose ("Images and
# image processing"); the tags are the short slugs the campaign used.
_HEADING_TAGS = (
    ("argv", "argv"), ("audio", "audio"), ("build", "build"), ("camera", "camera"),
    ("compress", "pack"), ("crypt", "crypt"), ("data struct", "data"),
    ("encrypt", "crypt"), ("font", "font"), ("geometry", "geom"),
    ("graphics", "2d"), ("gui", "gui"), ("hash", "hash"), ("image", "image"),
    ("json", "json"), ("math", "math"), ("mesh", "mesh"), ("multithread", "thread"),
    ("network", "net"), ("parsing", "parse"), ("physics", "physics"),
    ("profiling", "profile"), ("random", "random"), ("scripting", "script"),
    ("serializ", "serial"), ("sort", "sort"), ("string", "string"),
    ("test", "test"), ("thread", "thread"), ("unicode", "unicode"),
    ("video", "video"), ("3d", "3d"), ("2d", "2d"),
    ("file", "file"), ("archive", "pack"), ("compression", "pack"),
)

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$", re.MULTILINE)
_LINK_RE = re.compile(r"\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")
_GITHUB_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9._-]+)",
    re.I,
)
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}")


def normalize_repo(value: str) -> Optional[str]:
    """'https://github.com/O/R/tree/x#frag' -> 'O/R'. None if not a GitHub repo."""
    if not value:
        return None
    text = value.strip()
    m = _GITHUB_RE.match(text)
    if m:
        owner, name = m.group(1), m.group(2)
    else:
        # Already a slug: owner/name, possibly with an anchor or .git.
        bare = text.split("#", 1)[0].strip().strip("/")
        parts = [p for p in bare.split("/") if p]
        if len(parts) < 2 or bare.startswith("http"):
            return None
        owner, name = parts[0], parts[1]
    name = name.split("#", 1)[0]
    if name.lower().endswith(".git"):
        name = name[:-4]
    owner, name = owner.strip("."), name.strip(".")
    if not owner or not name:
        return None
    return f"{owner}/{name}"


def _tag_for_heading(heading: str) -> str:
    low = heading.strip().lower()
    for needle, tag in _HEADING_TAGS:
        if needle in low:
            return tag
    return "misc"


def parse_readme(markdown: str, include_non_github: bool = False) -> List[Dict[str, Any]]:
    """Parse a single_file_libs-style README into deduplicated repo entries.

    Deliberately tolerant: the README's table shape has changed over time, so
    rather than locking onto a column layout this takes the first GitHub link in
    each row and the nearest preceding heading as the tag. A row that carries no
    GitHub link is skipped (those are self-hosted or gist-hosted libraries).
    """
    if not markdown:
        return []

    # Heading offsets, so each row can be attributed to the section it sits in.
    headings = [(m.start(), _tag_for_heading(m.group(2))) for m in _HEADING_RE.finditer(markdown)]

    def tag_at(pos: int) -> str:
        tag = "misc"
        for start, t in headings:
            if start > pos:
                break
            tag = t
        return tag

    entries: Dict[str, Dict[str, Any]] = {}
    for line in _iter_lines_with_offsets(markdown):
        text, offset = line
        stripped = text.strip()
        if not stripped or stripped.startswith("#") or _TABLE_SEP_RE.match(stripped):
            continue
        links = _LINK_RE.findall(text)
        if not links:
            continue
        repo = None
        label = ""
        for lbl, url in links:
            repo = normalize_repo(url)
            if repo:
                label = lbl.strip()
                break
        if not repo:
            if not include_non_github:
                continue
            label, url = links[0]
            repo = None
        if repo is None:
            continue
        # A repo listed in several categories keeps its first (most specific)
        # tag; gating it once is the whole point of deduplicating here.
        if repo in entries:
            entries[repo].setdefault("also_tagged", [])
            t = tag_at(offset)
            if t != entries[repo]["tag"] and t not in entries[repo]["also_tagged"]:
                entries[repo]["also_tagged"].append(t)
            continue
        entries[repo] = {
            "repo": repo,
            "name": label or repo.split("/")[-1],
            "tag": tag_at(offset),
            "description": _row_description(text),
            "also_tagged": [],
        }
    return list(entries.values())


def _iter_lines_with_offsets(text: str):
    pos = 0
    for line in text.splitlines(True):
        yield line, pos
        pos += len(line)


def _row_description(row: str) -> str:
    """Best-effort description: the longest pipe-delimited cell with no link."""
    cells = [c.strip() for c in row.split("|")]
    plain = [c for c in cells if c and "](" not in c and not c.startswith("-")]
    return (max(plain, key=len)[:160] if plain else "")


def filter_tags(entries: Iterable[Dict[str, Any]],
                tags: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Keep entries whose tag (or any secondary tag) is in `tags`."""
    wanted = {t.strip().lower() for t in (tags if tags is not None else PARSER_TAGS) if t}
    out = []
    for e in entries:
        own = {str(e.get("tag", "")).lower(), *[str(t).lower() for t in e.get("also_tagged", [])]}
        if own & wanted:
            out.append(e)
    return out


def load_catalog(client: Optional[ghclient.GitHubClient] = None,
                 url: str = SINGLE_FILE_LIBS_README,
                 refresh: bool = False) -> Dict[str, Any]:
    """Fetch and parse the catalog. The README is a raw fetch, so it is free."""
    client = client or ghclient.GitHubClient()
    resp = client.raw(url, ttl=ghclient.TTL_POLICY, refresh=refresh)
    if not resp.ok:
        return {
            "source": url,
            "error": f"catalog fetch returned HTTP {resp.status}",
            "entries": [],
            "count": 0,
        }
    entries = parse_readme(resp.body)
    return {
        "source": url,
        "from_cache": resp.from_cache,
        "count": len(entries),
        "entries": entries,
    }


def load_tsv(path: str) -> List[Dict[str, Any]]:
    """Read a committed catalog TSV (docs/hunt-pipeline/catalog/*.tsv).

    These files start with a human-readable count line and use CRLF endings, so
    both are tolerated. Columns are: tag, owner/repo, [description].
    """
    entries: Dict[str, Dict[str, Any]] = {}
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            cols = line.split("\t")
            if len(cols) < 2:
                continue  # the leading count/header line
            repo = normalize_repo(cols[1])
            if not repo or repo in entries:
                continue
            entries[repo] = {
                "repo": repo,
                "name": repo.split("/")[-1],
                "tag": cols[0].strip().lower(),
                "description": (cols[2].split("|")[-1].strip()[:160] if len(cols) > 2 else ""),
                "also_tagged": [],
            }
    return list(entries.values())


def repos_of(entries: Sequence[Dict[str, Any]]) -> List[str]:
    return [e["repo"] for e in entries if e.get("repo")]
