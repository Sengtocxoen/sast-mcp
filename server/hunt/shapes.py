"""
shapes.py - Stage B: the three C memory-safety shape scanners.

Read section 2 of docs/hunt-pipeline/ARCHITECTURE.md before trusting anything
here. This stage was measured at **under 2% precision**: 60 hits across two
scanners produced one real bug, and that bug was already known. scan3 produced
53 hits and zero real findings; every one inspected was a false positive. The
document's verdict is explicit - "keep scan2 as a cheap sweep over a NEW
codebase; retire scan3" - and the negative result is the point of shipping it.

So this module does something a straight port of the scripts would not:

* **The verdicts are enforced, not documented.** scan3 refuses to run without
  `allow_retired=True`, and every result carries the measured precision of the
  scanner that produced it, so a hit cannot be over-trusted by accident.
* **Each scanner self-tests against its own known-positive** before a result is
  reported, and a zero-hit scan is only admissible as "clean" if that passed.
  scan2 found the assetsys bug as hit #2, which is the one genuine reason to
  believe anything it says; without that evidence a silent regression in the
  pattern looks exactly like a clean codebase.
* **Guards are detected.** The document's own explanation for the bad precision
  is that the scanner "cannot see the guard three lines up" - m3d.h's
  `_m3dstbi__malloc_mad3` is guarded by `mad3sizes_valid` and exists precisely
  to prevent the overflow being flagged. It cannot see three lines up, but it
  can see one, so hits carry `likely_false_positive` with reasons.

One correctness note about the originals: the committed
`scanners/scan1_narrowing_cast.py` defines regexes for its documented Shape A
(malloc(X) then a copy to an offset destination with length X) but its loop only
ever runs Shape B, making it a duplicate of scan2. That is a plausible part of
why section 7 records "scan1 has never produced a finding". Shape A is
implemented here as documented.
"""
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

SOURCE_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inl")
SKIP_DIRS = {".git", ".svn", "node_modules", "build", "dist", "corpus", "test",
             "tests", "artifacts", "artifacts2", "findings", "findings2",
             "doc", "docs", "third_party", "examples"}
MAX_FILE_BYTES = int(os.environ.get("HUNT_SHAPE_MAX_FILE", 4_000_000))

# Primary patterns, kept separate from the shape functions so a self-test can
# monkeypatch one and prove the guard catches a broken scanner.
_PATTERNS: Dict[str, Any] = {
    # Shape B (assetsys): a parsed size narrowed by a signed cast.
    "scan2": re.compile(
        r"([\w\->\.]+)\s*=\s*\(\s*(?:int|short|signed|int32_t|int16_t)\s*\)\s*"
        r"([^;]{0,80}?(?:size|len|count|Size|Len|Count)[^;]{0,40})\s*;"),
    # Shape A (paldither): an allocation whose size is reused as a copy length.
    "scan1": re.compile(
        r"(\w+)\s*=\s*\(?[\w\s\*]*\)?\s*(?:\w*MALLOC|malloc|calloc|realloc)\s*"
        r"\(\s*([^;]*?)\)\s*;"),
    # Shape C (videocodec/vox_loader/speech): allocation size from a product.
    "scan3": re.compile(
        r"(?:[A-Z_]*MALLOC|malloc|calloc|realloc)\s*\(\s*([^;]{4,160}?)\)\s*[;,)]"),
}

# Secondary patterns each shape needs after its primary match.
_SIGNED_BOUND_RE = r"\s*(?:>|>=)\s*([A-Za-z_][\w\->\.]*)"
_BOUND_WORDS = ("cap", "avail", "max", "size", "len", "remain", "left", "buf",
                "limit", "end")
_OFFSET_COPY_RE = re.compile(
    r"(?:memcpy|memmove)\s*\(\s*([\w\->\.\[\]]+)\s*\+\s*([^,]+),([^;]*);")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_NARROW_DECL = (r"\b(?:int|short|int32_t|int16_t|uint32_t|unsigned int)\s+"
                r"(?:\w+\s*,\s*)*{name}\b")
# Names that mean somebody already thought about the overflow.
_GUARD_RE = re.compile(
    r"\b(\w*sizes?_valid\w*|\w*overflow\w*|\w*check\w*|\w*validate\w*|"
    r"\w*_safe\w*|INT_MAX|SIZE_MAX|UINT32_MAX)\b", re.I)

SHAPES: Dict[str, Dict[str, Any]] = {
    "scan1": {
        "name": "narrowing_cast_offset_copy",
        "derived_from": "paldither",
        "description": "malloc(X) then a copy to an OFFSET destination with length X",
        "retired": False,
        "field_validated": False,
        "measured": "no finding ever produced; no known-positive from a real bug",
        "caution": ("unvalidated: this scanner has never produced a real finding, so a "
                    "negative from it proves nothing. Its self-test is synthetic."),
    },
    "scan2": {
        "name": "cast_signed_bound",
        "derived_from": "assetsys",
        "description": "narrowing cast of a parsed size, later used as a SIGNED bound",
        "retired": False,
        "field_validated": True,
        "measured": "7 hits, 1 real (the known assetsys.h:6204 bug) - ~14%",
        "caution": ("1 of 7 hits was real, and that one was already known. The other six "
                    "were unreachable in practice (strpool needs a 1 GiB string). Worth a "
                    "cheap sweep over a NEW codebase; read the guard yourself."),
    },
    "scan3": {
        "name": "mul_alloc_overflow",
        "derived_from": "videocodec, vox_loader, speech",
        "description": "allocation size from a multiplication with int-width operands",
        "retired": True,
        "field_validated": False,
        "measured": "53 hits, 0 real - every one inspected was a false positive",
        "caution": ("RETIRED: 0 of 53 hits were real. malloc(a*b*c) is idiomatic and almost "
                    "always fine; the scanner cannot see the guard above it, cannot tell "
                    "whether operands are file-derived, and cannot model integer promotion. "
                    "Better use of the budget: read the allocation sites of one target that "
                    "already passed Stage A."),
    },
}

DEFAULT_SHAPES = ("scan2",)

# Synthetic known-positives. scan2's is the real assetsys shape; the others are
# mechanical checks that the pattern still compiles and fires.
_KNOWN_POSITIVES: Dict[str, str] = {
    "scan2": ("static int read_entry(void) {\n"
              "    int size = (int) header_size_field;\n"
              "    if (size > sys->capacity) return 0;\n"
              "    memcpy(buf, src, size);\n"
              "}\n"),
    "scan1": ("void build(void) {\n"
              "    unsigned char* pixels = (unsigned char*) malloc(size);\n"
              "    memcpy(pixels + offset, src, size);\n"
              "}\n"),
    "scan3": ("void load(void) {\n"
              "    int width = read_int();\n"
              "    int height = read_int();\n"
              "    unsigned char* data = malloc(width * height * 4);\n"
              "}\n"),
}

STAGE_NOTE = (
    "Stage B measured under 2% precision in the OSS-Hunt-2026-09-30 campaign (60 hits, "
    "1 already-known bug). Stage A target gating measured ~100%. If you have budget for "
    "only one, gate targets instead of scanning for sites - see "
    "docs/hunt-pipeline/ARCHITECTURE.md section 0."
)


# ------------------------------------------------------------------ the shapes

def _line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


def _window(lines: Sequence[str], start_line: int, size: int) -> str:
    return "\n".join(lines[start_line:start_line + size])


def _shape_scan2(path: str, src: str, lines: Sequence[str]) -> List[Dict[str, Any]]:
    """A signed-narrowed parsed size used as a bound. The assetsys shape."""
    out = []
    pattern = _PATTERNS["scan2"]
    for m in pattern.finditer(src):
        var = m.group(1).strip()
        line = _line_of(src, m.start())
        tail = _window(lines, line, 50)
        cmp_m = re.search(re.escape(var) + _SIGNED_BOUND_RE, tail)
        if not cmp_m:
            continue
        bound = cmp_m.group(1)
        if not any(k in bound.lower() for k in _BOUND_WORDS):
            continue
        out.append({
            "shape": "scan2",
            "file": path,
            "line": line,
            "code": lines[line - 1].strip()[:160] if line <= len(lines) else "",
            "variable": var,
            "bound": cmp_m.group(0).strip()[:80],
            "why": ("a file-derived size narrowed by a signed cast, then compared as a "
                    "signed bound: a negative value passes the check"),
        })
    return out


def _shape_scan1(path: str, src: str, lines: Sequence[str]) -> List[Dict[str, Any]]:
    """malloc(X) then a copy to an offset destination with length X. paldither."""
    out = []
    for m in _PATTERNS["scan1"].finditer(src):
        var, size_expr = m.group(1).strip(), (m.group(2) or "").strip()
        if not size_expr:
            continue
        line = _line_of(src, m.start())
        tail = _window(lines, line, 25)
        for cm in _OFFSET_COPY_RE.finditer(tail):
            dst, offset_expr, rest = cm.group(1), cm.group(2), cm.group(3)
            if var not in dst:
                continue
            # The defect is the copy length being the FULL allocation while the
            # destination is already advanced by an offset.
            if size_expr.split()[0] not in rest and size_expr not in rest:
                continue
            out.append({
                "shape": "scan1",
                "file": path,
                "line": line,
                "code": lines[line - 1].strip()[:160] if line <= len(lines) else "",
                "variable": var,
                "alloc_size": size_expr[:80],
                "copy": cm.group(0).strip()[:120],
                "offset": offset_expr.strip()[:40],
                "why": ("destination is advanced by an offset but the length is the whole "
                        "allocation, so the tail of the copy lands past the end"),
            })
            break
    return out


def _shape_scan3(path: str, src: str, lines: Sequence[str]) -> List[Dict[str, Any]]:
    """Allocation size from a product of int-width operands. Retired: 0/53."""
    out = []
    for m in _PATTERNS["scan3"].finditer(src):
        expr = (m.group(1) or "").strip()
        if expr.count("*") < 2:
            continue
        line = _line_of(src, m.start())
        names = set(_IDENT_RE.findall(expr)) - {
            "sizeof", "char", "int", "unsigned", "long", "size_t", "void", "float", "double"}
        above = "\n".join(lines[max(0, line - 40):line])
        narrow = [n for n in names
                  if re.search(_NARROW_DECL.format(name=re.escape(n)), above)]
        if not narrow:
            continue

        # What the original scanner could not do: look for the guard.
        fp_reasons = []
        guards = _GUARD_RE.findall("\n".join(lines[max(0, line - 4):line]))
        if guards:
            fp_reasons.append(f"an overflow guard appears within 3 lines above: "
                              f"{', '.join(sorted(set(guards))[:3])}")
        enclosing = "\n".join(lines[max(0, line - 12):line])
        if _GUARD_RE.search(enclosing.split("\n")[0] if enclosing else ""):
            fp_reasons.append("the enclosing function is itself named as a safe/checked "
                              "allocator, which usually means it exists to prevent this")
        if "sizeof" in expr and len(narrow) < 2:
            fp_reasons.append("only one narrow operand and a sizeof constant: the product "
                              "is unlikely to wrap")

        out.append({
            "shape": "scan3",
            "file": path,
            "line": line,
            "code": lines[line - 1].strip()[:160] if line <= len(lines) else "",
            "size_expr": expr[:120],
            "narrow_operands": sorted(narrow)[:6],
            "likely_false_positive": bool(fp_reasons),
            "fp_reasons": fp_reasons,
            "why": ("the product can wrap at int width before reaching the allocator - but "
                    "verify the operands are file-derived and unguarded; 0 of 53 campaign "
                    "hits survived that check"),
        })
    return out


_SHAPE_FUNCS = {"scan1": _shape_scan1, "scan2": _shape_scan2, "scan3": _shape_scan3}


# -------------------------------------------------------------------- self-test

def selftest(shape: str) -> Dict[str, Any]:
    """Run a shape against its known-positive. A scanner that fails this cannot
    be believed when it reports nothing."""
    if shape not in _SHAPE_FUNCS:
        return {"shape": shape, "passed": False, "hits": 0, "error": "unknown shape"}
    src = _KNOWN_POSITIVES.get(shape, "")
    hits = _SHAPE_FUNCS[shape]("<selftest>", src, src.splitlines())
    return {
        "shape": shape,
        "passed": bool(hits),
        "hits": len(hits),
        "known_positive": ("the assetsys.h:6204 shape, which this scanner found as hit #2 "
                           "in the campaign" if shape == "scan2"
                           else "synthetic: proves the pattern fires, not that it finds bugs"),
    }


# ------------------------------------------------------------------- the scanner

def _iter_sources(root: str, max_file_bytes: int, skip_dirs: set):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if not fn.endswith(SOURCE_EXTS):
                continue
            yield os.path.join(dirpath, fn)


def scan(root: str, shapes_wanted: Optional[Sequence[str]] = None,
         allow_retired: bool = False, workers: int = 8,
         max_file_bytes: int = MAX_FILE_BYTES,
         skip_dirs: Optional[Sequence[str]] = None,
         max_hits: int = 500) -> Dict[str, Any]:
    """Run the requested shapes over a tree in a single pass per file.

    Each file is read once and every enabled shape is applied to it, which is
    the difference between this and running the three scripts back to back: on a
    large tree the read dominates, so three passes cost three times as much for
    the same answer.
    """
    started = time.time()
    wanted = [s.lower() for s in (shapes_wanted or DEFAULT_SHAPES)]
    skip = set(skip_dirs) if skip_dirs is not None else set(SKIP_DIRS)

    refused: Dict[str, str] = {}
    active: List[str] = []
    for s in wanted:
        if s not in _SHAPE_FUNCS:
            refused[s] = f"unknown shape {s!r}; known: {', '.join(sorted(_SHAPE_FUNCS))}"
            continue
        if SHAPES[s]["retired"] and not allow_retired:
            refused[s] = SHAPES[s]["caution"]
            continue
        active.append(s)

    selftests = {s: selftest(s) for s in active}
    selftest_passed = all(t["passed"] for t in selftests.values()) if selftests else False

    if not os.path.isdir(root):
        return {
            "root": root,
            "error": f"{root!r} is not a directory",
            "hits": [], "hit_count": 0, "refused": refused,
            "shapes_run": {}, "selftests": selftests,
            "selftest_passed": selftest_passed,
            "clean_claim_admissible": False,
            "stage_note": STAGE_NOTE,
        }

    files: List[str] = []
    skipped_size = 0
    unreadable = 0
    for path in _iter_sources(root, max_file_bytes, skip):
        try:
            if os.path.getsize(path) > max_file_bytes:
                skipped_size += 1
                continue
        except OSError:
            unreadable += 1
            continue
        files.append(path)

    hits: List[Dict[str, Any]] = []

    def scan_one(path: str) -> List[Dict[str, Any]]:
        try:
            with open(path, "r", errors="ignore") as f:
                src = f.read()
        except OSError:
            return []
        lines = src.splitlines()
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        found: List[Dict[str, Any]] = []
        for s in active:
            try:
                found.extend(_SHAPE_FUNCS[s](rel, src, lines))
            except Exception as e:  # one bad file must not kill the sweep
                logger.debug("shape %s failed on %s: %s", s, rel, e)
        return found

    if active and files:
        if workers <= 1 or len(files) < 4:
            for p in files:
                hits.extend(scan_one(p))
        else:
            with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
                for found in pool.map(scan_one, files):
                    hits.extend(found)

    # Collapse the duplicates the original scripts also collapsed: the same code
    # at the same place, usually a header included into several objects.
    collapsed: Dict[Any, Dict[str, Any]] = {}
    for h in hits:
        key = (h["shape"], h["file"], h.get("code", ""))
        if key in collapsed:
            collapsed[key]["occurrences"] += 1
            continue
        h["occurrences"] = 1
        collapsed[key] = h

    ordered = sorted(collapsed.values(), key=lambda x: (x["shape"], x["file"], x["line"]))
    truncated = len(ordered) > max_hits
    ordered = ordered[:max_hits]

    likely_fp = sum(1 for h in ordered if h.get("likely_false_positive"))
    return {
        "root": root,
        "shapes_run": {s: {k: SHAPES[s][k] for k in
                           ("name", "derived_from", "description", "measured",
                            "caution", "field_validated", "retired")} for s in active},
        "refused": refused,
        "selftests": selftests,
        "selftest_passed": selftest_passed,
        "files_scanned": len(files),
        "files_skipped_size": skipped_size,
        "files_unreadable": unreadable,
        "hit_count": len(ordered),
        "hits_truncated": truncated,
        "likely_false_positives": likely_fp,
        "hits": ordered,
        # A zero-hit sweep means something only if the scanner provably works.
        "clean_claim_admissible": bool(selftest_passed and not refused.get("__all__")),
        "elapsed_seconds": round(time.time() - started, 2),
        "stage_note": STAGE_NOTE,
        "triage_reminder": ("for each hit, check three things the scanner cannot see: is the "
                            "operand actually file-derived, is there a guard above it, and "
                            "what does integer promotion do here"),
    }
